import Darwin
import Foundation

/// What the app implements. Calls arrive on background threads.
public protocol BridgeDelegate: AnyObject {
    var appVersion: String { get }
    var isLocked: Bool { get }
    /// Show the panel for `request` and call `reply` exactly once. For signup,
    /// save to the card before replying with `.fill`.
    func bridge(fill request: FillRequest, reply: @escaping (FillReply) -> Void)
    /// The extension gave up on a request (timeout or tab closed).
    func bridge(cancel reqId: String)
    /// Toolbar dot and field dropdown: the logins for `host` (names and
    /// usernames only). Answer no logins while locked.
    func bridge(hasMatch host: String, reply: @escaping (_ logins: [LoginSummary], _ locked: Bool) -> Void)
}

/// Unix socket server for `ykvault-bridge` (SPEC §12.1): directory 0700,
/// socket 0600, and every peer must run as our uid.
public final class BridgeServer {
    public static var defaultPath: String {
        NSHomeDirectory() + "/Library/Application Support/99Passwords/bridge.sock"
    }

    public let path: String
    /// If not empty, only these extension ids may talk to the app.
    public var allowedExtensionIDs: Set<String> = []
    public weak var delegate: BridgeDelegate?

    private var listenFD: Int32 = -1

    public init(path: String = BridgeServer.defaultPath) {
        self.path = path
    }

    public func start() throws {
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        chmod(dir, 0o700)
        unlink(path)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw BridgeError.pathTooLong }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BridgeError.socket(errno) }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
        guard ok, chmod(path, 0o600) == 0, listen(fd, 8) == 0 else {
            let e = errno
            close(fd)
            throw BridgeError.socket(e)
        }
        listenFD = fd
        Thread.detachNewThread { [weak self] in self?.acceptLoop(fd) }
    }

    public func stop() {
        if listenFD >= 0 {
            shutdown(listenFD, SHUT_RDWR)
            close(listenFD)
            listenFD = -1
            unlink(path)
        }
    }

    deinit { stop() }

    private func acceptLoop(_ fd: Int32) {
        while true {
            let c = accept(fd, nil, nil)
            if c < 0 {
                if errno == EINTR { continue }
                return
            }
            var uid = uid_t(0), gid = gid_t(0)
            guard getpeereid(c, &uid, &gid) == 0, uid == getuid() else {
                close(c)
                continue
            }
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            let conn = BridgeConnection(fd: c)
            Thread.detachNewThread { [weak self] in self?.serve(conn) }
        }
    }

    private func serve(_ conn: BridgeConnection) {
        defer { conn.close() }
        while let msg = conn.receive() {
            guard (msg["v"] as? Int) == 1, let type = msg["type"] as? String else { return }
            switch type {
            case "bridge_hello":
                conn.callerOrigin = msg["caller_origin"] as? String
                if !allowedExtensionIDs.isEmpty {
                    let id = conn.callerOrigin?
                        .replacingOccurrences(of: "chrome-extension://", with: "")
                        .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                    guard let id, allowedExtensionIDs.contains(id) else { return }
                }
            case "hello":
                conn.send(["v": 1, "type": "hello",
                           "app_version": delegate?.appVersion ?? "0",
                           "locked": delegate?.isLocked ?? true])
            case "fill_request":
                guard let req = FillRequest(msg) else {
                    conn.send(["v": 1, "type": "error", "code": "bad_request",
                               "req_id": msg["req_id"] as? String ?? ""])
                    continue
                }
                guard let delegate else {
                    conn.send(FillReply.error(code: "unavailable").message(for: req))
                    continue
                }
                delegate.bridge(fill: req) { [weak conn] reply in conn?.send(reply.message(for: req)) }
            case "has_match":
                let reqId = msg["req_id"] as? String ?? ""
                let host = FillRequest.normalise(msg["host"] as? String ?? "")
                guard let delegate, !host.isEmpty, host.count <= 253 else {
                    conn.send(["v": 1, "type": "has_match", "req_id": reqId, "match": false, "locked": true])
                    continue
                }
                delegate.bridge(hasMatch: host) { [weak conn] logins, locked in
                    let list = locked ? [] : Array(logins.prefix(20))
                    conn?.send(["v": 1, "type": "has_match", "req_id": reqId, "match": !list.isEmpty,
                                "locked": locked, "logins": list.map(\.message)])
                }
            case "cancel":
                if let id = msg["req_id"] as? String { delegate?.bridge(cancel: id) }
            default:
                conn.send(["v": 1, "type": "error", "code": "unknown_type"])
            }
        }
    }
}

/// One bridge connection (one Chrome native messaging port).
public final class BridgeConnection {
    private var fd: Int32
    private let lock = NSLock()
    public internal(set) var callerOrigin: String?

    init(fd: Int32) { self.fd = fd }

    func receive() -> [String: Any]? {
        guard let header = read(4), let n = try? Framing.decodeLength(header),
              var body = read(n) else { return nil }
        defer { body.resetBytes(in: 0..<body.count) }
        return try? Framing.decodeBody(body)
    }

    public func send(_ message: [String: Any]) {
        guard var data = try? Framing.encode(message) else { return }
        defer { data.resetBytes(in: 0..<data.count) }
        lock.lock()
        defer { lock.unlock() }
        guard fd >= 0 else { return }
        data.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                let w = write(fd, raw.baseAddress! + off, raw.count - off)
                if w <= 0 { return }
                off += w
            }
        }
    }

    private func read(_ n: Int) -> Data? {
        var buf = Data(count: n)
        var off = 0
        while off < n {
            let r = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress! + off, n - off) }
            if r <= 0 { return nil }
            off += r
        }
        return buf
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }
}
