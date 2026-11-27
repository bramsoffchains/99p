import Darwin
import Foundation
import Testing
@testable import BridgeServer

final class FakeApp: BridgeDelegate {
    let appVersion = "test"
    let isLocked = false
    var cancelled: [String] = []
    func bridge(fill request: FillRequest, reply: @escaping (FillReply) -> Void) {
        reply(.fill(username: "alice", password: "hunter2", totp: nil))
    }
    func bridge(cancel reqId: String) { cancelled.append(reqId) }
    func bridge(hasMatch host: String, reply: @escaping ([LoginSummary], Bool) -> Void) {
        reply(host == "github.com" ? [LoginSummary(id: "7", name: "GitHub", username: "alice"),
                                      LoginSummary(id: "9", name: "GitHub work", username: nil)] : [], false)
    }
}

/// Minimal client playing the role of 99p-bridge.
final class Client {
    let fd: Int32
    init(path: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes); $0[bytes.count] = 0 }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 { throw BridgeError.socket(errno) }
    }
    func send(_ m: [String: Any]) throws {
        let d = try Framing.encode(m)
        _ = d.withUnsafeBytes { write(fd, $0.baseAddress!, d.count) }
    }
    func receive() throws -> [String: Any] {
        func readN(_ n: Int) -> Data {
            var buf = Data(count: n)
            var off = 0
            while off < n {
                let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + off, n - off) }
                if r <= 0 { break }
                off += r
            }
            return buf
        }
        let n = try Framing.decodeLength(readN(4))
        return try Framing.decodeBody(readN(n))
    }
    deinit { close(fd) }
}

@Suite(.serialized) struct BridgeServerTests {
    @Test func testFramingRoundTrip() throws {
        let d = try Framing.encode(["v": 1, "type": "hello"])
        XCTAssertEqual(try Framing.decodeLength(d.prefix(4)), d.count - 4)
        XCTAssertEqual(try Framing.decodeBody(d.dropFirst(4))["type"] as? String, "hello")
        XCTAssertThrowsError(try Framing.decodeLength(Data([0, 0, 0, 0])))
        XCTAssertThrowsError(try Framing.decodeLength(Data([0x01, 0x00, 0x01, 0x00]))) // 65,537
        XCTAssertThrowsError(try Framing.encode(["x": String(repeating: "a", count: Framing.maxMessage)]))
    }

    @Test func testFillRequestValidation() {
        let base: [String: Any] = ["v": 1, "type": "fill_request", "req_id": "r1", "mode": "login",
                                   "host": "GitHub.com.", "origin": "https://github.com"]
        let r = FillRequest(base)
        XCTAssertEqual(r?.host, "github.com")
        XCTAssertEqual(r?.mode, .login)
        XCTAssertNil(r?.username)
        XCTAssertNil(r?.entryId)
        XCTAssertEqual(r?.siteName, "Github")
        XCTAssertEqual(FillRequest.siteName("app.example.co.uk"), "Example")
        XCTAssertEqual(FillRequest.siteName("www.bbc.co.uk"), "Bbc")
        XCTAssertEqual(FillRequest.siteName("accounts.google.com"), "Google")
        XCTAssertEqual(FillRequest.siteName("localhost"), "Localhost")
        XCTAssertEqual(FillRequest.siteName("127.0.0.1"), "127.0.0.1")
        XCTAssertNil(r?.password)
        var save = base; save["mode"] = "signup"; save["password"] = "typed-pw"
        XCTAssertEqual(FillRequest(save)?.password, "typed-pw")
        save["mode"] = "login"
        XCTAssertNil(FillRequest(save)?.password)
        var picked = base; picked["entry_id"] = "42"
        XCTAssertEqual(FillRequest(picked)?.entryId, "42")
        picked["entry_id"] = "42; drop"
        XCTAssertNil(FillRequest(picked)?.entryId)

        var spoof = base; spoof["host"] = "github.com.evil.net"
        XCTAssertNil(FillRequest(spoof))
        var idMode = base; idMode["mode"] = "identity"
        XCTAssertEqual(FillRequest(idMode)?.mode, .identity)
        let idReply = FillReply.identity(["email": "a@b.c"]).message(for: FillRequest(idMode)!)
        XCTAssertEqual(idReply["type"] as? String, "fill")
        XCTAssertEqual((idReply["identity"] as? [String: String])?["email"], "a@b.c")
        var badMode = base; badMode["mode"] = "steal"
        XCTAssertNil(FillRequest(badMode))
        var badScheme = base; badScheme["origin"] = "file:///etc"
        XCTAssertNil(FillRequest(badScheme))
        var v2 = base; v2["v"] = 2
        XCTAssertNil(FillRequest(v2))

        var png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52,
                        0, 0, 0, 32, 0, 0, 0, 32])
        var withIcon = base; withIcon["favicon_png"] = png.base64EncodedString()
        XCTAssertEqual(FillRequest(withIcon)?.faviconPNG, png)
        png[19] = 64
        withIcon["favicon_png"] = png.base64EncodedString()
        XCTAssertNotNil(FillRequest(withIcon))
        XCTAssertNil(FillRequest(withIcon)?.faviconPNG)
    }

    @Test func testManifest() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let url = try NativeHostManifest.install(bridgePath: "/Applications/99passwords.app/Contents/MacOS/99p-bridge",
                                                 extensionIDs: ["abcdefghijklmnopabcdefghijklmnop"], directory: dir)
        XCTAssertEqual(url.lastPathComponent, "app.99passwords.bridge.json")
        let m = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        XCTAssertEqual(m["name"] as? String, "app.99passwords.bridge")
        XCTAssertEqual(m["type"] as? String, "stdio")
        XCTAssertEqual(m["allowed_origins"] as? [String], ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"])
        try? FileManager.default.removeItem(at: dir)
    }

    @Test func testEndToEnd() throws {
        // sun_path is 104 bytes, so keep the path short.
        let path = "/tmp/p99b-\(getpid())/bridge.sock"
        let server = BridgeServer(path: path)
        let app = FakeApp()
        server.delegate = app
        server.allowedExtensionIDs = ["abcdefghijklmnopabcdefghijklmnop"]
        try server.start()
        defer { server.stop() }

        var st = stat()
        XCTAssertEqual(stat(path, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)
        XCTAssertEqual(stat((path as NSString).deletingLastPathComponent, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o700)

        let c = try Client(path: path)
        try c.send(["v": 1, "type": "bridge_hello", "caller_origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"])
        try c.send(["v": 1, "type": "hello", "ext_version": "1.0.0"])
        let hello = try c.receive()
        XCTAssertEqual(hello["type"] as? String, "hello")
        XCTAssertEqual(hello["locked"] as? Bool, false)

        try c.send(["v": 1, "type": "fill_request", "req_id": "r1", "mode": "login",
                    "host": "github.com", "origin": "https://github.com"])
        let fill = try c.receive()
        XCTAssertEqual(fill["type"] as? String, "fill")
        XCTAssertEqual(fill["req_id"] as? String, "r1")
        XCTAssertEqual(fill["host"] as? String, "github.com")
        XCTAssertEqual(fill["password"] as? String, "hunter2")

        try c.send(["v": 1, "type": "has_match", "req_id": "m1", "host": "GitHub.com."])
        let m1 = try c.receive()
        XCTAssertEqual(m1["type"] as? String, "has_match")
        XCTAssertEqual(m1["req_id"] as? String, "m1")
        XCTAssertEqual(m1["match"] as? Bool, true)
        let logins = m1["logins"] as? [[String: Any]] ?? []
        XCTAssertEqual(logins.map { $0["name"] as? String }, ["GitHub", "GitHub work"])
        XCTAssertEqual(logins.first?["username"] as? String, "alice")
        XCTAssertNil(logins.last?["username"])
        XCTAssertEqual(logins.first?["id"] as? String, "7")
        try c.send(["v": 1, "type": "has_match", "req_id": "m2", "host": "example.com"])
        XCTAssertEqual(try c.receive()["match"] as? Bool, false)

        try c.send(["v": 1, "type": "fill_request", "req_id": "r2", "mode": "login",
                    "host": "github.com", "origin": "https://evil.net"])
        XCTAssertEqual(try c.receive()["code"] as? String, "bad_request")
    }

    @Test func testUnknownExtensionIsDropped() throws {
        let path = "/tmp/p99b-\(getpid())-x/bridge.sock"
        let server = BridgeServer(path: path)
        server.delegate = FakeApp()
        server.allowedExtensionIDs = ["abcdefghijklmnopabcdefghijklmnop"]
        try server.start()
        defer { server.stop() }
        let c = try Client(path: path)
        try c.send(["v": 1, "type": "bridge_hello", "caller_origin": "chrome-extension://pppppppppppppppppppppppppppppppp/"])
        try c.send(["v": 1, "type": "hello"])
        XCTAssertThrowsError(try c.receive()) // server closed the connection
    }
}
