import Foundation

/// A validated `fill_request` from the extension (SPEC §12.2).
public struct FillRequest: Equatable {
    public enum Mode: String { case login, signup, totp, identity }

    public let reqId: String
    public let mode: Mode
    /// Normalised host to show in "Fill into <host>?" and to match entries on.
    public let host: String
    public let origin: String
    public let username: String?
    /// 32×32 PNG (≤ 8 KiB) if the extension sent one and it checks out.
    public let faviconPNG: Data?
    /// The login the user picked in the field dropdown, if any. The app fills
    /// it without the panel only if it matches `host`.
    public let entryId: String?
    /// "Save new login" from the field menu: what the user typed in the
    /// page's password field, to save instead of a generated one (signup only).
    public let password: String?

    /// Parses and checks a message. The host must agree with the origin.
    public init?(_ m: [String: Any]) {
        guard (m["v"] as? Int) == 1, (m["type"] as? String) == "fill_request",
              let reqId = m["req_id"] as? String, !reqId.isEmpty, reqId.count <= 64,
              let mode = (m["mode"] as? String).flatMap(Mode.init(rawValue:)),
              let rawHost = m["host"] as? String, let origin = m["origin"] as? String,
              let url = URL(string: origin), ["https", "http"].contains(url.scheme ?? ""),
              let originHost = url.host
        else { return nil }
        let host = FillRequest.normalise(rawHost)
        guard !host.isEmpty, host == FillRequest.normalise(originHost) else { return nil }
        self.reqId = reqId
        self.mode = mode
        self.host = host
        self.origin = origin
        self.username = (m["username"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        self.password = mode == .signup ? (m["password"] as? String).flatMap { !$0.isEmpty && $0.count <= 1024 ? $0 : nil } : nil
        self.entryId = (m["entry_id"] as? String).flatMap {
            !$0.isEmpty && $0.count <= 20 && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) ? $0 : nil
        }
        self.faviconPNG = (m["favicon_png"] as? String)
            .flatMap { Data(base64Encoded: $0) }
            .flatMap { FillRequest.isFavicon($0) ? $0 : nil }
    }

    /// Default name for a new login: the site's main domain without the TLD,
    /// capitalised. "github.com" -> "Github", "app.example.co.uk" -> "Example".
    public var siteName: String { FillRequest.siteName(host) }

    public static func siteName(_ host: String) -> String {
        var labels = host.split(separator: ".").map(String.init)
        if labels.last?.allSatisfy(\.isNumber) ?? true { return host } // IP address or empty
        guard labels.count >= 2 else { return host.prefix(1).uppercased() + host.dropFirst() }
        labels.removeLast() // TLD
        // Second-level registries such as co.uk, com.au, gouv.fr.
        if labels.count >= 2, ["co", "com", "org", "net", "gov", "gouv", "ac", "edu", "ne", "or"].contains(labels.last!) {
            labels.removeLast()
        }
        let main = labels.last!
        return main.prefix(1).uppercased() + main.dropFirst()
    }

    static func normalise(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    /// PNG signature and a 32×32 IHDR (SPEC §10).
    public static func isFavicon(_ d: Data) -> Bool {
        let b = [UInt8](d)
        guard b.count >= 24, b.count <= 8 * 1024,
              b[0..<8].elementsEqual([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        else { return false }
        let be = { (i: Int) in b[i..<i + 4].reduce(0) { $0 << 8 | Int($1) } }
        return be(16) == 32 && be(20) == 32
    }
}

/// A matching login for the field dropdown: no secrets.
public struct LoginSummary: Equatable {
    public let id: String
    public let name: String
    public let username: String?
    public init(id: String, name: String, username: String?) {
        self.id = id
        self.name = name
        self.username = username
    }

    var message: [String: Any] {
        var m: [String: Any] = ["id": id, "name": name]
        if let username { m["username"] = username }
        return m
    }
}

/// What the app answers to a fill request.
public enum FillReply {
    case fill(username: String?, password: String?, totp: String?)
    /// Name, email, phone and address for a form, keyed like SPEC §12.2
    /// (`first_name`, `last_name`, `email`, `phone`, `street`, `city`,
    /// `postcode`, `region`, `country`).
    case identity([String: String])
    case cancel
    case error(code: String)

    func message(for req: FillRequest) -> [String: Any] {
        var m: [String: Any] = ["v": 1, "req_id": req.reqId]
        switch self {
        case let .fill(username, password, totp):
            m["type"] = "fill"
            m["host"] = req.host
            if let username { m["username"] = username }
            if let password { m["password"] = password }
            if let totp { m["totp"] = totp }
        case let .identity(fields):
            m["type"] = "fill"
            m["host"] = req.host
            m["identity"] = fields
        case .cancel:
            m["type"] = "cancel"
        case let .error(code):
            m["type"] = "error"
            m["code"] = code
        }
        return m
    }
}
