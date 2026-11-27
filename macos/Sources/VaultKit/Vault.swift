// Swift wrapper over the C ABI in crates/ffi/include/p99.h (SPEC §11).
// Every call goes through one serial queue: a session is not thread-safe, and
// unlock/save block (touch, APDUs), so they never run on the main thread.

import CP99
import Foundation

public struct VaultError: Error, Equatable, LocalizedError {
    public let code: UInt32
    /// The core's own description of what went wrong.
    public let detail: String

    init(_ s: P99Status) {
        code = s.rawValue
        var buf = P99Buf(ptr: nil, len: 0)
        p99_last_error(&buf)
        detail = buf.ptr.map { String(decoding: UnsafeBufferPointer(start: $0, count: buf.len), as: UTF8.self) } ?? ""
        p99_buf_free(buf)
    }

    public var isCardRemoved: Bool { code == P99_ERR_CARD_REMOVED.rawValue }
    public var isLocked: Bool { code == P99_ERR_LOCKED.rawValue }
    public var isWrongPin: Bool { code == P99_ERR_WRONG_PIN.rawValue }

    public var errorDescription: String? {
        switch P99Status(rawValue: code) {
        case P99_ERR_CARD_REMOVED: return "The YubiKey was removed."
        case P99_ERR_CAPACITY: return "The vault is full: this would not fit on the YubiKey."
        case P99_ERR_MGMT_KEY: return "This YubiKey has a custom PIV management key."
        case P99_ERR_DECRYPT: return "Wrong master password, or a different YubiKey."
        case P99_ERR_NO_VAULT: return "No vault on this YubiKey."
        case P99_ERR_LOCKED: return "The vault is locked."
        case P99_ERR_TOUCH_TIMEOUT: return "No touch. Tap the YubiKey when it blinks."
        case P99_ERR_WRONG_PIN: return "Wrong master password."
        case P99_ERR_PIN_BLOCKED: return "255 wrong master passwords: this YubiKey is blocked and its vault is gone."
        case P99_ERR_INVALID:
            let d = detail.replacingOccurrences(of: "invalid argument: ", with: "")
            return d.isEmpty ? "That input was not accepted." : d.prefix(1).uppercased() + d.dropFirst() + "."
        default: return detail.isEmpty ? "YubiKey error (\(code))." : "YubiKey error: \(detail)."
        }
    }
}

@inline(__always) func check(_ s: P99Status) throws {
    if s != P99_OK { throw VaultError(s) }
}

/// Calls `f` with an out-buffer and copies it out; Rust zeroizes its copy.
func take(_ f: (UnsafeMutablePointer<P99Buf>) -> P99Status) throws -> Data {
    var buf = P99Buf(ptr: nil, len: 0)
    try check(f(&buf))
    defer { p99_buf_free(buf) }
    guard let p = buf.ptr else { return Data() }
    return Data(bytes: p, count: buf.len)
}

func takeString(_ f: (UnsafeMutablePointer<P99Buf>) -> P99Status) throws -> String {
    String(decoding: try take(f), as: UTF8.self)
}

func withBytes<T>(_ s: String, _ f: (UnsafePointer<UInt8>?, Int) throws -> T) rethrows -> T {
    var a = Array(s.utf8)
    defer { for i in a.indices { a[i] = 0 } }
    return try a.withUnsafeBufferPointer { try f($0.baseAddress, $0.count) }
}

// MARK: - JSON shapes

public struct CardInfo: Decodable, Equatable, Identifiable {
    public let id: String
    public let serial: UInt32
    public let has_vault: Bool
    public let mock: Bool?
}

public struct FieldInfo: Decodable, Equatable {
    public let kind: Int
    public let secret: Bool
    public let label: String?
    public let value: String?
}

public struct EntryInfo: Decodable, Equatable, Identifiable {
    public let id: String
    public let kind: Int
    public let name: String
    public let hosts: [String]
    public let username: String?
    public let has_totp: Bool
    /// 0 when unknown (items created before it was recorded).
    public let created_at: UInt32?
    public let updated_at: UInt32
    public let fields: [FieldInfo]
    public var numericId: UInt64 { UInt64(id) ?? 0 }
}

public struct Capacity: Decodable, Equatable {
    public let used: Int
    public let capacity: Int
    public let mode: String
    public let revision: UInt64
    /// Unix seconds of the last change to the vault content.
    public let updated_at: UInt32
}

/// A YubiKey that holds this vault (`p99_known_keys`).
public struct KnownKey: Decodable, Equatable, Identifiable {
    public let serial: UInt32
    public let label: String
    public let last_synced_rev: UInt64
    /// The key this session is open on.
    public let this: Bool
    public var id: UInt32 { serial }
}

public struct KnownKeys: Decodable, Equatable {
    public let revision: UInt64
    public let keys: [KnownKey]

    /// The key has missed saves made on this one since it was last synced.
    public func isBehind(_ k: KnownKey) -> Bool { !k.this && k.last_synced_rev < revision }
    public func contains(serial: UInt32) -> Bool { keys.contains { $0.serial == serial } }
}

/// What `sync(with:)` did.
public enum SyncResult: UInt32 {
    case inSync = 0, updatedOther = 1, updatedThis = 2, merged = 3
}

public enum PlainFormat: UInt32 {
    /// Logins only; opens in Chrome, 1Password and Bitwarden.
    case csv = 0
    /// Every item, lossless (99p-v1).
    case json = 1
}

public struct ImportResult: Decodable, Equatable {
    public struct Skipped: Decodable, Equatable {
        public let line: Int
        public let reason: String
    }
    public let imported: Int
    public let skipped: [Skipped]
}

/// SPEC §11.3.
public struct EntryDraft: Encodable {
    public struct Field: Encodable {
        public var kind: Int
        public var label: String?
        public var value: String
        public init(kind: Int, label: String? = nil, value: String) {
            self.kind = kind; self.label = label; self.value = value
        }
    }
    public var id: String?
    public var kind: Int
    public var name: String
    public var hosts: [String]
    public var fields: [Field]
    public init(id: String?, kind: Int, name: String, hosts: [String], fields: [Field]) {
        self.id = id; self.kind = kind; self.name = name; self.hosts = hosts; self.fields = fields
    }
}

public enum FieldKind {
    public static let username = 0x01, password = 0x02, totp = 0x03, cardNumber = 0x04,
        cardExpiry = 0x05, cardCVV = 0x06, cardHolder = 0x07, pin = 0x08, note = 0x09,
        customText = 0x10, customSecret = 0x11,
        firstName = 0x20, lastName = 0x21, email = 0x22, phone = 0x23, street = 0x24,
        city = 0x25, postcode = 0x26, region = 0x27, country = 0x28

    public static func name(_ k: Int) -> String {
        switch k {
        case username: return "Username"
        case password: return "Password"
        case totp: return "One-time code"
        case cardNumber: return "Card number"
        case cardExpiry: return "Expiry (YYYY-MM)"
        case cardCVV: return "CVV"
        case cardHolder: return "Cardholder"
        case pin: return "PIN"
        case note: return "Note"
        case firstName: return "First name"
        case lastName: return "Last name"
        case email: return "Email"
        case phone: return "Phone"
        case street: return "Address"
        case city: return "City"
        case postcode: return "Postcode"
        case region: return "State / region"
        case country: return "Country"
        default: return "Field"
        }
    }
}

public enum EntryKind {
    public static let login = 1, card = 2, note = 3, custom = 4, identity = 5
}

// MARK: - Vault

/// The single owner of FFI calls.
public final class Vault {
    public static let shared = Vault()
    public let queue = DispatchQueue(label: "app.99passwords.vault")

    /// Runs `f` on the FFI queue.
    public func run<T>(_ f: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { c in
            queue.async { c.resume(with: Result { try f() }) }
        }
    }

    public static func enableMock(cards: UInt32, demo: Bool, touchMs: UInt32) throws {
        try check(p99_mock_enable(cards, demo ? 1 : 0, touchMs))
    }

    public static func setMockPresent(_ reader: String, _ present: Bool) throws {
        try check(p99_mock_set_present(reader, present))
    }

    public static func listCards() throws -> [CardInfo] {
        try JSONDecoder().decode([CardInfo].self, from: take { p99_list_cards($0) })
    }

    public static func password(length: Int, flags: UInt32) throws -> String {
        try takeString { p99_gen_password(UInt32(length), flags, $0) }
    }

    public static func passphrase(words: Int, separator: Character = "-") throws -> String {
        try takeString { p99_gen_passphrase(UInt32(words), separator.asciiValue ?? 45, $0) }
    }
}

public enum PasswordClass {
    public static let lower: UInt32 = 1, upper: UInt32 = 2, digits: UInt32 = 4, symbols: UInt32 = 8
}

/// One open card. Close it with `close()`; it is not freed on deinit because
/// the FFI queue may still be using it.
public final class Session {
    let ptr: OpaquePointer
    public let reader: String

    init(_ ptr: OpaquePointer, reader: String) { self.ptr = ptr; self.reader = reader }

    public static func open(_ reader: String) throws -> Session {
        var p: OpaquePointer?
        try check(p99_open(reader, &p))
        return Session(p!, reader: reader)
    }

    /// The passphrase is NFC-normalised here, as SPEC §5.1 requires.
    public static func provision(_ reader: String, passphrase: String, label: String) throws -> Session {
        var p: OpaquePointer?
        try withBytes(passphrase.precomposedStringWithCanonicalMapping) { b, n in
            try check(p99_provision(reader, b, n, label, &p))
        }
        return Session(p!, reader: reader)
    }

    public func unlock(_ passphrase: String) throws {
        try withBytes(passphrase.precomposedStringWithCanonicalMapping) { b, n in
            try check(p99_unlock(ptr, b, n))
        }
    }

    /// Wrong passphrases left before the YubiKey blocks (255 when fresh).
    public func pinTriesLeft() throws -> Int {
        var n: UInt32 = 0
        try check(p99_pin_tries(ptr, &n))
        return Int(n)
    }

    public func lock() { p99_lock(ptr) }
    public func close() { p99_close(ptr) }
    public var isUnlocked: Bool { p99_is_unlocked(ptr) }

    /// `fn` runs on the PC/SC watcher thread after the session was locked.
    public func setRemovalCallback(_ ctx: UnsafeMutableRawPointer?, _ fn: P99RemovalFn?) {
        p99_set_removal_callback(ptr, fn, ctx)
    }

    /// `fn` runs on the FFI queue, right before the card waits for a touch.
    public func setTouchCallback(_ ctx: UnsafeMutableRawPointer?, _ fn: P99TouchFn?) {
        p99_set_touch_callback(ptr, fn, ctx)
    }

    public func entries(host: String? = nil) throws -> [EntryInfo] {
        let data: Data
        if let host {
            data = try take { p99_list_entries(ptr, host, $0) }
        } else {
            data = try take { p99_list_entries(ptr, nil, $0) }
        }
        return try JSONDecoder().decode([EntryInfo].self, from: data)
    }

    public func reveal(_ id: UInt64, field: Int) throws -> String {
        try takeString { p99_reveal_field(ptr, id, UInt32(field), $0) }
    }

    public func totp(_ id: UInt64, at date: Date = Date()) throws -> (code: String, secondsLeft: Int) {
        var left: UInt32 = 0
        let code = try takeString { p99_totp_now(ptr, id, UInt64(date.timeIntervalSince1970), $0, &left) }
        return (code, Int(left))
    }

    @discardableResult
    public func upsert(_ draft: EntryDraft) throws -> UInt64 {
        let json = try JSONEncoder().encode(draft)
        var id: UInt64 = 0
        try json.withUnsafeBytes { b in
            try check(p99_upsert_entry(ptr, b.bindMemory(to: UInt8.self).baseAddress, b.count, &id))
        }
        return id
    }

    public func delete(_ id: UInt64) throws { try check(p99_delete_entry(ptr, id)) }

    /// Opaque cache filename for `host` (SPEC §10).
    public func faviconName(_ host: String) throws -> String {
        try takeString { p99_favicon_name(ptr, host, $0) }
    }

    public func faviconSeal(_ host: String, png: Data) throws -> Data {
        try png.withUnsafeBytes { b in
            try take { p99_favicon_seal(ptr, host, b.bindMemory(to: UInt8.self).baseAddress, b.count, $0) }
        }
    }

    public func faviconOpen(_ host: String, blob: Data) throws -> Data {
        try blob.withUnsafeBytes { b in
            try take { p99_favicon_open(ptr, host, b.bindMemory(to: UInt8.self).baseAddress, b.count, $0) }
        }
    }

    public func capacity() throws -> Capacity {
        try JSONDecoder().decode(Capacity.self, from: take { p99_capacity(ptr, $0) })
    }

    // MARK: backup keys

    public func knownKeys() throws -> KnownKeys {
        try JSONDecoder().decode(KnownKeys.self, from: take { p99_known_keys(ptr, $0) })
    }

    /// Makes the empty YubiKey in `reader` a clone of this vault. No touch.
    public func cloneTo(_ reader: String, label: String) throws {
        try check(p99_clone_to(ptr, reader, label))
    }

    /// Reconciles with another YubiKey holding this vault (one touch on it).
    public func sync(with reader: String) throws -> SyncResult {
        var r: UInt32 = 0
        try check(p99_sync_with(ptr, reader, &r))
        return SyncResult(rawValue: r) ?? .merged
    }

    // MARK: export / import

    /// Encrypted `.99p` export; the recovery key is returned only once.
    public func exportBackup(withRecoveryKey: Bool) throws -> (file: Data, recoveryKey: String?) {
        var f = P99Buf(ptr: nil, len: 0)
        var r = P99Buf(ptr: nil, len: 0)
        defer {
            p99_buf_free(f)
            p99_buf_free(r)
        }
        try check(p99_export_backup(ptr, withRecoveryKey, &f, &r))
        let file = f.ptr.map { Data(bytes: $0, count: f.len) } ?? Data()
        let key = r.ptr.map { String(decoding: UnsafeBufferPointer(start: UnsafePointer($0), count: r.len), as: UTF8.self) }
        return (file, key)
    }

    /// Merges a `.99p` into this vault. Without a recovery key, this YubiKey
    /// opens it (one touch). Returns the number of items in the file.
    @discardableResult
    public func importBackup(_ file: Data, passphrase: String, recoveryKey: String?) throws -> Int {
        var n: UInt32 = 0
        try file.withUnsafeBytes { fb in
            let fp = fb.bindMemory(to: UInt8.self).baseAddress
            try withBytes(passphrase.precomposedStringWithCanonicalMapping) { b, len in
                if let rk = recoveryKey {
                    try check(p99_import_backup(ptr, fp, fb.count, b, len, rk, &n))
                } else {
                    try check(p99_import_backup(ptr, fp, fb.count, b, len, nil, &n))
                }
            }
        }
        return Int(n)
    }

    /// Every secret in the clear. Callers warn first and write the file 0600.
    public func exportPlain(_ format: PlainFormat) throws -> Data {
        try take { p99_export_plain(ptr, format.rawValue, $0) }
    }

    /// CSV (Chrome, 1Password, Bitwarden) or 99p-v1 JSON, in one save.
    public func importPlain(_ data: Data) throws -> ImportResult {
        let json = try data.withUnsafeBytes { b in
            try take { p99_import_plain(ptr, b.bindMemory(to: UInt8.self).baseAddress, b.count, $0) }
        }
        return try JSONDecoder().decode(ImportResult.self, from: json)
    }
}
