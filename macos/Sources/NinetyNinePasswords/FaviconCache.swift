import AppKit
import VaultKit

/// Encrypted favicon cache (SPEC §10). Filenames are HMACs of the host and
/// contents are sealed with a vault-derived key, so the locked cache shows
/// no domain names. Only readable while unlocked.
enum FaviconCache {
    static var directory: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("app.99passwords/favicons", isDirectory: true)
    }

    /// Call on the FFI queue.
    static func store(_ session: Session, host: String, png: Data) {
        guard let name = try? session.faviconName(host),
              let blob = try? session.faviconSeal(host, png: png) else { return }
        let dir = directory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let url = dir.appendingPathComponent(name)
        _ = FileManager.default.createFile(atPath: url.path, contents: blob, attributes: [.posixPermissions: 0o600])
    }

    /// Call on the FFI queue.
    static func load(_ session: Session, host: String) -> Data? {
        guard let name = try? session.faviconName(host),
              let blob = try? Data(contentsOf: directory.appendingPathComponent(name)) else { return nil }
        return try? session.faviconOpen(host, blob: blob)
    }
}
