import Foundation

/// Chrome native messaging host manifest (SPEC §12.1). It holds no secrets;
/// the app rewrites it at launch so it follows the bundle if it moves.
public enum NativeHostManifest {
    public static let hostName = "app.99passwords.bridge"

    public static var chromeDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Google/Chrome/NativeMessagingHosts")
    }

    /// The bridge binary inside the running app bundle.
    public static var bundledBridgePath: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/99p-bridge").path
    }

    public static func json(bridgePath: String, extensionIDs: [String]) throws -> Data {
        let manifest: [String: Any] = [
            "name": hostName,
            "description": "99passwords bridge",
            "path": bridgePath,
            "type": "stdio",
            "allowed_origins": extensionIDs.sorted().map { "chrome-extension://\($0)/" },
        ]
        return try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
    }

    /// Writes the manifest if it is missing or different. Returns its URL.
    @discardableResult
    public static func install(bridgePath: String = bundledBridgePath,
                               extensionIDs: [String],
                               directory: URL = chromeDirectory) throws -> URL {
        let data = try json(bridgePath: bridgePath, extensionIDs: extensionIDs)
        let url = directory.appendingPathComponent("\(hostName).json")
        if (try? Data(contentsOf: url)) == data { return url }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
        return url
    }
}
