import AppKit
import UniformTypeIdentifiers

/// Save and open dialogs for export and import. They run as sheets on the
/// floating panel, so the panel stays open while one has focus.
@MainActor
enum Files {
    static let backup = UTType(filenameExtension: "99p") ?? .data

    static var today: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: Date())
    }

    private static var host: NSWindow? {
        NSApp.windows.first { $0 is FloatingPanel && $0.isVisible }
    }

    private static func run(_ panel: NSSavePanel) async -> URL? {
        NSApp.activate(ignoringOtherApps: true)
        if let w = host {
            return await withCheckedContinuation { c in
                panel.beginSheetModal(for: w) { r in c.resume(returning: r == .OK ? panel.url : nil) }
            }
        }
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func save(name: String, types: [UTType]) async -> URL? {
        let p = NSSavePanel()
        p.nameFieldStringValue = name
        p.allowedContentTypes = types
        p.canCreateDirectories = true
        return await run(p)
    }

    static func open(types: [UTType]) async -> URL? {
        let p = NSOpenPanel()
        p.allowedContentTypes = types
        p.allowsMultipleSelection = false
        p.canChooseDirectories = false
        return await run(p)
    }

    /// Writes `data` readable by this user only (0600), as SPEC §13.2 asks.
    static func writePrivate(_ data: Data, to url: URL) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
        guard fm.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
    }
}
