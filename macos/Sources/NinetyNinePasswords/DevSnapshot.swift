import AppKit
import SwiftUI

/// Developer aid: renders the menu bar icon (`P99_STATUS_OUT`) or the app
/// icon artwork (`P99_ICON_OUT`, used by make-icon.sh) to a PNG and quits.
@MainActor
enum DevSnapshot {
    static func run() {
        if let out = ProcessInfo.processInfo.environment["P99_STATUS_OUT"] {
            // The menu bar icon at 8x, black on white, for checking it.
            let img = StatusIcon.image()
            let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 144, pixelsHigh: 144, bitsPerSample: 8,
                                       samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                       colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
            NSColor.white.setFill()
            NSRect(x: 0, y: 0, width: 144, height: 144).fill()
            img.draw(in: NSRect(x: 0, y: 0, width: 144, height: 144))
            NSGraphicsContext.restoreGraphicsState()
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
            NSApp.terminate(nil)
            return
        }
        if let out = ProcessInfo.processInfo.environment["P99_ICON_OUT"] {
            // Renders the app icon artwork (used by macos/make-icon.sh).
            let r = ImageRenderer(content: AppIconArt())
            r.scale = 1
            if let img = r.nsImage, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) {
                try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
            }
            NSApp.terminate(nil)
            return
        }
    }
}
