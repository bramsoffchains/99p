import AppKit
import SwiftUI

/// A frosted dropdown panel under the menu bar icon: it takes keyboard focus
/// without activating the app (so the browser stays frontmost) and hides
/// when it loses focus or on Escape.
final class FloatingPanel: NSPanel {
    static let size = NSSize(width: 360, height: 500)
    /// The unlock screen is short; everything else gets the full height.
    static let lockedHeight: CGFloat = 330
    static let cornerRadius: CGFloat = 12

    static func height(for screen: AppModel.Screen) -> CGFloat {
        screen == .locked ? lockedHeight : size.height
    }

    /// Resizes from the bottom, so the top stays under the menu bar.
    func fitHeight(_ h: CGFloat) {
        guard abs(frame.height - h) > 0.5 else { return }
        let f = NSRect(x: frame.minX, y: frame.maxY - h, width: frame.width, height: h)
        setFrame(f, display: true, animate: isVisible)
    }

    init<Content: View>(@ViewBuilder content: () -> Content) {
        super.init(
            contentRect: NSRect(origin: .zero, size: Self.size),
            styleMask: [.borderless, .nonactivatingPanel, .fullSizeContentView],
            backing: .buffered, defer: false)
        isFloatingPanel = true
        level = .statusBar
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        // Tab moves between fields: SwiftUI's text fields join the window's
        // key view loop only when the window recalculates it.
        autorecalculatesKeyViewLoop = true
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true

        // Opaque white (dark in Dark Mode), rounded, with a hairline border,
        // like 1Password's windows.
        let base = NSView()
        base.wantsLayer = true
        base.layer?.backgroundColor = NSColor.textBackgroundColor.cgColor
        base.layer?.cornerRadius = Self.cornerRadius
        base.layer?.cornerCurve = .continuous
        base.layer?.masksToBounds = true
        base.layer?.borderWidth = 0.5
        base.layer?.borderColor = NSColor.separatorColor.cgColor
        let host = NSHostingView(rootView: content())
        host.translatesAutoresizingMaskIntoConstraints = false
        base.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: base.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: base.trailingAnchor),
            host.topAnchor.constraint(equalTo: base.topAnchor),
            host.bottomAnchor.constraint(equalTo: base.bottomAnchor),
        ])
        contentView = base
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }

    /// Called whenever the panel hides (focus lost, Escape, or explicitly).
    var onHide: () -> Void = {}

    /// False for offscreen snapshots: show without taking keyboard focus.
    var takesFocus = true

    /// The menu bar button to drop down from.
    weak var anchor: NSStatusBarButton?

    override func resignKey() {
        super.resignKey()
        // Keep it while one of its own popovers or sheets has focus.
        DispatchQueue.main.async { [weak self] in
            guard let self, self.isVisible, !self.isKeyWindow else { return }
            if let k = NSApp.keyWindow, k.sheetParent === self || k.parent === self || k.className.contains("Popover") {
                return
            }
            self.hide()
        }
    }

    override func cancelOperation(_ sender: Any?) { hide() }

    func hide() {
        orderOut(nil)
        onHide()
    }

    /// Drops the panel down just under the menu bar icon, kept on screen.
    /// Without a visible icon, it goes under the menu bar at the mouse.
    func present() {
        let gap: CGFloat = 6
        if let button = anchor, let win = button.window,
           case let r = win.convertToScreen(button.convert(button.bounds, to: nil)),
           let screen = NSScreen.screens.first(where: { $0.frame.contains(NSPoint(x: r.midX, y: r.midY)) }) {
            let vf = screen.visibleFrame
            let x = min(max(r.midX - frame.width / 2, vf.minX + 8), vf.maxX - frame.width - 8)
            setFrameOrigin(NSPoint(x: x, y: r.minY - frame.height - gap))
        } else {
            let mouse = NSEvent.mouseLocation
            let screen = NSScreen.screens.first { $0.frame.contains(mouse) } ?? NSScreen.main
            if let vf = screen?.visibleFrame {
                let x = min(max(mouse.x - frame.width / 2, vf.minX + 8), vf.maxX - frame.width - 8)
                setFrameOrigin(NSPoint(x: x, y: vf.maxY - frame.height - gap))
            }
        }
        if takesFocus { makeKeyAndOrderFront(nil) } else { orderFrontRegardless() }
    }
}
