import AppKit
import Combine
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    let bridge = BridgeHandler()
    var statusItem: NSStatusItem!
    var panel: FloatingPanel!
    var monitor: Any?
    var sizing: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // No core dumps of a process that holds the vault (SPEC §5.4).
        var none = rlimit(rlim_cur: 0, rlim_max: 0)
        setrlimit(RLIMIT_CORE, &none)

        panel = FloatingPanel { RootView().environmentObject(self.model) }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.image = StatusIcon.image()
            button.target = self
            button.action = #selector(statusClicked)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        // Any input in the panel counts as activity for the idle lock.
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .scrollWheel]) { [weak self] e in
            self?.model.touch()
            return e
        }
        panel.anchor = statusItem.button
        panel.onHide = { [weak self] in self?.model.cancelFill(reqId: nil, notify: true) }
        model.showPanel = { [weak self] in self?.panel.present() }
        model.hidePanel = { [weak self] in self?.panel.hide() }
        // Short while locked, full size once unlocked. `$screen` fires before
        // the value changes; resizing right then redraws the panel with the old
        // screen and the new (emptied) state, and nothing redraws it after, so
        // the vault went blank instead of showing the lock screen. Wait a turn.
        sizing = model.$screen.removeDuplicates().receive(on: RunLoop.main).sink { [weak self] screen in
            self?.panel.fitHeight(FloatingPanel.height(for: screen))
        }
        model.bridge = bridge
        bridge.model = model
        model.start()
        bridge.start()
        DevSnapshot.run()
    }

    @objc func statusClicked() {
        if NSApp.currentEvent?.type == .rightMouseUp {
            let menu = NSMenu()
            menu.addItem(withTitle: "Open 99passwords", action: #selector(togglePanel), keyEquivalent: "")
            menu.addItem(withTitle: "Lock", action: #selector(lock), keyEquivalent: "l")
            menu.addItem(.separator())
            menu.addItem(withTitle: "Quit", action: #selector(quit), keyEquivalent: "q")
            for item in menu.items { item.target = self }
            statusItem.menu = menu
            statusItem.button?.performClick(nil)
            statusItem.menu = nil
        } else {
            togglePanel()
        }
    }

    @objc func togglePanel() {
        if panel.isVisible { panel.hide() } else { panel.present() }
    }

    @objc func lock() { model.lock() }

    @objc func quit() {
        model.lock()
        NSApp.terminate(nil)
    }
}

@main
enum Main {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
