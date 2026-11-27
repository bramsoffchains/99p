import BridgeServer
import Foundation

/// The Chrome extension's id, pinned by the `key` in extension/manifest.json.
/// More ids (a packed build) can be added with
/// `defaults write app.99passwords extensionIDs -array <id>`.
let builtInExtensionID = "bjppeeoihhidakjbpmbpmhcddcebiieg"

/// Receives browser requests on bridge threads and hands them to the model.
final class BridgeHandler: BridgeDelegate {
    weak var model: AppModel?
    private let lock = NSLock()
    private var locked = true
    let server = BridgeServer()

    var appVersion: String { Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.2" }

    var isLocked: Bool {
        lock.lock()
        defer { lock.unlock() }
        return locked
    }

    func setLocked(_ v: Bool) {
        lock.lock()
        locked = v
        lock.unlock()
    }

    func start() {
        let ids = [builtInExtensionID] + (UserDefaults.standard.stringArray(forKey: "extensionIDs") ?? [])
        server.allowedExtensionIDs = Set(ids)
        server.delegate = self
        do {
            try server.start()
            // Only point Chrome at the bridge when it is really in our bundle
            // (not when running from `swift run`).
            if FileManager.default.isExecutableFile(atPath: NativeHostManifest.bundledBridgePath) {
                try NativeHostManifest.install(extensionIDs: ids)
            }
        } catch {
            NSLog("99passwords: browser bridge not started: \(error)")
        }
    }

    func bridge(fill request: FillRequest, reply: @escaping (FillReply) -> Void) {
        Task { @MainActor [weak self] in
            guard let model = self?.model else { return reply(.error(code: "unavailable")) }
            model.beginFill(request, reply: reply)
        }
    }

    func bridge(hasMatch host: String, reply: @escaping ([LoginSummary], Bool) -> Void) {
        Task { @MainActor [weak self] in
            guard let model = self?.model, model.screen == .unlocked else { return reply([], true) }
            let logins = await model.matchingLogins(host).map {
                LoginSummary(id: $0.id, name: $0.name, username: $0.username)
            }
            reply(logins, false)
        }
    }

    func bridge(cancel reqId: String) {
        Task { @MainActor [weak self] in self?.model?.cancelFill(reqId: reqId, notify: false) }
    }
}
