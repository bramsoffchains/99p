import AppKit
import BridgeServer
import Combine
import UniformTypeIdentifiers
import VaultKit

/// UI state. Lives on the main actor; every vault call hops to the FFI queue.
@MainActor
final class AppModel: ObservableObject {
    enum Screen: Equatable {
        case noCard
        case setup(CardInfo)
        case locked
        case unlocked
    }

    enum Route: Hashable {
        case list
        case detail(String)
        case edit(String?, kind: Int)
        /// Clone to a backup YubiKey, sync a stale one.
        case backup
        /// Settings: auto-lock, backups and transfer, about.
        case settings
        /// How to add the Chrome extension (after setup, or from Settings).
        case extensionSetup
    }

    @Published var screen: Screen = .noCard {
        didSet { bridge?.setLocked(screen != .unlocked) }
    }
    @Published var route: Route = .list
    @Published var cards: [CardInfo] = []
    @Published var entries: [EntryInfo] = []
    @Published var capacity: Capacity?
    @Published var query = ""
    @Published var busy = false
    @Published var touchPrompt = false
    @Published var error: String?
    /// A browser request waiting for the user to pick an entry.
    @Published var fill: FillRequest?
    @Published var fillMatches: [EntryInfo] = []
    @Published var icons: [String: NSImage] = [:]
    /// Short confirmation shown at the bottom of the panel ("Password copied").
    @Published var toast: String?
    /// Wrong passphrases the open YubiKey still accepts before it blocks.
    @Published var pinTriesLeft: Int?
    /// Tries left at or below which the count is shown: 255 - 10 wrong.
    static let showTriesBelow = 245
    /// YubiKeys holding this vault, for the backup screen.
    @Published var knownKeys: KnownKeys?
    private var fillReply: ((FillReply) -> Void)?
    var bridge: BridgeHandler?
    var showPanel: () -> Void = {}
    var hidePanel: () -> Void = {}

    private(set) var session: Session?
    private let vault = Vault.shared
    private var lastActivity = Date()
    private var timers: [Timer] = []
    /// Minutes of inactivity before the vault locks; 0 means never.
    static let autoLockKey = "autoLockMinutes"
    var idleLockSeconds: TimeInterval {
        let m = UserDefaults.standard.object(forKey: Self.autoLockKey) as? Int ?? 5
        return m == 0 ? .infinity : TimeInterval(m * 60)
    }
    let clipboardClearSeconds: TimeInterval = 30

    // MARK: cards and sessions

    func start() {
        refreshCards()
        timers.append(Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkIdle() }
        })
        // Notice a YubiKey being plugged in.
        timers.append(Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in if self?.screen == .noCard { self?.refreshCards() } }
        })
        let ws = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            ws.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock() }
            }
        }
        DistributedNotificationCenter.default().addObserver(
            forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.lock() }
        }
    }

    func refreshCards() {
        cards = (try? Vault.listCards()) ?? []
        if let s = session, cards.contains(where: { $0.id == s.reader }) { return }
        closeSession()
        if let card = cards.first(where: { $0.has_vault }) {
            open(card)
        } else if let card = cards.first {
            screen = .setup(card)
        } else {
            screen = .noCard
        }
    }

    func open(_ card: CardInfo) {
        closeSession()
        guard card.has_vault else { screen = .setup(card); return }
        do {
            let s = try Session.open(card.id)
            attach(s)
            screen = .locked
            Task { await refreshPinTries() }
        } catch {
            show(error)
        }
    }

    private func attach(_ s: Session) {
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        s.setRemovalCallback(ctx) { ctx, _ in
            let model = Unmanaged<AppModel>.fromOpaque(ctx!).takeUnretainedValue()
            Task { @MainActor in model.cardRemoved() }
        }
        s.setTouchCallback(ctx) { ctx in
            let model = Unmanaged<AppModel>.fromOpaque(ctx!).takeUnretainedValue()
            Task { @MainActor in model.touchPrompt = true }
        }
        session = s
    }

    private func closeSession() {
        guard let s = session else { return }
        session = nil
        pinTriesLeft = nil
        entries = []
        vault.queue.async { s.close() }
    }

    func cardRemoved() {
        // The FFI already locked and wiped the session.
        cancelFill(reqId: nil, notify: true)
        icons = [:]
        entries = []
        capacity = nil
        knownKeys = nil
        route = .list
        // The connection is dead even if the key is still in (another app
        // reset it), so drop it: refreshCards then reopens a present key.
        closeSession()
        refreshCards()
        if case .unlocked = screen { screen = .locked }
    }

    // MARK: lock / unlock

    func unlock(_ passphrase: String) {
        guard let s = session, !busy else { return }
        busy = true
        touchPrompt = false
        error = nil
        Task {
            do {
                try await vault.run { try s.unlock(passphrase) }
                screen = .unlocked
                route = fill?.mode == .signup ? .edit(nil, kind: EntryKind.login) : .list
                touch()
                await reload()
            } catch {
                show(error)
                await refreshPinTries()
                if (error as? VaultError)?.isWrongPin == true {
                    // The count only shows after 10 wrong tries (of 255).
                    if let n = pinTriesLeft, n <= Self.showTriesBelow {
                        self.error = "Wrong master password. \(n) \(n == 1 ? "try" : "tries") left before this YubiKey blocks."
                    } else {
                        self.error = "Wrong master password."
                    }
                }
            }
            busy = false
            touchPrompt = false
        }
    }

    func refreshPinTries() async {
        guard let s = session else { pinTriesLeft = nil; return }
        pinTriesLeft = try? await vault.run { try s.pinTriesLeft() }
    }

    func provision(_ card: CardInfo, passphrase: String, label: String) {
        busy = true
        error = nil
        Task {
            do {
                let s = try await vault.run { try Session.provision(card.id, passphrase: passphrase, label: label) }
                closeSession()
                attach(s)
                cards = (try? Vault.listCards()) ?? []
                screen = .unlocked
                // Offer the Chrome extension once the vault exists (hidden for now).
                route = ExtensionSetupView.enabled ? .extensionSetup : .list
                touch()
                await reload()
            } catch {
                show(error)
            }
            busy = false
        }
    }

    func lock() {
        guard let s = session else { return }
        entries = []
        cancelFill(reqId: nil, notify: true)
        icons = [:]
        capacity = nil
        knownKeys = nil
        route = .list
        query = ""
        vault.queue.async { s.lock() }
        if screen == .unlocked { screen = .locked }
    }

    func touch() { lastActivity = Date() }

    private func checkIdle() {
        if screen == .unlocked, Date().timeIntervalSince(lastActivity) > idleLockSeconds { lock() }
    }

    // MARK: entries

    func reload() async {
        guard let s = session else { return }
        let host = fill?.host
        let png = fill?.faviconPNG
        do {
            let (list, matches, cap) = try await vault.run {
                (try s.entries(), try host.map { try s.entries(host: $0) } ?? [], try s.capacity())
            }
            entries = list
            // Identities fit any site, so an identity fill lists them all.
            fillMatches = fill?.mode == .identity ? list.filter { $0.kind == EntryKind.identity } : matches
            capacity = cap
            let hosts = Set(list.compactMap(\.hosts.first))
            let loaded: [String: Data] = try await vault.run {
                if let host, let png { FaviconCache.store(s, host: host, png: png) }
                var out: [String: Data] = [:]
                for h in hosts { out[h] = FaviconCache.load(s, host: h) }
                if let host, out[host] == nil { out[host] = FaviconCache.load(s, host: host) }
                return out
            }
            icons = loaded.compactMapValues { NSImage(data: $0) }
        } catch {
            show(error)
        }
    }

    // MARK: browser fill (SPEC §12.2)

    func beginFill(_ request: FillRequest, reply: @escaping (FillReply) -> Void) {
        cancelFill(reqId: nil, notify: true)
        fill = request
        fillReply = reply
        query = ""
        fillMatches = []
        // Picked in the field dropdown: fill that login without the panel,
        // if it really is one of this site's logins.
        if let id = request.entryId, request.mode == .login, screen == .unlocked {
            Task {
                if let e = await matchingLogins(request.host).first(where: { $0.id == id }), fill?.reqId == request.reqId {
                    completeFill(e)
                } else if fill?.reqId == request.reqId {
                    route = .list
                    await reload()
                    showPanel()
                }
            }
            return
        }
        if screen == .unlocked {
            route = request.mode == .signup ? .edit(nil, kind: EntryKind.login) : .list
            Task { await reload() }
        }
        showPanel()
    }

    /// For the extension's toolbar dot and field dropdown: the logins for `host`, best match first.
    func matchingLogins(_ host: String) async -> [EntryInfo] {
        guard screen == .unlocked, let s = session else { return [] }
        let found = (try? await vault.run { try s.entries(host: host) }) ?? []
        return found.filter { $0.kind == EntryKind.login }
    }

    /// Drops the pending request; `notify` tells the extension it was cancelled.
    func cancelFill(reqId: String?, notify: Bool) {
        guard let f = fill, reqId == nil || reqId == f.reqId else { return }
        if notify { fillReply?(.cancel) }
        fill = nil
        fillReply = nil
        fillMatches = []
        if case .edit = route { route = .list }
    }

    /// Sends the chosen entry's credentials to the page and closes the panel.
    func completeFill(_ e: EntryInfo) {
        guard let req = fill, let reply = fillReply else { return }
        fill = nil
        fillReply = nil
        Task {
            if req.mode == .identity {
                reply(.identity(identityFields(e.fields.map { (kind: $0.kind, value: $0.value) })))
            } else if req.mode == .totp {
                reply(.fill(username: nil, password: nil, totp: await totp(e)?.code))
            } else {
                let pw = e.fields.firstIndex { $0.kind == FieldKind.password }
                let password: String? = pw == nil ? nil : await reveal(e, field: pw!)
                reply(.fill(username: e.username, password: password, totp: nil))
            }
            fillMatches = []
            route = .list
            hidePanel()
        }
    }

    /// An identity's fields as the extension expects them (all non-secret).
    func identityFields(_ fields: [(kind: Int, value: String?)]) -> [String: String] {
        let keys = [FieldKind.firstName: "first_name", FieldKind.lastName: "last_name", FieldKind.email: "email",
                    FieldKind.phone: "phone", FieldKind.street: "street", FieldKind.city: "city",
                    FieldKind.postcode: "postcode", FieldKind.region: "region", FieldKind.country: "country"]
        var out: [String: String] = [:]
        for f in fields {
            if let k = keys[f.kind], let v = f.value, !v.isEmpty, out[k] == nil { out[k] = v }
        }
        return out
    }

    var filtered: [EntryInfo] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return entries }
        return entries.filter { e in
            e.name.lowercased().contains(q) || e.hosts.contains { $0.contains(q) }
                || (e.username?.lowercased().contains(q) ?? false)
        }
    }

    func entry(_ id: String) -> EntryInfo? { entries.first { $0.id == id } }

    func reveal(_ e: EntryInfo, field: Int) async -> String? {
        guard let s = session else { return nil }
        touch()
        do { return try await vault.run { try s.reveal(e.numericId, field: field) } } catch {
            show(error)
            return nil
        }
    }

    func totp(_ e: EntryInfo) async -> (code: String, secondsLeft: Int)? {
        guard let s = session else { return nil }
        return try? await vault.run { try s.totp(e.numericId) }
    }

    func copy(_ e: EntryInfo, field: Int) {
        Task {
            if let v = await reveal(e, field: field) {
                copyText(v, what: e.fields[field].label ?? FieldKind.name(e.fields[field].kind))
            }
        }
    }

    func copyTotp(_ e: EntryInfo) {
        Task {
            if let t = await totp(e) { copyText(t.code, what: "One-time code") }
        }
    }

    /// Copies, clears the clipboard later, and confirms with a toast.
    func copyText(_ v: String, what: String) {
        Clipboard.copy(v, clearAfter: clipboardClearSeconds)
        flash("\(what) copied · clears in \(Int(clipboardClearSeconds)) s", seconds: 2)
    }

    /// Copies something that isn't secret (no auto-clear) and confirms it.
    func copyPlain(_ v: String, what: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(v, forType: .string)
        flash("\(what) copied", seconds: 2)
    }

    func save(_ draft: EntryDraft) async -> Bool {
        guard let s = session else { return false }
        touch()
        busy = true
        defer { busy = false }
        do {
            let id = try await vault.run { try s.upsert(draft) }
            // "Fill & Save": the entry is on the card before the page gets it.
            if draft.id == nil, let reply = fillReply, fill?.mode == .identity, draft.kind == EntryKind.identity {
                reply(.identity(identityFields(draft.fields.map { (kind: $0.kind, value: Optional($0.value)) })))
                fill = nil
                fillReply = nil
                hidePanel()
            } else if draft.id == nil, let reply = fillReply, fill?.mode != .totp, fill?.mode != .identity {
                let value = { (k: Int) in draft.fields.first { $0.kind == k }?.value }
                reply(.fill(username: value(FieldKind.username), password: value(FieldKind.password), totp: nil))
                fill = nil
                fillReply = nil
                hidePanel()
            }
            await reload()
            route = .detail(String(id))
            return true
        } catch {
            show(error)
            return false
        }
    }

    func delete(_ e: EntryInfo) {
        guard let s = session else { return }
        Task {
            do {
                try await vault.run { try s.delete(e.numericId) }
                route = .list
                await reload()
            } catch {
                show(error)
            }
        }
    }

    // MARK: backup keys

    func loadKnownKeys() async {
        guard let s = session else { return }
        knownKeys = try? await vault.run { try s.knownKeys() }
    }

    /// Plugged-in YubiKeys other than the open one.
    func otherCards() async -> [CardInfo] {
        let reader = session?.reader
        let list = (try? await vault.run { try Vault.listCards() }) ?? []
        return list.filter { $0.id != reader }
    }

    func cloneTo(_ card: CardInfo, label: String) async -> Bool {
        guard let s = session, !busy else { return false }
        touch()
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await vault.run { try s.cloneTo(card.id, label: label) }
            await loadKnownKeys()
            await reload()
            flash("Backup key ready")
            return true
        } catch {
            show(error)
            return false
        }
    }

    func sync(_ card: CardInfo) async {
        guard let s = session, !busy else { return }
        touch()
        busy = true
        touchPrompt = false
        error = nil
        defer { busy = false; touchPrompt = false }
        do {
            let r = try await vault.run { try s.sync(with: card.id) }
            await loadKnownKeys()
            await reload()
            switch r {
            case .inSync: flash("Already up to date")
            case .updatedOther: flash("Backup key updated")
            case .updatedThis: flash("Updated from the backup key")
            case .merged: flash("Both keys merged and updated")
            }
        } catch {
            show(error)
        }
    }

    // MARK: export / import

    /// Exports an encrypted .99p. Returns the recovery key to show, once.
    func exportBackup(withRecoveryKey: Bool) async -> String? {
        guard let s = session, !busy else { return nil }
        touch()
        busy = true
        defer { busy = false }
        do {
            let (file, rk) = try await vault.run { try s.exportBackup(withRecoveryKey: withRecoveryKey) }
            guard let url = await Files.save(name: "99passwords \(Files.today).99p", types: [Files.backup]) else { return nil }
            try Files.writePrivate(file, to: url)
            flash("Encrypted backup saved")
            return rk
        } catch {
            show(error)
            return nil
        }
    }

    func importBackup(_ url: URL, passphrase: String, recoveryKey: String?) async -> Bool {
        guard let s = session, !busy else { return false }
        touch()
        busy = true
        touchPrompt = false
        error = nil
        defer { busy = false; touchPrompt = false }
        do {
            let data = try Data(contentsOf: url)
            let n = try await vault.run { try s.importBackup(data, passphrase: passphrase, recoveryKey: recoveryKey) }
            await reload()
            flash("Merged \(n) item\(n == 1 ? "" : "s") from the backup")
            return true
        } catch {
            show(error)
            return false
        }
    }

    func exportPlain(_ format: PlainFormat) async {
        guard let s = session, !busy else { return }
        touch()
        busy = true
        defer { busy = false }
        do {
            let ext = format == .csv ? "csv" : "json"
            let type: UTType = format == .csv ? .commaSeparatedText : .json
            guard let url = await Files.save(name: "99passwords \(Files.today) UNENCRYPTED.\(ext)", types: [type])
            else { return }
            var data = try await vault.run { try s.exportPlain(format) }
            defer { data.resetBytes(in: 0..<data.count) }
            try Files.writePrivate(data, to: url)
            flash("Plaintext saved. Delete it when done")
        } catch {
            show(error)
        }
    }

    func importPlain(_ url: URL) async -> ImportResult? {
        guard let s = session, !busy else { return nil }
        touch()
        busy = true
        error = nil
        defer { busy = false }
        do {
            var data = try Data(contentsOf: url)
            defer { data.resetBytes(in: 0..<data.count) }
            let input = data
            let r = try await vault.run { try s.importPlain(input) }
            await reload()
            return r
        } catch {
            show(error)
            return nil
        }
    }

    /// The short confirmation at the bottom of the panel.
    func flash(_ msg: String, seconds: TimeInterval = 2.5) {
        toast = msg
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { [weak self] in
            if self?.toast == msg { self?.toast = nil }
        }
    }

    func show(_ e: Error) {
        error = (e as? LocalizedError)?.errorDescription ?? e.localizedDescription
        if let v = e as? VaultError, v.isCardRemoved || v.isLocked { cardRemoved() }
    }
}
