import BridgeServer
import SwiftUI
import VaultKit

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 0) {
                switch model.screen {
                case .noCard: NoCardView()
                case .setup(let card): SetupFlow(card: card)
                case .locked: UnlockView()
                case .unlocked: VaultView()
                }
            }

            VStack(spacing: 6) {
                if let error = model.error {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        Text(error).font(.callout).lineLimit(2)
                        Spacer(minLength: 0)
                        IconButton(systemName: "xmark", size: 20) { model.error = nil }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .shadow(color: .black.opacity(0.1), radius: 4, y: 1)
                }
                if let t = model.toast {
                    Label(t, systemImage: "checkmark.circle.fill")
                        .font(.system(size: 12, weight: .medium))
                        .padding(.horizontal, 12).padding(.vertical, 7)
                        .background(.regularMaterial, in: Capsule())
                        .shadow(color: .black.opacity(0.12), radius: 8, y: 2)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .padding(.horizontal, 12)
            // Clear the footer; the unlock screen has none, so sit low there.
            .padding(.bottom, model.screen == .locked ? 12 : 48)
            .animation(.spring(duration: 0.3), value: model.toast)
        }
        .frame(width: FloatingPanel.size.width, height: FloatingPanel.height(for: model.screen))
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: FloatingPanel.cornerRadius, style: .continuous))
    }
}

// MARK: - Vault

struct VaultView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        switch model.route {
        case .list: EntryListView()
        case .detail(let id):
            if let e = model.entry(id) { EntryDetailView(entry: e) } else { EntryListView() }
        case .edit(let id, let kind): EditView(entry: id.flatMap(model.entry), kind: kind).id(model.route)
        case .extensionSetup: ExtensionSetupView()
        case .backup: BackupKeysView()
        case .settings: SettingsView()
        }
    }
}

struct EntryListView: View {
    @EnvironmentObject var model: AppModel
    @FocusState private var searchFocused: Bool
    @Local private var selected = 0

    var items: [EntryInfo] {
        model.fill != nil && model.query.isEmpty ? model.fillMatches : model.filtered
    }
    var current: EntryInfo? { items.indices.contains(selected) ? items[selected] : nil }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").font(.system(size: 15)).foregroundStyle(.secondary)
                TextField(model.fill.map { "Search for \($0.host)" } ?? "Search", text: $model.query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 16))
                    .focused($searchFocused)
                    .onSubmit(openSelected)
                    .onKeyPress(.downArrow) { move(1); return .handled }
                    .onKeyPress(.upArrow) { move(-1); return .handled }
                    .onKeyPress(.rightArrow) {
                        guard let e = current else { return .ignored }
                        model.route = .detail(e.id)
                        return .handled
                    }
                    .onKeyPress(characters: ["c"], phases: .down) { press in
                        guard press.modifiers.contains(.control), let e = current else { return .ignored }
                        if press.modifiers.contains(.shift) { copyPassword(e) } else if let u = e.username {
                            model.copyText(u, what: "Username")
                        }
                        return .handled
                    }
                if !model.query.isEmpty {
                    Button { model.query = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                    }.buttonStyle(.plain)
                }
                Menu {
                    Button("New Login") { model.route = .edit(nil, kind: EntryKind.login) }
                    Button("New Card") { model.route = .edit(nil, kind: EntryKind.card) }
                    Button("New Secure Note") { model.route = .edit(nil, kind: EntryKind.note) }
                    Button("New Identity") { model.route = .edit(nil, kind: EntryKind.identity) }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "plus").font(.system(size: 11, weight: .bold))
                        Text("New").font(.system(size: 13, weight: .semibold))
                    }
                    .foregroundStyle(Brand.navy)
                    .padding(.horizontal, 12)
                    .frame(height: 28)
                    .background(Capsule().fill(Brand.gold))
                    .contentShape(Capsule())
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("New item")
            }
            .padding(.horizontal, 18)
            .frame(height: 52)
            Divider()
            if let req = model.fill { FillBanner(request: req); Divider() }
            if items.isEmpty {
                Spacer()
                Text(model.fill != nil && model.query.isEmpty
                     ? (model.fill?.mode == .identity ? "No identity yet. Add one with +." : "No saved login for this site.")
                     : model.entries.isEmpty ? "No items yet. Add one with +." : "No results.")
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            Text(model.fill != nil && model.query.isEmpty ? "SUGGESTED" : model.query.isEmpty ? "ALL ITEMS" : "RESULTS")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 10)
                                .padding(.top, 12)
                                .padding(.bottom, 6)
                            ForEach(Array(items.enumerated()), id: \.element.id) { i, e in
                                EntryRow(entry: e, selected: i == selected) { open(e) }
                                    .id(e.id)
                                    .onHover { if $0 { selected = i } }
                            }
                        }
                        .padding(.horizontal, 8)
                        .padding(.bottom, 8)
                    }
                    .onChange(of: selected) { _, i in
                        if items.indices.contains(i) { proxy.scrollTo(items[i].id) }
                    }
                }
            }
            Divider()
            FooterView()
        }
        .onAppear { searchFocused = true }
        .onChange(of: model.query) { _, _ in selected = 0 }
    }

    func copyPassword(_ e: EntryInfo) {
        if let i = e.fields.firstIndex(where: { $0.kind == FieldKind.password }) { model.copy(e, field: i) }
    }

    func move(_ d: Int) {
        guard !items.isEmpty else { return }
        selected = min(max(selected + d, 0), items.count - 1)
    }

    func openSelected() {
        if let e = current { open(e) }
    }

    func open(_ e: EntryInfo) {
        if model.fill != nil { model.completeFill(e) } else { model.route = .detail(e.id) }
    }
}

/// Icon, name, and a grey second line; the selected row is a soft grey.
struct EntryRow: View {
    @EnvironmentObject var model: AppModel
    let entry: EntryInfo
    var selected = false
    let open: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            ItemIcon(entry: entry, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.name).font(.system(size: 14)).lineLimit(1)
                Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(selected ? 0.07 : 0)))
        .contentShape(Rectangle())
        .onTapGesture(perform: open)
        .contextMenu {
            if let i = entry.fields.firstIndex(where: { $0.kind == FieldKind.password }) {
                Button("Copy Password") { model.copy(entry, field: i) }
            }
            if let u = entry.username { Button("Copy Username") { model.copyText(u, what: "Username") } }
            if entry.has_totp { Button("Copy One-Time Code") { model.copyTotp(entry) } }
        }
    }

    var subtitle: String {
        if let u = entry.username { return u }
        if let h = entry.hosts.first { return h }
        if entry.kind == EntryKind.identity {
            let v = { (k: Int) in entry.fields.first { $0.kind == k }?.value }
            return v(FieldKind.email) ?? v(FieldKind.city) ?? "Identity"
        }
        switch entry.kind {
        case EntryKind.card: return "Credit card"
        case EntryKind.note: return "Secure note"
        default: return ""
        }
    }
}

struct FooterView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        HStack(spacing: 14) {
            // No shortcut hints: ⌃C, ⌃⇧C and → still work in the list.
            if let c = model.capacity {
                let updated = Date(timeIntervalSince1970: TimeInterval(c.updated_at))
                Text("Updated \(updated.formatted(date: .abbreviated, time: .shortened)) · \(max(1, c.used / 1024)) of \(c.capacity / 1024) KB")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .help("Last change to the vault · revision \(c.revision) · \(c.used) of \(c.capacity) bytes used on the YubiKey")
            }
            Spacer()
            Button { model.route = .settings } label: { Image(systemName: "gearshape") }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .keyboardShortcut(",", modifiers: .command)
                .help("Settings (⌘,)")
            Button { model.lock() } label: { Image(systemName: "lock") }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .keyboardShortcut("l", modifiers: .command)
                .help("Lock (⌘L)")
        }
        .padding(.horizontal, 18)
        .frame(height: 34)
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.6))
    }
}

struct FillBanner: View {
    @EnvironmentObject var model: AppModel
    let request: FillRequest

    var body: some View {
        HStack(spacing: 8) {
            Text(request.mode == .totp ? "Fill a one-time code into "
                 : request.mode == .identity ? "Fill your details into " : "Fill into ")
                .foregroundColor(.secondary) + Text(request.host).fontWeight(.medium)
            Spacer()
            if request.mode == .identity {
                Button { model.route = .edit(nil, kind: EntryKind.identity) } label: { Label("New Identity", systemImage: "plus") }
                    .buttonStyle(PillButtonStyle(prominent: false))
            } else if request.mode != .totp {
                Button { model.route = .edit(nil, kind: EntryKind.login) } label: { Label("New Login", systemImage: "plus") }
                    .buttonStyle(PillButtonStyle(prominent: false))
            }
            Button("Cancel") { model.cancelFill(reqId: nil, notify: true) }.buttonStyle(PillButtonStyle(prominent: false))
        }
        .font(.system(size: 12))
        .padding(.horizontal, 18)
        .frame(height: 38)
    }
}

// MARK: - Detail

/// Big icon and title, then the fields in one bordered card with small
/// coloured labels, like 1Password's item view. Hover a field to copy it.
struct EntryDetailView: View {
    @EnvironmentObject var model: AppModel
    let entry: EntryInfo
    @Local private var revealed: [Int: String] = [:]
    @Local private var confirmDelete = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                IconButton(systemName: "chevron.left", help: "Back (Esc)") { model.route = .list }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button { model.route = .edit(entry.id, kind: entry.kind) } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .buttonStyle(PillButtonStyle(prominent: false))
                .keyboardShortcut("e", modifiers: .command)
            }
            .padding(.horizontal, 12)
            .frame(height: 40)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 14) {
                        ItemIcon(entry: entry, size: 44)
                        Text(entry.name).font(.system(size: 20, weight: .semibold)).lineLimit(1)
                    }
                    .padding(.horizontal, 4)
                    if !entry.fields.isEmpty {
                        VStack(spacing: 0) {
                            ForEach(Array(entry.fields.enumerated()), id: \.offset) { i, f in
                                if i > 0 { Divider() }
                                if f.kind == FieldKind.totp {
                                    FieldRow(title: "one-time password", copy: { model.copyTotp(entry) }) {
                                        TotpView(entry: entry)
                                    } actions: { EmptyView() }
                                } else {
                                    FieldRow(title: (f.label ?? FieldKind.name(f.kind)).lowercased(), copy: { copy(i, f) }) {
                                        value(i, f)
                                    } actions: {
                                        if f.secret {
                                            IconButton(systemName: revealed[i] == nil ? "eye" : "eye.slash",
                                                       help: revealed[i] == nil ? "Reveal" : "Hide") { toggle(i) }
                                        }
                                    }
                                }
                            }
                        }
                        .card()
                    }
                    ForEach(entry.hosts, id: \.self) { h in
                        VStack(alignment: .leading, spacing: 3) {
                            Text("website").font(.system(size: 12)).foregroundStyle(Brand.label)
                            Link(destination: URL(string: "https://\(h)")!) { Text(h).font(.system(size: 14)) }
                        }
                        .padding(.horizontal, 14)
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        if let c = entry.created_at, c > 0 { Text("Created \(itemDate(c))") }
                        if entry.updated_at > 0 { Text("Last edited \(itemDate(entry.updated_at))") }
                    }
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                    .padding(.horizontal, 14)
                    HStack {
                        if confirmDelete {
                            Text("Delete \(entry.name)?").font(.system(size: 12))
                                .lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Button("Cancel") { confirmDelete = false }.buttonStyle(PillButtonStyle(prominent: false))
                            Button { model.delete(entry) } label: { Label("Delete", systemImage: "trash") }
                                .buttonStyle(PillButtonStyle(destructive: true))
                        } else {
                            Button("Delete item…") { confirmDelete = true }
                                .buttonStyle(.plain).font(.system(size: 12)).foregroundStyle(.secondary)
                            Spacer()
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.top, 6)
                }
                .padding(.horizontal, 18)
                .padding(.top, 4)
                .padding(.bottom, 16)
            }
            Divider()
            FooterView()
        }
    }

    func toggle(_ i: Int) {
        if revealed[i] != nil { revealed[i] = nil } else {
            Task { revealed[i] = await model.reveal(entry, field: i) }
        }
    }

    func copy(_ i: Int, _ f: FieldInfo) {
        if f.secret { model.copy(entry, field: i) } else if let v = f.value {
            model.copyText(v, what: f.label ?? FieldKind.name(f.kind))
        }
    }

    @ViewBuilder func value(_ i: Int, _ f: FieldInfo) -> some View {
        if !f.secret {
            Text(f.value ?? "")
        } else if let r = revealed[i] {
            Text(r).font(.system(size: 14, design: .monospaced))
        } else {
            Text("••••••••••")
        }
    }
}

/// One field in the detail card: small coloured label over the value.
/// Clicking copies it; hovering shows "Copy".
struct FieldRow<Value: View, Actions: View>: View {
    let title: String
    let copy: () -> Void
    @ViewBuilder let value: () -> Value
    @ViewBuilder let actions: () -> Actions
    @Local private var hover = false

    var body: some View {
        HStack(spacing: 6) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 12)).foregroundStyle(Brand.label)
                value().font(.system(size: 14)).lineLimit(1)
            }
            Spacer(minLength: 4)
            actions()
            if hover {
                Text("Copy").font(.system(size: 12)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(Color.primary.opacity(hover ? 0.035 : 0))
        .contentShape(Rectangle())
        .onTapGesture(perform: copy)
        .onHover { hover = $0 }
    }
}

struct TotpView: View {
    @EnvironmentObject var model: AppModel
    let entry: EntryInfo
    @Local private var code = "------"
    @Local private var left = 30

    var body: some View {
        HStack(spacing: 8) {
            Text(code.count == 6 ? "\(code.prefix(3)) • \(code.suffix(3))" : code)
            ZStack {
                Circle().stroke(Color.primary.opacity(0.1), lineWidth: 2)
                Circle().trim(from: 0, to: CGFloat(left) / 30)
                    .stroke(left <= 5 ? Color.orange : Color.green, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 12, height: 12)
            Text("\(left)").font(.system(size: 11).monospacedDigit()).foregroundStyle(.secondary)
        }
        .task {
            while !Task.isCancelled {
                if let t = await model.totp(entry) { code = t.code; left = t.secondsLeft }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }
}
