import BridgeServer
import SwiftUI
import VaultKit

// MARK: - Edit / create

struct EditView: View {
    @EnvironmentObject var model: AppModel
    let entry: EntryInfo?
    let kind: Int

    struct Row: Identifiable {
        let id = UUID()
        var kind: Int
        var label: String?
        var value: String
    }

    @Local private var name = ""
    @Local private var sites: [String] = []
    @Local private var rows: [Row] = []
    @Local private var loaded = false

    var title: String {
        if entry != nil { return "Edit item" }
        switch kind {
        case EntryKind.card: return "New card"
        case EntryKind.note: return "New secure note"
        case EntryKind.identity: return "New identity"
        default: return "New login"
        }
    }

    var isIdentity: Bool { kind == EntryKind.identity }

    /// Identities are named after the person: "First Last".
    var identityName: String {
        [FieldKind.firstName, FieldKind.lastName]
            .compactMap { k in rows.first { $0.kind == k }?.value.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }

    var finalName: String { isIdentity ? identityName : name.trimmingCharacters(in: .whitespaces) }

    var canSave: Bool { !finalName.isEmpty && !model.busy }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button("Cancel") { model.route = entry.map { .detail($0.id) } ?? .list }
                    .buttonStyle(PillButtonStyle(prominent: false))
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Text(title).font(.system(size: 13, weight: .semibold))
                Spacer()
                Button(entry == nil && model.fill != nil ? "Fill & Save" : "Save") { save() }
                    .buttonStyle(PillButtonStyle())
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    titleRow
                    if !mainRows.isEmpty {
                        VStack(spacing: 0) {
                            ForEach(Array(mainRows.enumerated()), id: \.element) { n, i in
                                if n > 0 { Divider() }
                                fieldRow($rows[i])
                            }
                        }
                        .card()
                    }
                    if kind == EntryKind.login { websites }
                    addMore
                    if let i = rows.firstIndex(where: { $0.kind == FieldKind.note }) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("notes").font(.system(size: 12)).foregroundStyle(Brand.label)
                            ZStack(alignment: .topLeading) {
                                if rows[i].value.isEmpty {
                                    Text("Add any notes about this item here.").foregroundStyle(.tertiary)
                                        .padding(.top, 1)
                                }
                                TextEditor(text: $rows[i].value)
                                    .scrollContentBackground(.hidden)
                                    .padding(.leading, -5)
                                    .frame(minHeight: 60)
                            }
                            .font(.system(size: 14))
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .card()
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 4)
                .padding(.bottom, 20)
            }
        }
        .task { await load() }
    }

    // Everything except notes, in order.
    var mainRows: [Int] { rows.indices.filter { rows[$0].kind != FieldKind.note } }

    @ViewBuilder var titleRow: some View {
        HStack(spacing: 12) {
            KindTile(kind: kind, name: finalName, size: 52)
            if isIdentity {
                // No separate title: the name comes from the fields below.
                Text(identityName.isEmpty ? "New identity" : identityName)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(identityName.isEmpty ? .tertiary : .primary)
                    .lineLimit(1)
                Spacer(minLength: 0)
            } else {
                TextField("Enter a title", text: $name)
                    .textFieldStyle(.plain)
                    .font(.system(size: 19, weight: .semibold))
                    .padding(.horizontal, 14)
                    .frame(height: 52)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(0.05)))
            }
        }
        .padding(.bottom, 4)
    }

    /// One field in a card: small navy label, borderless value.
    @ViewBuilder func fieldRow(_ row: Binding<Row>) -> some View {
        let r = row.wrappedValue
        let custom = r.kind == FieldKind.customText || r.kind == FieldKind.customSecret
        HStack(alignment: .center, spacing: 6) {
            VStack(alignment: .leading, spacing: 3) {
                if custom {
                    TextField("label", text: Binding(get: { row.wrappedValue.label ?? "" },
                                                     set: { row.wrappedValue.label = $0.isEmpty ? nil : $0 }))
                        .textFieldStyle(.plain)
                        .font(.system(size: 12)).foregroundStyle(Brand.label)
                } else {
                    Text((r.label ?? FieldKind.name(r.kind)).lowercased())
                        .font(.system(size: 12)).foregroundStyle(Brand.label)
                }
                Group {
                    if r.kind == FieldKind.password {
                        PasswordField(value: row.value)
                    } else if r.kind == FieldKind.customSecret {
                        SecureField("value", text: row.value)
                    } else if r.kind == FieldKind.street {
                        TextField("Street and number", text: row.value, axis: .vertical).lineLimit(1...4)
                    } else {
                        TextField(placeholder(r.kind), text: row.value)
                    }
                }
                .textFieldStyle(.plain)
                .font(.system(size: 14))
            }
            if custom || r.kind == FieldKind.totp {
                IconButton(systemName: "minus.circle", help: "Remove field") {
                    rows.removeAll { $0.id == r.id }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }

    var websites: some View {
        VStack(spacing: 0) {
            ForEach(sites.indices, id: \.self) { i in
                if i > 0 { Divider() }
                HStack(spacing: 6) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("website").font(.system(size: 12)).foregroundStyle(Brand.label)
                        TextField("example.com", text: $sites[i]).textFieldStyle(.plain).font(.system(size: 14))
                    }
                    if sites.count > 1 || !sites[i].isEmpty {
                        IconButton(systemName: "minus.circle", help: "Remove website") {
                            sites.remove(at: i)
                            if sites.isEmpty { sites = [""] }
                        }
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
            }
            Divider()
            AddRow(title: "add another website") { sites.append("") }
        }
        .card()
    }

    var addMore: some View {
        Menu {
            if kind == EntryKind.login && !rows.contains(where: { $0.kind == FieldKind.totp }) {
                Button("One-time code") { insert(Row(kind: FieldKind.totp, value: "")) }
            }
            Button("Text field") { insert(Row(kind: FieldKind.customText, label: "text", value: "")) }
            Button("Hidden field") { insert(Row(kind: FieldKind.customSecret, label: "hidden", value: "")) }
        } label: {
            AddRow(title: "add more", action: nil).frame(maxWidth: .infinity)
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .frame(maxWidth: .infinity)
        .card()
    }

    /// New fields go before the notes.
    func insert(_ r: Row) {
        if let n = rows.firstIndex(where: { $0.kind == FieldKind.note }) { rows.insert(r, at: n) } else { rows.append(r) }
    }

    func placeholder(_ kind: Int) -> String {
        switch kind {
        case FieldKind.username: return "Username or email"
        case FieldKind.totp: return "otpauth:// link or secret (optional)"
        case FieldKind.cardExpiry: return "YYYY-MM"
        case FieldKind.email: return "name@example.com"
        case FieldKind.country: return "e.g. FR or France"
        default: return FieldKind.name(kind)
        }
    }

    func template() -> [Row] {
        switch kind {
        case EntryKind.card:
            return [FieldKind.cardHolder, FieldKind.cardNumber, FieldKind.cardExpiry, FieldKind.cardCVV, FieldKind.note]
                .map { Row(kind: $0, value: "") }
        case EntryKind.note:
            return [Row(kind: FieldKind.note, value: "")]
        case EntryKind.identity:
            return [FieldKind.firstName, FieldKind.lastName, FieldKind.email, FieldKind.phone, FieldKind.street,
                    FieldKind.city, FieldKind.postcode, FieldKind.region, FieldKind.country, FieldKind.note]
                .map { Row(kind: $0, value: "") }
        default:
            return [FieldKind.username, FieldKind.password, FieldKind.note].map { Row(kind: $0, value: "") }
        }
    }

    func load() async {
        guard !loaded else { return }
        loaded = true
        guard let e = entry else {
            rows = template()
            if kind == EntryKind.login, let i = rows.firstIndex(where: { $0.kind == FieldKind.password }) {
                rows[i].value = (try? Vault.password(length: 20, flags: PasswordClass.lower | PasswordClass.upper
                                                    | PasswordClass.digits | PasswordClass.symbols)) ?? ""
            }
            if kind == EntryKind.login, let req = model.fill {
                name = req.siteName
                sites = [req.host]
                if let p = req.password, let i = rows.firstIndex(where: { $0.kind == FieldKind.password }) {
                    rows[i].value = p
                }
                if let u = req.username, let i = rows.firstIndex(where: { $0.kind == FieldKind.username }) {
                    rows[i].value = u
                }
            }
            if sites.isEmpty { sites = [""] }
            return
        }
        name = e.name
        sites = e.hosts.isEmpty ? [""] : e.hosts
        var loadedRows: [Row] = []
        for (i, f) in e.fields.enumerated() {
            let v = f.secret ? (await model.reveal(e, field: i) ?? "") : (f.value ?? "")
            loadedRows.append(Row(kind: f.kind, label: f.label, value: v))
        }
        // Offer the template's missing fields too (e.g. add TOTP later).
        for t in template() where !loadedRows.contains(where: { $0.kind == t.kind }) { loadedRows.append(t) }
        rows = loadedRows
    }

    func save() {
        var hostList: [String] = []
        for h in sites.map(normaliseHost) where !h.isEmpty && !hostList.contains(h) { hostList.append(h) }
        let fields = rows.filter { !$0.value.isEmpty }.map {
            EntryDraft.Field(kind: $0.kind, label: $0.label, value: $0.value)
        }
        let draft = EntryDraft(id: entry?.id, kind: kind, name: finalName,
                               hosts: hostList, fields: fields)
        Task { _ = await model.save(draft) }
    }
}

/// "26 Nov 2026 at 17:52" in the user's locale.
func itemDate(_ t: UInt32) -> String {
    Date(timeIntervalSince1970: TimeInterval(t)).formatted(date: .abbreviated, time: .shortened)
}

/// "https://Github.com/login" -> "github.com".
func normaliseHost(_ s: String) -> String {
    var h = s.trimmingCharacters(in: .whitespaces).lowercased()
    if let u = URL(string: h), let host = u.host { h = host }
    return h.trimmingCharacters(in: CharacterSet(charactersIn: "./"))
}

/// The password row inside an item card: reveal, regenerate, generator options.
struct PasswordField: View {
    @Binding var value: String
    @Local private var show = false
    @Local private var options = false
    @AppStorage("gen.length") private var length = 20.0
    @AppStorage("gen.symbols") private var symbols = true
    @AppStorage("gen.words") private var useWords = false

    var body: some View {
        HStack(spacing: 2) {
            Group {
                if show {
                    TextField("Password", text: $value).font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Password", text: $value)
                }
            }
            .textFieldStyle(.plain)
            IconButton(systemName: show ? "eye.slash" : "eye", help: show ? "Hide" : "Show", size: 20) { show.toggle() }
            IconButton(systemName: "arrow.clockwise", help: "Generate a new password", size: 20) { generate() }
            IconButton(systemName: "slider.horizontal.3", help: "Generator options", size: 20) { options.toggle() }
                .popover(isPresented: $options) {
                    VStack(alignment: .leading, spacing: 10) {
                        Picker("", selection: $useWords) {
                            Text("Random").tag(false)
                            Text("Words").tag(true)
                        }
                        .pickerStyle(.segmented)
                        if useWords {
                            Stepper("\(Int(length / 4)) words", value: $length, in: 12...40, step: 4)
                        } else {
                            Slider(value: $length, in: 8...64, step: 1) { Text("\(Int(length)) characters") }
                            Toggle("Symbols", isOn: $symbols)
                        }
                        Button("Generate") { generate() }
                    }
                    .padding()
                    .frame(width: 260)
                    .onChange(of: useWords) { _, _ in generate() }
                }
        }
    }

    func generate() {
        show = true
        if useWords {
            value = (try? Vault.passphrase(words: max(3, Int(length / 4)))) ?? value
        } else {
            var flags = PasswordClass.lower | PasswordClass.upper | PasswordClass.digits
            if symbols { flags |= PasswordClass.symbols }
            value = (try? Vault.password(length: Int(length), flags: flags)) ?? value
        }
    }
}
