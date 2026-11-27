import SwiftUI
import UniformTypeIdentifiers
import VaultKit

// MARK: - Settings, export and import

/// What the user wants to do, each with its own page.
enum TransferIntent: Hashable {
    case saveFile, restoreFile, importOther, exportOther

    var title: String {
        switch self {
        case .saveFile: return "Save a backup file"
        case .restoreFile: return "Restore a backup file"
        case .importOther: return "Import from another app"
        case .exportOther: return "Export to another app"
        }
    }
}

/// Settings: security, backups and moving passwords (organised by intent:
/// protect the vault, bring passwords in, take them out), and About.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @Local private var intent: TransferIntent?
    @AppStorage(AppModel.autoLockKey) private var autoLock = 5
    // Encrypted .ykv
    @Local private var withRecovery = false
    @Local private var recoveryKey: String?
    @Local private var importURL: URL?
    @Local private var importPass = ""
    @Local private var useRecovery = false
    @Local private var importRK = ""
    // Plaintext
    @Local private var format: PlainFormat = .csv
    @Local private var confirmExport = false
    @Local private var plainResult: ImportResult?

    var body: some View {
        VStack(spacing: 0) {
            if let i = intent {
                ScreenHeader(title: i.title, back: nil) { intent = nil; resetImport(); plainResult = nil }
            } else {
                ScreenHeader(title: "Settings")
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    switch intent {
                    case nil: hub
                    case .saveFile: saveFile
                    case .restoreFile: restoreFile
                    case .importOther: importOther
                    case .exportOther: exportOther
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 14)
                .padding(.bottom, 20)
            }
        }
    }

    // MARK: hub

    @ViewBuilder var hub: some View {
        group("Security") {
            HStack(spacing: 12) {
                Image(systemName: "lock.badge.clock").font(.system(size: 15)).foregroundStyle(Brand.label).frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Auto-lock").font(.system(size: 13, weight: .medium))
                    Text("Locks the vault when you haven't used it for a while.")
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
                Picker("", selection: $autoLock) {
                    Text("1 min").tag(1)
                    Text("5 min").tag(5)
                    Text("15 min").tag(15)
                    Text("30 min").tag(30)
                    Text("1 hour").tag(60)
                    Text("Never").tag(0)
                }
                .labelsHidden()
                .fixedSize()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
        }
        if ExtensionSetupView.enabled {
            group("Browser") {
                IntentRow(icon: "puzzlepiece.extension", title: "Add the Chrome extension",
                          detail: "Logins offered and filled right in the page.") { model.route = .extensionSetup }
            }
        }
        group("Protect your vault") {
            IntentRow(icon: "key.horizontal", title: "Clone my YubiKey",
                      detail: "Copy the vault to a second YubiKey and keep it somewhere safe.") { model.route = .backup }
            Divider()
            IntentRow(icon: "lock.doc", title: "Save a backup file",
                      detail: "An encrypted file only your YubiKeys and master password can open.") { intent = .saveFile }
        }
        group("Bring passwords in") {
            IntentRow(icon: "clock.arrow.circlepath", title: "Restore a backup file",
                      detail: "Merge a .ykv backup into this vault.") { intent = .restoreFile }
            Divider()
            IntentRow(icon: "square.and.arrow.down", title: "Import from another app",
                      detail: "From 1Password, Bitwarden or Chrome (CSV), or a 99passwords JSON file.") { intent = .importOther }
        }
        group("Take passwords out") {
            IntentRow(icon: "square.and.arrow.up", title: "Export to another app",
                      detail: "An unencrypted CSV or JSON file, for moving to another password manager.") { intent = .exportOther }
        }
        about
    }

    var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let v = info["CFBundleShortVersionString"] as? String ?? "0.1.0"
        let b = info["CFBundleVersion"] as? String ?? "1"
        return "Version \(v) (\(b))"
    }

    var about: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle("About")
            HStack(alignment: .top, spacing: 14) {
                LogoView(size: 48)
                VStack(alignment: .leading, spacing: 4) {
                    Text("99passwords").font(.system(size: 15, weight: .semibold))
                    Text(version).font(.system(size: 12)).foregroundStyle(.secondary)
                    Text("A password manager whose vault lives on your YubiKey. Unlock with your master password and a touch.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 2)
                    Tagline().padding(.top, 2)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .card()
        }
    }

    func group<C: View>(_ title: String, @ViewBuilder _ rows: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle(title)
            VStack(spacing: 0) { rows() }.card()
        }
    }

    // MARK: pages

    @ViewBuilder var saveFile: some View {
        Text("A .ykv file that only your YubiKeys and master password can open. It is fine to keep in cloud storage.")
            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        if let rk = recoveryKey {
            recoveryCard(rk)
        } else {
            Toggle(isOn: $withRecovery) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Also make a recovery key").font(.system(size: 13))
                    Text("Opens the file with your master password if every YubiKey is lost.")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)
            Button { Task { recoveryKey = await model.exportYkv(withRecoveryKey: withRecovery) } } label: {
                HStack(spacing: 8) {
                    if model.busy { ProgressView().controlSize(.small).tint(Brand.navy) }
                    Label("Save backup file…", systemImage: "square.and.arrow.down.on.square")
                }
            }
            .buttonStyle(PillButtonStyle(fullWidth: true))
            .disabled(model.busy)
        }
    }

    @ViewBuilder var restoreFile: some View {
        Text("Items in the backup are merged into this vault. Where an item was edited in both, the newer edit wins.")
            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        if let url = importURL {
            importForm(url)
        } else {
            Button { Task { if let u = await Files.open(types: [Files.ykv]) { importURL = u } } } label: {
                Label("Choose backup file…", systemImage: "doc")
            }
            .buttonStyle(PillButtonStyle(fullWidth: true))
            .disabled(model.busy)
        }
    }

    @ViewBuilder var importOther: some View {
        Text("Export a CSV from 1Password, Bitwarden or Chrome (or a JSON file from 99passwords), then choose it here.")
            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        Button {
            Task {
                plainResult = nil
                if let u = await Files.open(types: [.commaSeparatedText, .json, .plainText]) {
                    plainResult = await model.importPlain(u)
                }
            }
        } label: { Label("Choose file…", systemImage: "doc") }
            .buttonStyle(PillButtonStyle(fullWidth: true))
            .disabled(model.busy)
        if let r = plainResult { importSummary(r) }
    }

    @ViewBuilder var exportOther: some View {
        plaintextWarning
        Picker("", selection: $format) {
            Text("CSV · logins").tag(PlainFormat.csv)
            Text("JSON · everything").tag(PlainFormat.json)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        Text(format == .csv ? "Opens in Chrome, 1Password and Bitwarden. Cards and notes are left out."
                            : "Every item and field, in 99passwords' own format.")
            .font(.system(size: 11)).foregroundStyle(.secondary)
        if confirmExport {
            HStack {
                Text("Export every password unencrypted?").font(.system(size: 12)).lineLimit(2)
                Spacer()
                Button("Cancel") { confirmExport = false }.buttonStyle(PillButtonStyle(prominent: false))
                Button("Export") {
                    confirmExport = false
                    Task { await model.exportPlain(format) }
                }
                .buttonStyle(PillButtonStyle(destructive: true))
            }
        } else {
            Button { confirmExport = true } label: { Label("Export unencrypted file…", systemImage: "square.and.arrow.up") }
                .buttonStyle(PillButtonStyle(fullWidth: true))
                .disabled(model.busy)
        }
    }

    func recoveryCard(_ rk: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Your recovery key").font(.system(size: 13, weight: .semibold))
            Text(rk)
                .font(.system(size: 14, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Text("Write it down or print it now: it is shown only this once. Keep it apart from your YubiKeys.")
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button { model.copyText(rk, what: "Recovery key") } label: { Label("Copy", systemImage: "doc.on.doc") }
                    .buttonStyle(PillButtonStyle(prominent: false))
                Spacer()
                Button("I wrote it down") { recoveryKey = nil }
                    .buttonStyle(PillButtonStyle())
            }
        }
        .padding(14)
        .card()
    }

    func importForm(_ url: URL) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(url.lastPathComponent, systemImage: "doc").font(.system(size: 13)).lineLimit(1).truncationMode(.middle)
            labelledField("master password") {
                SecureField("The master password when it was exported", text: $importPass).fieldBackground()
            }
            Toggle("Open with a recovery key instead of this YubiKey", isOn: $useRecovery)
                .toggleStyle(.checkbox).font(.system(size: 12))
            if useRecovery {
                labelledField("recovery key") {
                    TextField("XXXX-XXXX-…", text: $importRK).font(.system(size: 14, design: .monospaced)).fieldBackground()
                }
            }
            if model.touchPrompt { TouchPromptView() }
            Text("Items in the file are merged into this vault; newer edits win.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                Button("Cancel") { resetImport() }.buttonStyle(PillButtonStyle(prominent: false))
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button("Import") {
                    Task {
                        let rk = useRecovery ? importRK : nil
                        if await model.importYkv(url, passphrase: importPass, recoveryKey: rk) { resetImport() }
                        importPass = ""
                    }
                }
                .buttonStyle(PillButtonStyle())
                .keyboardShortcut(.defaultAction)
                .disabled(model.busy || importPass.isEmpty || (useRecovery && importRK.isEmpty))
            }
        }
        .padding(14)
        .card()
    }

    func resetImport() {
        importURL = nil
        importPass = ""
        importRK = ""
        useRecovery = false
    }

    var plaintextWarning: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 3) {
                Text("Not encrypted").font(.system(size: 13, weight: .semibold))
                Text("Anyone who gets this file can read every password in it. Import it into the other app, then delete it and empty the Bin.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.red.opacity(0.06)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.red.opacity(0.3), lineWidth: 0.5))
    }

    func importSummary(_ r: ImportResult) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(summary(r), systemImage: "checkmark.circle.fill")
                .font(.system(size: 12, weight: .medium)).foregroundStyle(.green)
            if let first = r.skipped.first {
                Text("Line \(first.line): \(first.reason)").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Text("Now delete the plaintext file you imported.").font(.system(size: 11)).foregroundStyle(.secondary)
        }
    }

    func summary(_ r: ImportResult) -> String {
        let items = r.imported == 1 ? "1 item" : "\(r.imported) items"
        return r.skipped.isEmpty ? "Imported \(items)" : "Imported \(items), skipped \(r.skipped.count)"
    }
}
