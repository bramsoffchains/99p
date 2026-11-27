import SwiftUI
import VaultKit

// MARK: - Backup keys

/// Lists the YubiKeys that hold this vault, makes a new backup from an empty
/// key, and syncs a plugged-in backup that is behind.
struct BackupKeysView: View {
    @EnvironmentObject var model: AppModel
    @Local private var others: [CardInfo] = []
    @Local private var label = "Backup YubiKey"

    var known: KnownKeys? { model.knownKeys }

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "Clone my YubiKey", back: .settings)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("A clone is a second YubiKey with the same vault, opened with the same master password. Keep it somewhere safe and plug it in now and then to bring it up to date.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    if model.touchPrompt {
                        TouchPromptView(title: "Touch the backup YubiKey", detail: "Tap the gold contact on the key you plugged in.")
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        SectionTitle("Keys with this vault")
                        if let k = known {
                            VStack(spacing: 0) {
                                ForEach(Array(k.keys.enumerated()), id: \.element.id) { i, key in
                                    if i > 0 { Divider() }
                                    row(key, behind: k.isBehind(key))
                                }
                            }
                            .card()
                        } else {
                            ProgressView().controlSize(.small)
                        }
                    }
                    pluggedIn
                }
                .padding(.horizontal, 20)
                .padding(.top, 14)
                .padding(.bottom, 20)
            }
        }
        .task {
            await model.loadKnownKeys()
            while !Task.isCancelled {
                if !model.busy { others = await model.otherCards() }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    func row(_ key: KnownKey, behind: Bool) -> some View {
        let plugged = others.first { $0.serial == key.serial }
        return HStack(spacing: 12) {
            KeyGlyph()
            VStack(alignment: .leading, spacing: 2) {
                Text(key.label).font(.system(size: 14)).lineLimit(1)
                Group {
                    if key.this {
                        Text("This key · \(String(key.serial))")
                    } else if behind {
                        Label(plugged == nil ? "Behind · plug it in to sync" : "Behind · ready to sync",
                              systemImage: "exclamationmark.circle.fill").foregroundStyle(.orange)
                    } else {
                        Label("Up to date · \(String(key.serial))", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }
            Spacer(minLength: 4)
            if let card = plugged, !key.this {
                Button("Sync") { Task { await model.sync(card) } }
                    .buttonStyle(PillButtonStyle(prominent: behind))
                    .disabled(model.busy)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    @ViewBuilder var pluggedIn: some View {
        let empty = others.filter { !$0.has_vault }
        let foreign = others.filter { $0.has_vault && !(known?.contains(serial: $0.serial) ?? true) }
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle("Clone to a new key")
            if let card = empty.first {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 12) {
                        KeyGlyph()
                        VStack(alignment: .leading, spacing: 2) {
                            Text("New YubiKey").font(.system(size: 14))
                            Text("Serial \(String(card.serial)) · no vault yet").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                    }
                    labelledField("name") { TextField("Backup YubiKey", text: $label).fieldBackground() }
                    Text("This gives the key its own vault slot and a new PIV management key. No touch needed.")
                        .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Spacer()
                        if model.busy { ProgressView().controlSize(.small) }
                        Button("Clone to this key") {
                            Task { _ = await model.cloneTo(card, label: label.trimmingCharacters(in: .whitespaces)) }
                        }
                        .buttonStyle(PillButtonStyle())
                        .disabled(model.busy || label.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
                .padding(14)
                .card()
            } else {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Plug in a second YubiKey to clone your vault onto it, or to sync a clone.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 4)
            }
            ForEach(foreign) { c in
                Label("YubiKey \(String(c.serial)) holds a different vault.", systemImage: "info.circle")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
        }
    }
}
