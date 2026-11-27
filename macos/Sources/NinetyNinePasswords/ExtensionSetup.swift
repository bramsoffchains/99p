import AppKit
import SwiftUI

/// After setup (and from Settings): how to add the Chrome extension. It is
/// not in the Chrome Web Store yet, so this walks through "Load unpacked"
/// with the copy bundled inside the app. Skippable.
struct ExtensionSetupView: View {
    @EnvironmentObject var model: AppModel

    /// Hidden for now: no step after setup, no Settings
    /// row. Flip to bring it back.
    static let enabled = false

    /// The extension folder shipped in the app bundle (see build-app.sh).
    static var folder: URL? {
        let u = Bundle.main.resourceURL?.appendingPathComponent("extension")
        return u.flatMap { FileManager.default.fileExists(atPath: $0.path) ? $0 : nil }
    }

    static var chrome: URL? { NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.google.Chrome") }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 12) {
                        Image(systemName: "puzzlepiece.extension")
                            .font(.system(size: 22))
                            .foregroundStyle(Brand.label)
                            .frame(width: 48, height: 48)
                            .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(Color.primary.opacity(0.06)))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Add the Chrome extension").font(.system(size: 17, weight: .semibold))
                            Text("Your vault is ready.").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                    }
                    Text("The extension offers your logins right in the page, fills them and saves new ones. It takes a minute to add.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    VStack(spacing: 0) {
                        step(1, "Open Chrome's Extensions page") {
                            Button { openExtensionsPage() } label: { Label("Open", systemImage: "arrow.up.forward.app") }
                                .buttonStyle(PillButtonStyle(prominent: false))
                                .disabled(Self.chrome == nil)
                        }
                        Divider()
                        step(2, "Turn on Developer mode, top right") { EmptyView() }
                        Divider()
                        step(3, "Click Load unpacked and pick the extension folder") {
                            Button { showFolder() } label: { Label("Show folder", systemImage: "folder") }
                                .buttonStyle(PillButtonStyle(prominent: false))
                                .disabled(Self.folder == nil)
                            if let f = Self.folder {
                                Button { model.copyPlain(f.path, what: "Folder path") } label: {
                                    Label("Copy path", systemImage: "doc.on.doc")
                                }
                                .buttonStyle(PillButtonStyle(prominent: false))
                                .help("In Chrome's file picker, press ⌘⇧G and paste it")
                            }
                        }
                    }
                    .card()
                    if Self.chrome == nil {
                        Label("Google Chrome isn't installed on this Mac.", systemImage: "info.circle")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Text("Tip: in Chrome's file picker, press ⌘⇧G and paste the copied path.")
                        .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                .padding(24)
            }
            Divider()
            HStack(spacing: 8) {
                Button("Skip for now") { model.route = .list }
                    .buttonStyle(PillButtonStyle(prominent: false))
                Button("Done") { model.route = .list }
                    .buttonStyle(PillButtonStyle(fullWidth: true))
                    .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
    }

    func step<A: View>(_ n: Int, _ text: String, @ViewBuilder _ action: () -> A) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(n)")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Brand.navy)
                .frame(width: 22, height: 22)
                .background(Circle().fill(Brand.gold))
            VStack(alignment: .leading, spacing: 8) {
                Text(text).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
                HStack(spacing: 6) { action() }
                    .padding(.leading, -10)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    func openExtensionsPage() {
        guard let chrome = Self.chrome, let url = URL(string: "chrome://extensions") else { return }
        NSWorkspace.shared.open([url], withApplicationAt: chrome, configuration: NSWorkspace.OpenConfiguration())
    }

    func showFolder() {
        guard let f = Self.folder else { return }
        NSWorkspace.shared.activateFileViewerSelecting([f])
    }
}
