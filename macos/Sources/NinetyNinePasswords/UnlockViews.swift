import SwiftUI
import VaultKit

// MARK: - No card / setup / unlock

struct NoCardView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 10) {
            Spacer()
            LogoView(size: 64).padding(.bottom, 6)
            Text("Insert your YubiKey").font(.system(size: 18, weight: .semibold))
            Text("Your vault lives only on the key.\nPlug it in to unlock your passwords.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Waiting for a key…").font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 8)
            Spacer()
        }
        .padding()
    }
}

/// First run on a new YubiKey: what the app is, then create the vault.
struct SetupFlow: View {
    let card: CardInfo
    @Local private var started = false

    var body: some View {
        if started {
            SetupView(card: card)
        } else {
            IntroView { started = true }
        }
    }
}

/// Explains the app in three points before setup.
struct IntroView: View {
    let next: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    VStack(alignment: .leading, spacing: 8) {
                        LogoView(size: 48)
                        Text("Welcome to 99passwords").font(.system(size: 20, weight: .semibold))
                        Tagline()
                    }
                    point("lock.shield", "Your vault lives on your YubiKey",
                          "Passwords are encrypted and stored on the key. No cloud, and nothing readable on this Mac.")
                    point("hand.tap", "Master password plus a touch",
                          "Unlocking takes your master password and a tap on the key. One without the other gets nothing.")
                    point("cable.connector", "Unplug to lock",
                          "Pull the key out and the vault locks straight away.")
                    point("checkmark.seal", "Still your YubiKey",
                          "Passkeys, one-time codes and everything else on the key keep working as before. 99passwords only uses its smart-card (PIV) area.")
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 20)
            }
            Divider()
            Button("Set up this YubiKey", action: next)
                .buttonStyle(PillButtonStyle(fullWidth: true))
                .keyboardShortcut(.defaultAction)
                .padding(16)
        }
    }

    func point(_ icon: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundStyle(Brand.label)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(text).font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// A rough strength estimate for a master passphrase. It only informs: the
/// passphrase is the user's choice.
struct PassphraseStrength {
    enum Level: Int { case weak = 1, fair, strong }
    let level: Level
    let bits: Int

    static let common: Set<String> = ["password", "passw0rd", "123456", "12345678", "123456789", "qwerty",
                                      "azerty", "letmein", "iloveyou", "admin", "welcome", "monkey", "dragon",
                                      "abc123", "111111", "000000", "password1", "yubikey"]

    init(_ p: String) {
        let words = p.split(whereSeparator: { " -_.,".contains($0) }).filter { $0.count >= 3 }
        var pool = 0
        if p.rangeOfCharacter(from: .lowercaseLetters) != nil { pool += 26 }
        if p.rangeOfCharacter(from: .uppercaseLetters) != nil { pool += 26 }
        if p.rangeOfCharacter(from: .decimalDigits) != nil { pool += 10 }
        if p.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil { pool += 32 }
        // Characters are rarely random, so count them at half their worth;
        // a run of words counts about 11 bits each (a big dictionary).
        let charBits = pool == 0 ? 0 : Double(p.count) * log2(Double(pool)) * 0.5
        let wordBits = words.count >= 3 ? Double(words.count) * 11 : 0
        var b = Int(max(charBits, wordBits))
        if Self.common.contains(p.lowercased()) || Set(p).count <= 2 { b = min(b, 10) }
        bits = b
        level = b >= 64 ? .strong : b >= 40 ? .fair : .weak
    }

    var label: String {
        switch level {
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .strong: return "Strong"
        }
    }

    var color: Color {
        switch level {
        case .weak: return .red
        case .fair: return .orange
        case .strong: return .green
        }
    }
}

/// Three bars and a word: weak, fair or strong. Never blocks.
struct StrengthMeter: View {
    let strength: PassphraseStrength

    var body: some View {
        // Starts where the text inside the field starts.
        HStack(spacing: 6) {
            HStack(spacing: 3) {
                ForEach(1...3, id: \.self) { i in
                    Capsule()
                        .fill(i <= strength.level.rawValue ? strength.color : Color.primary.opacity(0.1))
                        .frame(height: 4)
                }
            }
            .frame(width: 96)
            Text(strength.label).font(.system(size: 12, weight: .medium)).foregroundStyle(strength.color)
        }
        .padding(.leading, 12)
        .animation(.easeInOut(duration: 0.15), value: strength.level)
    }
}

/// Create a vault. The passphrase is the user's choice; we only check that
/// the two entries match.
struct SetupView: View {
    @EnvironmentObject var model: AppModel
    let card: CardInfo
    @Local private var pass = ""
    @Local private var confirm = ""
    @Local private var label = "My YubiKey"

    var ready: Bool { !pass.isEmpty && pass == confirm && !model.busy }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 12) {
                        LogoView(size: 44)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Create your vault").font(.system(size: 17, weight: .semibold))
                            Text("On YubiKey \(String(card.serial))").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Text("There is no way to recover the master password. After 255 wrong tries the YubiKey blocks itself for good and the vault on it is gone. You can clone it to a backup key later.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    labelledField("name") { TextField("My YubiKey", text: $label).fieldBackground() }
                    labelledField("master password") {
                        VStack(alignment: .leading, spacing: 8) {
                            SecureField("Master password", text: $pass).fieldBackground()
                            if !pass.isEmpty { StrengthMeter(strength: PassphraseStrength(pass)) }
                        }
                    }
                    labelledField("repeat master password") { SecureField("Type it again", text: $confirm).fieldBackground() }
                    if !confirm.isEmpty && pass != confirm {
                        Text("The two master passwords don't match.").font(.system(size: 12)).foregroundStyle(.red)
                    }
                }
                .padding(24)
            }
            Divider()
            Button { model.provision(card, passphrase: pass, label: label) } label: {
                HStack(spacing: 8) {
                    if model.busy { ProgressView().controlSize(.small).tint(Brand.navy) }
                    Text("Create vault")
                }
            }
            .buttonStyle(PillButtonStyle(fullWidth: true))
            .keyboardShortcut(.defaultAction)
            .disabled(!ready)
            .padding(16)
        }
    }
}

/// The catchphrase, in small grey italics.
struct Tagline: View {
    var body: some View {
        Text("I got 99passwords, but a breach ain't one.")
            .font(.system(size: 12).italic())
            .foregroundStyle(.secondary)
    }
}

/// Modelled on 1Password's lock screen, upright: a grey band with the logo
/// on its edge, and a single password field with reveal and submit inside it.
/// While the YubiKey waits for a touch, the field turns into a gold prompt.
struct UnlockView: View {
    @EnvironmentObject var model: AppModel
    @Local private var pass = ""
    @Local private var reveal = false
    @FocusState private var focused: Bool
    static let band: CGFloat = 110

    var body: some View {
        VStack(spacing: 0) {
            // Grey band with the logo sitting on its bottom edge: 1Password's
            // lock screen, turned upright for the tall panel.
            Color(nsColor: .windowBackgroundColor)
                .frame(height: Self.band)
                .overlay(alignment: .bottom) { Rectangle().fill(Color(nsColor: .separatorColor)).frame(height: 0.5) }
                .overlay(alignment: .bottom) {
                    LogoView(size: 76)
                        .shadow(color: .black.opacity(0.08), radius: 3, y: 1)
                        .offset(y: 38)
                }
            VStack(spacing: 10) {
                Tagline().padding(.bottom, 14)
                if model.touchPrompt {
                    TouchPromptView()
                } else if model.pinTriesLeft == 0 {
                    blocked
                } else {
                    field
                    // Only after 10 wrong passphrases, so a typo or two stays quiet.
                    if let n = model.pinTriesLeft, n <= AppModel.showTriesBelow {
                        Text("\(n) wrong \(n == 1 ? "master password" : "master passwords") left before this YubiKey blocks")
                            .font(.system(size: 11)).foregroundStyle(n <= 10 ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                    }
                }
            }
            .padding(.horizontal, 32)
            .padding(.top, 62)
            Spacer()
        }
        .animation(.easeInOut(duration: 0.2), value: model.touchPrompt)
        .onAppear { focused = true }
    }

    var field: some View {
        HStack(spacing: 0) {
            Group {
                if reveal {
                    TextField("Enter your master password", text: $pass)
                } else {
                    SecureField("Enter your master password", text: $pass)
                }
            }
            .textFieldStyle(.plain)
            .font(.system(size: 14))
            .focused($focused)
            .onSubmit(submit)
            .padding(.leading, 12)
            if model.busy {
                ProgressView().controlSize(.small).padding(.horizontal, 10)
            } else {
                Button { reveal.toggle() } label: {
                    Image(systemName: reveal ? "eye.slash" : "eye").foregroundStyle(Brand.label)
                }
                .buttonStyle(.plain)
                .frame(width: 30)
                Rectangle().fill(Color(nsColor: .separatorColor)).frame(width: 0.5, height: 20)
                Button(action: submit) {
                    Image(systemName: "arrow.right").font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(pass.isEmpty ? AnyShapeStyle(.tertiary) : AnyShapeStyle(Brand.label))
                }
                .buttonStyle(.plain)
                .frame(width: 34)
                .disabled(pass.isEmpty)
            }
        }
        .frame(height: 36)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color(nsColor: .textBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(focused ? Brand.label.opacity(0.45) : Color(nsColor: .separatorColor), lineWidth: focused ? 2.5 : 0.5))
    }

    /// After 255 wrong passphrases the PIN is blocked and there is no PUK.
    var blocked: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("This YubiKey is blocked", systemImage: "lock.slash")
                .font(.system(size: 13, weight: .semibold)).foregroundStyle(.red)
            Text("The master password was wrong 255 times, so the key locked itself for good and the vault on it can't be opened. Use a backup key, or reset this one and set it up again.")
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    func submit() {
        guard !pass.isEmpty else { return }
        model.unlock(pass)
        pass = ""
    }
}
