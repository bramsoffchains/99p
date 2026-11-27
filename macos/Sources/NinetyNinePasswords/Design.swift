import AppKit
import SwiftUI
import VaultKit

// MARK: - Brand

enum Brand {
    /// Deep navy: the main brand colour (logo, labels).
    static let navy = Color(red: 0.05, green: 0.11, blue: 0.29)
    /// YubiKey gold, kept for a few important moments (touch prompt,
    /// primary action).
    static let gold = Color(red: 0.98, green: 0.74, blue: 0.0)
    /// Field labels: navy-blue in light mode, a light blue in dark mode.
    static let label = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(red: 0.55, green: 0.66, blue: 1.0, alpha: 1)
            : NSColor(red: 0.16, green: 0.27, blue: 0.62, alpha: 1)
    })
}

// MARK: - Logo

/// The 99passwords badge, after 1Password's lock-screen badge: a pale outer
/// ring, a thick gold ring, a white centre, and our own centre mark.
struct LogoView: View {
    var size: CGFloat = 64

    var body: some View {
        ZStack {
            Circle().fill(Color(white: 0.93))
                .overlay(Circle().strokeBorder(Color.black.opacity(0.12), lineWidth: max(0.5, size * 0.008)))
            Circle().fill(Brand.gold).padding(size * 0.07)
                .overlay(Circle().strokeBorder(Color.black.opacity(0.08), lineWidth: max(0.5, size * 0.006)).padding(size * 0.07))
            Circle().fill(.white).padding(size * 0.21)
            YubiKeyMark(contact: Brand.gold)
                .frame(width: size * 0.19, height: size * 0.41)
                .rotationEffect(.degrees(-35))
        }
        .frame(width: size, height: size)
    }
}

/// A generic navy YubiKey: rounded body with a key-ring hole and a touch
/// contact, and a USB plug at the bottom.
struct YubiKeyMark: View {
    var contact: Color

    var body: some View {
        GeometryReader { g in
            let w = g.size.width, h = g.size.height
            ZStack(alignment: .top) {
                // Plug.
                RoundedRectangle(cornerRadius: w * 0.06)
                    .fill(Brand.navy.opacity(0.75))
                    .frame(width: w * 0.56, height: h * 0.26)
                    .offset(y: h * 0.74)
                // Body with the ring hole cut out.
                ZStack(alignment: .top) {
                    RoundedRectangle(cornerRadius: w * 0.3, style: .continuous).fill(Brand.navy)
                        .frame(width: w, height: h * 0.78)
                    Circle().frame(width: w * 0.3, height: w * 0.3)
                        .offset(y: h * 0.07)
                        .blendMode(.destinationOut)
                }
                .compositingGroup()
                // Touch contact.
                Circle().fill(contact)
                    .frame(width: w * 0.52, height: w * 0.52)
                    .offset(y: h * 0.36)
            }
            .frame(width: w, height: h, alignment: .top)
        }
    }
}

/// App icon artwork: the disc alone on a transparent canvas.
struct AppIconArt: View {
    var body: some View {
        LogoView(size: 860)
            .compositingGroup()
            .shadow(color: .black.opacity(0.2), radius: 14, y: 8)
            .frame(width: 1024, height: 1024)
    }
}

enum StatusIcon {
    /// Menu bar template: a solid disc with a YubiKey cut out of it (the
    /// key-ring hole and touch contact stay solid, so it reads as a key).
    static func image() -> NSImage {
        let img = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            ctx.setFillColor(NSColor.black.cgColor)
            ctx.fillEllipse(in: rect.insetBy(dx: 0.75, dy: 0.75))
            ctx.translateBy(x: rect.midX, y: rect.midY)
            ctx.rotate(by: 35 * .pi / 180)
            // Drawn upright around the centre, y up: body above, plug below.
            let w: CGFloat = 5.2, h: CGFloat = 11.5
            let body = CGRect(x: -w / 2, y: -h / 2 + h * 0.22, width: w, height: h * 0.78)
            let plug = CGRect(x: -1.5, y: -h / 2, width: 3.0, height: h * 0.26)
            // Cut the key out of the disc.
            ctx.setBlendMode(.clear)
            ctx.addPath(CGPath(roundedRect: body, cornerWidth: 1.6, cornerHeight: 1.6, transform: nil))
            ctx.addRect(plug)
            ctx.fillPath()
            // Put back the ring hole's rim and the touch contact as solid.
            ctx.setBlendMode(.normal)
            ctx.fillEllipse(in: CGRect(x: -0.8, y: h / 2 - 2.6, width: 1.6, height: 1.6))
            ctx.fillEllipse(in: CGRect(x: -1.45, y: body.minY + body.height * 0.22, width: 2.9, height: 2.9))
            return true
        }
        img.isTemplate = true
        img.accessibilityDescription = "99passwords"
        return img
    }
}

// MARK: - Item icons

/// Muted monogram colours, like 1Password's item icons.
private let tilePalette: [Color] = [.blue, .indigo, .teal, .green, .orange, .pink, .purple, .brown]

func tileColor(_ s: String) -> Color {
    let h = s.lowercased().unicodeScalars.reduce(UInt32(5381)) { ($0 &* 33) &+ $1.value }
    return tilePalette[Int(h % UInt32(tilePalette.count))]
}

func kindIcon(_ kind: Int) -> String {
    switch kind {
    case EntryKind.card: return "creditcard"
    case EntryKind.note: return "note.text"
    case EntryKind.custom: return "square.grid.2x2"
    case EntryKind.identity: return "person.text.rectangle"
    default: return "key"
    }
}

/// The site's favicon, or the kind tile.
struct ItemIcon: View {
    @EnvironmentObject var model: AppModel
    let entry: EntryInfo
    var size: CGFloat = 32

    var body: some View {
        if let h = entry.hosts.first, let icon = model.icons[h] {
            Image(nsImage: icon).resizable().interpolation(.high).frame(width: size, height: size)
        } else {
            KindTile(kind: entry.kind, name: entry.name, size: size)
        }
    }
}

// MARK: - Controls

/// Small borderless icon button that shows a hover background.
struct IconButton: View {
    let systemName: String
    var help: String = ""
    var size: CGFloat = 24
    let action: () -> Void
    @Local private var hover = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: size * 0.5))
                .frame(width: size, height: size)
                .background(RoundedRectangle(cornerRadius: 5).fill(Color.primary.opacity(hover ? 0.06 : 0)))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .onHover { hover = $0 }
        .help(help)
    }
}

/// 1Password-style buttons. Primary: a solid navy pill with white text.
/// Secondary: plain icon-and-text that greys on hover.
struct PillButtonStyle: ButtonStyle {
    var prominent = true
    var destructive = false
    /// A full-width call to action.
    var fullWidth = false

    func makeBody(configuration: Configuration) -> some View {
        PillBody(configuration: configuration, prominent: prominent, destructive: destructive, fullWidth: fullWidth)
    }

    struct PillBody: View {
        let configuration: Configuration
        let prominent: Bool
        let destructive: Bool
        let fullWidth: Bool
        @Environment(\.isEnabled) private var enabled
        @Local private var hover = false

        var body: some View {
            // Calls to action are YubiKey gold with navy text.
            let fill: Color = prominent ? (destructive ? .red : Brand.gold) : Color.primary.opacity(hover ? 0.06 : 0)
            configuration.label
                .labelStyle(.titleAndIcon)
                .lineLimit(1)
                .fixedSize()
                .frame(maxWidth: fullWidth ? .infinity : nil)
                .font(.system(size: fullWidth ? 14 : 13, weight: prominent ? .semibold : .regular))
                .foregroundStyle(prominent ? AnyShapeStyle(destructive ? Color.white : Brand.navy) : destructive ? AnyShapeStyle(Color.red) : AnyShapeStyle(.primary))
                .padding(.horizontal, prominent ? 16 : 10)
                .padding(.vertical, fullWidth ? 11 : 7)
                .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(fill))
                .opacity(enabled ? (configuration.isPressed ? 0.75 : 1) : 0.4)
                .contentShape(Rectangle())
                .onHover { hover = $0 }
        }
    }
}

/// The one text field look for every form: roomy, rounded, white, with the
/// same soft focus ring as the unlock field.
struct FieldBackground: ViewModifier {
    @FocusState private var isFocused: Bool

    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .font(.system(size: 14))
            .focused($isFocused)
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .frame(minHeight: 40)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color(nsColor: .textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(isFocused ? Brand.label.opacity(0.45) : Color(nsColor: .separatorColor),
                              lineWidth: isFocused ? 2.5 : 0.5))
    }
}

/// A light bordered card for grouped fields.
struct CardBackground: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color(nsColor: .textBackgroundColor)))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
    }
}

/// A flat item tile: the name's monogram for logins, the kind's symbol
/// otherwise.
struct KindTile: View {
    let kind: Int
    let name: String
    var size: CGFloat = 52

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
        Group {
            if kind == EntryKind.login, let ch = name.trimmingCharacters(in: .whitespaces).first {
                shape.fill(tileColor(name).opacity(0.9))
                    .overlay(Text(String(ch).uppercased()).font(.system(size: size * 0.5, weight: .semibold)).foregroundStyle(.white))
            } else {
                shape.fill(Color.primary.opacity(0.06))
                    .overlay(Image(systemName: kindIcon(kind)).font(.system(size: size * 0.45)).foregroundStyle(.secondary))
            }
        }
        .frame(width: size, height: size)
    }
}

/// A "+ add …" row at the bottom of a card, in the label colour.
struct AddRow: View {
    let title: String
    let action: (() -> Void)?
    @Local private var hover = false

    var body: some View {
        let row = HStack(spacing: 8) {
            Image(systemName: "plus").font(.system(size: 12, weight: .semibold))
            Text(title).font(.system(size: 13))
            Spacer()
        }
        .foregroundStyle(Brand.label)
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(Color.primary.opacity(hover ? 0.04 : 0))
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        if let action {
            Button(action: action) { row }.buttonStyle(.plain)
        } else {
            row
        }
    }
}

extension View {
    func fieldBackground() -> some View { modifier(FieldBackground()) }
    func card() -> some View { modifier(CardBackground()) }
}

// MARK: - Screen parts

/// Back button and a centred title, for the settings-style screens.
struct ScreenHeader: View {
    @EnvironmentObject var model: AppModel
    let title: String
    /// Where the back button goes; nil uses `onBack`.
    var back: AppModel.Route? = .list
    var onBack: () -> Void = {}

    var body: some View {
        HStack {
            IconButton(systemName: "chevron.left", help: "Back (Esc)") {
                if let b = back { model.route = b } else { onBack() }
            }
                .keyboardShortcut(.cancelAction)
            Spacer()
            Text(title).font(.system(size: 13, weight: .semibold))
            Spacer()
            Color.clear.frame(width: 24, height: 24)
        }
        .padding(.horizontal, 12)
        .frame(height: 40)
    }
}

/// Small grey caps above a group, like "ALL ITEMS" in the list.
struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
    }
}

/// The gold "touch your YubiKey" prompt (gold is kept for this moment only).
struct TouchPromptView: View {
    var title = "Touch your YubiKey"
    var detail = "Tap the gold contact."

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(Brand.gold).frame(width: 10, height: 10)
                .overlay(Circle().stroke(Brand.gold.opacity(0.4), lineWidth: 4).scaleEffect(1.6))
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(height: 44)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Brand.gold.opacity(0.12)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Brand.gold.opacity(0.7), lineWidth: 1))
    }
}

/// One "what do you want to do" row: icon, title, a line of detail.
struct IntentRow: View {
    let icon: String
    let title: String
    let detail: String
    let action: () -> Void
    @Local private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon).font(.system(size: 15)).foregroundStyle(Brand.label).frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 13, weight: .medium)).foregroundStyle(.primary)
                    Text(detail).font(.system(size: 11.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold)).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .background(Color.primary.opacity(hover ? 0.04 : 0))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

/// A navy YubiKey glyph for key rows.
struct KeyGlyph: View {
    var body: some View {
        RoundedRectangle(cornerRadius: 7, style: .continuous)
            .fill(Brand.navy.opacity(0.07))
            .frame(width: 32, height: 32)
            .overlay(YubiKeyMark(contact: .white).frame(width: 10, height: 21).rotationEffect(.degrees(-35)))
    }
}

func labelledField<V: View>(_ title: String, @ViewBuilder _ v: () -> V) -> some View {
    VStack(alignment: .leading, spacing: 6) {
        Text(title).font(.system(size: 12)).foregroundStyle(Brand.label)
        v()
    }
}
