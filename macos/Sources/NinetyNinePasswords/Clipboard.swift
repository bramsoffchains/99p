import AppKit

/// Copies a secret marked concealed and transient (SPEC §14.6), then clears
/// it after `clearAfter` seconds unless something else was copied since.
enum Clipboard {
    static func copy(_ value: String, clearAfter: TimeInterval) {
        let pb = NSPasteboard.general
        let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
        let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
        pb.declareTypes([.string, concealed, transient], owner: nil)
        pb.setString(value, forType: .string)
        pb.setString("", forType: concealed)
        pb.setString("", forType: transient)
        let count = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            if pb.changeCount == count { pb.clearContents() }
        }
    }
}
