import Foundation

/// Socket framing: little-endian u32 length, then UTF-8 JSON (SPEC §12.1).
public enum Framing {
    public static let maxMessage = 64 * 1024

    public static func encode(_ object: [String: Any]) throws -> Data {
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard !body.isEmpty, body.count <= maxMessage else { throw BridgeError.badFrame }
        var len = UInt32(body.count).littleEndian
        var out = Data(bytes: &len, count: 4)
        out.append(body)
        return out
    }

    public static func decodeLength(_ header: Data) throws -> Int {
        guard header.count == 4 else { throw BridgeError.badFrame }
        let n = Int(header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian)
        guard n > 0, n <= maxMessage else { throw BridgeError.badFrame }
        return n
    }

    public static func decodeBody(_ body: Data) throws -> [String: Any] {
        guard let obj = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw BridgeError.badMessage
        }
        return obj
    }
}

public enum BridgeError: Error, Equatable {
    case badFrame
    case badMessage
    case pathTooLong
    case socket(Int32)
}
