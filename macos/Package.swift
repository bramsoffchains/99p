// swift-tools-version:5.9
// The 99passwords menu bar app. Links the Rust C ABI (crates/ffi/, libp99_ffi.a);
// build that first with `cargo build -p p99-ffi --release`, or use build-app.sh.
import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().path

let package = Package(
    name: "NinetyNinePasswords",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "BridgeServer")],
    targets: [
        .systemLibrary(name: "CP99", path: "Sources/CP99"),
        .target(
            name: "VaultKit",
            dependencies: ["CP99"],
            linkerSettings: [.unsafeFlags(["-L\(root)/target/release"])]
        ),
        .executableTarget(
            name: "NinetyNinePasswords",
            dependencies: ["VaultKit", .product(name: "BridgeServer", package: "BridgeServer")]
        ),
        .testTarget(name: "VaultKitTests", dependencies: ["VaultKit"]),
    ]
)
