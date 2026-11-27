// swift-tools-version:5.9
// The 99passwords menu bar app. Links the Rust C ABI (crates/ffi/, libykvault_ffi.a);
// build that first with `cargo build -p ykvault-ffi --release`, or use build-app.sh.
import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().path

let package = Package(
    name: "NinetyNinePasswords",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "BridgeServer")],
    targets: [
        .systemLibrary(name: "CYkvault", path: "Sources/CYkvault"),
        .target(
            name: "VaultKit",
            dependencies: ["CYkvault"],
            linkerSettings: [.unsafeFlags(["-L\(root)/target/release"])]
        ),
        .executableTarget(
            name: "NinetyNinePasswords",
            dependencies: ["VaultKit", .product(name: "BridgeServer", package: "BridgeServer")]
        ),
        .testTarget(name: "VaultKitTests", dependencies: ["VaultKit"]),
    ]
)
