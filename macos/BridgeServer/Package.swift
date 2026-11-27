// swift-tools-version:5.9
// App-side half of the browser bridge (SPEC §12). The menu bar app embeds
// this as a local package: socket server, peer check, message router and the
// Chrome native messaging host manifest.
import PackageDescription

let package = Package(
    name: "BridgeServer",
    platforms: [.macOS(.v13)],
    products: [.library(name: "BridgeServer", targets: ["BridgeServer"])],
    targets: [
        .target(name: "BridgeServer"),
        .testTarget(name: "BridgeServerTests", dependencies: ["BridgeServer"]),
    ]
)
