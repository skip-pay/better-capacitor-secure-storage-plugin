// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BetterCapacitorSecureStoragePlugin",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "BetterCapacitorSecureStoragePlugin",
            targets: ["SecureStoragePlugin"])
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "8.3.0")
    ],
    targets: [
        .target(
            name: "SecureStoragePlugin",
            dependencies: [
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm")
            ],
            path: "ios/Sources/SecureStoragePlugin"),
        .testTarget(
            name: "SecureStoragePluginTests",
            dependencies: ["SecureStoragePlugin"],
            path: "ios/Tests/SecureStoragePluginTests")
    ]
)