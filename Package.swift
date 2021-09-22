// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "TIM",
    platforms: [
       .iOS(.v9),
    ],
    products: [
        .library(
            name: "TIM",
            targets: ["TIM"]),
    ],
    dependencies: [
        .package(name: "AppAuth", url: "https://github.com/openid/AppAuth-iOS", .exact("1.4.0")),
        .package(name: "TIMEncryptedStorage", url: "https://github.com/trifork/TIMEncryptedStorage-iOS", .branch("bugfix/import-issue")),

    ],
    targets: [
        .target(
            name: "TIM",
            dependencies: [
                "AppAuth",
                "TIMEncryptedStorage"
            ]),
        .testTarget(
            name: "TIMTests",
            dependencies: ["TIM"]),
    ]
)
