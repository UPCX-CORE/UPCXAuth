// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "UPCXAuth",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        // The library exposed to clients
        .library(
            name: "UPCXAuth",
            targets: ["UPCXAuth"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/aws-amplify/amplify-swift.git", from: "2.49.1"),
	.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.9.0"),
	.package(url: "https://github.com/21-DOT-DEV/swift-secp256k1.git", from: "0.21.1"),
	.package(url: "https://github.com/anquii/RIPEMD160.git", from: "1.0.0"),
	.package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0")
    ],
    targets: [
        // Your framework target
        .target(
            name: "UPCXAuth",
            dependencies: [
                .product(name: "Amplify", package: "amplify-swift"),
                .product(name: "AWSCognitoAuthPlugin", package: "amplify-swift")
            ],
            path: "UPCXAuth"
        )
    ]
)
