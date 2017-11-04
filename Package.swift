// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "OAuth",
    dependencies: [
        .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", Version(0,7,0)),
        .Package(url: "https://github.com/PerfectlySoft/Perfect.git", majorVersion: 3)
    ]
)
