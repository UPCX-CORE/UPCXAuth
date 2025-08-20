//
//  EOSKeyGenerator.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/24.
//

import Foundation
import CryptoKit
import libsecp256k1
import RIPEMD160

// MARK: - Data Extensions

extension Data {

    var hexString: String {
        self.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - EOSIO Key Pair Struct

struct UPCXKeyPair {
    let privateKey: Data    // 32 bytes
    let publicKey: Data     // 33 bytes (compressed)

    var wif: String {
        var payload = Data([0x80]) + privateKey  // prefix 0x80
        let checksum = payload.sha256().sha256().prefix(4)
        payload.append(checksum)
        return Base58.encode(payload)
    }

    var upcxPublicKey: String {
        let checksum = publicKey.ripemd160().prefix(4)
        let full = publicKey + checksum
        return "UPCX" + Base58.encode(full)
    }
}

// MARK: - EOSIO Key Generator

class UPCKeyGenerator {
    static func generate() -> UPCXKeyPair {
        // 1. Generate 32-byte private key
        var privBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &privBytes)
        let privKey = Data(privBytes)

        // 2. Create public key from private key
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        var pubkey = secp256k1_pubkey()
        _ = privKey.withUnsafeBytes {
            secp256k1_ec_pubkey_create(ctx, &pubkey, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }

        var output = [UInt8](repeating: 0, count: 33)
        var outLen = 33
        _ = secp256k1_ec_pubkey_serialize(
            ctx,
            &output,
            &outLen,
            &pubkey,
            UInt32(SECP256K1_EC_COMPRESSED)
        )

        return UPCXKeyPair(privateKey: privKey, publicKey: Data(output))
    }
}
