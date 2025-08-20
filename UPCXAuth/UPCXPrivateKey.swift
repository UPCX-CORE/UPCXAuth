//
//  UPCXPrivateKey.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/25.
//

import Foundation
import CryptoKit
import libsecp256k1
import RIPEMD160
import BigInt

// MARK: - Base58 encoding (assumes Base58.encode(_: Data) and Base58.decode(_: String))

// MARK: - Data Extensions

extension Data {
    init?(hex: String) {
        let hex = hex.dropFirst(hex.hasPrefix("0x") ? 2 : 0)
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            if nextIndex > hex.endIndex { return nil }
            guard let b = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(b)
            index = nextIndex
        }
        self = data
    }

    func sha256() -> Data {
        return Data(SHA256.hash(data: self))
    }

    func ripemd160() -> Data {
        return RIPEMD160.hash(data: self)
    }

    func leftPadding(to length: Int) -> Data {
        if self.count >= length { return self }
        return Data(repeating: 0, count: length - self.count) + self
    }
}

// MARK: - UPCX Key Pair Class

class UPCXPrivateKey {
    let privateKey: Data // 32 bytes
    let publicKey: Data  // 33 bytes (compressed)

    init?(privateKey: Data) {
        guard privateKey.count == 32 else { return nil }
        self.privateKey = privateKey

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        var pubkey = secp256k1_pubkey()
        guard privateKey.withUnsafeBytes({
            secp256k1_ec_pubkey_create(ctx, &pubkey, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }) == 1 else {
            return nil
        }

        var output = [UInt8](repeating: 0, count: 33)
        var outputLen = 33
        secp256k1_ec_pubkey_serialize(ctx, &output, &outputLen, &pubkey, UInt32(SECP256K1_EC_COMPRESSED))
        self.publicKey = Data(output)
    }

    static func fromWIF(_ wif: String) -> UPCXPrivateKey? {
        guard let decoded = Base58.decode(wif), decoded.count >= 37 else { return nil }
        let version = decoded[0]
        guard version == 0x80 else { return nil }
        let privKey = decoded[1..<33]
        let checksum = decoded[33..<37]
        let check = Data(decoded.prefix(33)).sha256().sha256().prefix(4)
        guard checksum == check else { return nil }
        return UPCXPrivateKey(privateKey: Data(privKey))
    }

    static func fromSeed(_ hex: String, index: Int) -> UPCXPrivateKey? {
        guard let data = Data(hex: hex) else { return nil }
        var number = BigUInt(data)
        number += BigUInt(index)
        let padded = number.serialize().leftPadding(to: 32)
        return UPCXPrivateKey(privateKey: padded)
    }

    var wif: String {
        let extended = Data([0x80]) + privateKey
        let checksum = extended.sha256().sha256().prefix(4)
        return Base58.encode(extended + checksum)
    }

    var upcxPublicKey: String {
        let checksum = publicKey.ripemd160().prefix(4)
        return "UPCX" + Base58.encode(publicKey + checksum)
    }

    func sign(_ hash: Data) -> Data? {
        var sig = secp256k1_ecdsa_recoverable_signature()
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        guard privateKey.withUnsafeBytes({ pkPtr in
            hash.withUnsafeBytes { hashPtr in
                secp256k1_ecdsa_sign_recoverable(ctx, &sig, hashPtr.bindMemory(to: UInt8.self).baseAddress!, pkPtr.bindMemory(to: UInt8.self).baseAddress!, nil, nil)
            }
        }) == 1 else {
            return nil
        }

        var compact = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &compact, &recid, &sig)

        let headerByte = UInt8(recid + 27 + 4)
        return Data([headerByte] + compact)
    }
}
