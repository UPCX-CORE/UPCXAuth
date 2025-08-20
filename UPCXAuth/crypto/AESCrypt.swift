//
//  AESCrypt.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/29.
//

import Foundation
import CommonCrypto
import CryptoKit

class AESCrypt {

    private static let ivSize = kCCBlockSizeAES128

    static func encrypt(base64Key: String, plainText: String) throws -> String {
        guard let keyData = Data(base64Encoded: base64Key),
              let plainData = plainText.data(using: .utf8) else {
            throw NSError(domain: "AES", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid input"])
        }

        // Generate random IV
        var iv = Data(count: ivSize)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, ivSize, $0.baseAddress!) }

        // Prepare output buffer
        let encryptedLength = plainData.count + kCCBlockSizeAES128
        var encrypted = Data(count: encryptedLength)
        var numBytesEncrypted = 0
        
        let status: CCCryptorStatus = encrypted.withUnsafeMutableBytes { encryptedBuffer in
            numBytesEncrypted = 0

            return plainData.withUnsafeBytes { plainBytes in
                iv.withUnsafeBytes { ivBytes in
                    keyData.withUnsafeBytes { keyBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            keyData.count,
                            ivBytes.baseAddress,
                            plainBytes.baseAddress,
                            plainData.count,
                            encryptedBuffer.baseAddress,
                            encryptedLength,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        encrypted.removeSubrange(encrypted.index(encrypted.startIndex, offsetBy: numBytesEncrypted)..<encrypted.endIndex)
        guard status == kCCSuccess else {
            throw NSError(domain: "AES", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Encryption failed"])
        }

        encrypted.count = numBytesEncrypted

        // Combine IV + encrypted
        let combined = iv + encrypted
        return combined.base64EncodedString()
    }

    static func decrypt(base64Key: String, base64CipherText: String) throws -> String {
        guard let keyData = Data(base64Encoded: base64Key),
              let combinedData = Data(base64Encoded: base64CipherText) else {
            throw NSError(domain: "AES", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64"])
        }

        let iv = combinedData.prefix(ivSize)
        let cipherText = combinedData.dropFirst(ivSize)
        var numBytesDecrypted = 0
        var decrypted = Data(count: cipherText.count)
        let status: CCCryptorStatus = decrypted.withUnsafeMutableBytes { decryptedBuffer in
            numBytesDecrypted = 0

            return cipherText.withUnsafeBytes { cipherBytes in
                iv.withUnsafeBytes { ivBytes in
                    keyData.withUnsafeBytes { keyBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            keyData.count,
                            ivBytes.baseAddress,
                            cipherBytes.baseAddress,
                            cipherText.count,
                            decryptedBuffer.baseAddress,
                            decryptedBuffer.count,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }
        decrypted.removeSubrange(decrypted.index(decrypted.startIndex, offsetBy: numBytesDecrypted)..<decrypted.endIndex)

        guard status == kCCSuccess else {
            throw NSError(domain: "AES", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Decryption failed"])
        }

        decrypted.count = numBytesDecrypted
        return String(data: decrypted, encoding: .utf8) ?? ""
    }
    
    static func aesKeyFromString(_ string: String) -> String {
        let data = Data(string.utf8)
        let hash = SHA256.hash(data: data)
        return Data(hash).base64EncodedString()
    }
}
