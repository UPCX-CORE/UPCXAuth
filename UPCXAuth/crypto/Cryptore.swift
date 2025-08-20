//
//  Cryptore.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/29.
//

import Foundation
import Security

// MARK: - CryptoreError
// Custom error type for Cryptore operations
enum CryptoreError: Error, LocalizedError {
    case invalidKeyIdentifier
    case keyGenerationFailed(String)
    case keyRetrievalFailed(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case dataConversionFailed(String)
    case algorithmNotSupported(String)
    case invalidBase64String

    var errorDescription: String? {
        switch self {
        case .invalidKeyIdentifier:
            return "The provided key identifier is invalid."
        case .keyGenerationFailed(let details):
            return "Failed to generate cryptographic key pair: \(details)"
        case .keyRetrievalFailed(let details):
            return "Failed to retrieve cryptographic key pair: \(details)"
        case .encryptionFailed(let details):
            return "Encryption failed: \(details)"
        case .decryptionFailed(let details):
            return "Decryption failed: \(details)"
        case .dataConversionFailed(let details):
            return "Data conversion failed: \(details)"
        case .algorithmNotSupported(let details):
            return "The specified algorithm is not supported: \(details)"
        case .invalidBase64String:
            return "The input string is not a valid Base64 encoded string."
        }
    }
}

// MARK: - CipherAlgorithm
// Represents the cryptographic algorithm, mirroring Java's CipherAlgorithm.RSA
enum CipherAlgorithm {
    case rsa
    // Add other algorithms if your Java Cryptore supports them
}

// MARK: - Cryptore
// Swift equivalent of the Java Cryptore class
class Cryptore {

    private let keyIdentifier: String // Used as kSecAttrApplicationTag for Keychain
    private let algorithm: CipherAlgorithm
    private var privateKey: SecKey?
    private var publicKey: SecKey?

    // RSA specific constants
    private static let rsaKeySize = 2048 // bits
    private static let rsaPadding: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256 // Recommended padding

    // MARK: - Builder (Mimicking Java's Builder pattern)
    class Builder {
        private var key: String?
        private var algorithm: CipherAlgorithm?
        // In Swift/iOS, 'context' is often implicit or handled by Security framework directly.
        // We don't need a direct 'context' parameter here for Keychain operations.

        init(key: String, algorithm: CipherAlgorithm) {
            self.key = key
            self.algorithm = algorithm
        }

        // setContext is not directly needed for Security.framework, but keeping it for API parity
        // You might use this to pass a ViewController for presenting UI, but not for core crypto.
        func setContext(_ context: Any?) -> Builder {
            // No-op for this implementation as context is not directly used for key ops
            return self
        }

        func build() throws -> Cryptore {
            guard let key = key, !key.isEmpty else {
                throw CryptoreError.invalidKeyIdentifier
            }
            guard let algorithm = algorithm else {
                throw CryptoreError.algorithmNotSupported("Algorithm not specified in builder.")
            }
            return try Cryptore(key: key, algorithm: algorithm)
        }
    }

    // MARK: - Cryptore Initialization
    private init(key: String, algorithm: CipherAlgorithm) throws {
        self.keyIdentifier = key
        self.algorithm = algorithm

        // Attempt to load or generate keys upon initialization
        try loadOrCreateKeyPair()
    }

    // MARK: - Key Management
    private func loadOrCreateKeyPair() throws {
        let tag = keyIdentifier.data(using: .utf8)!

        // Try to load existing private key from Keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess {
            // Key found, cast to SecKey
            self.privateKey = (item as! SecKey)
            self.publicKey = SecKeyCopyPublicKey(self.privateKey!)
            print("Cryptore: Loaded existing RSA key pair for identifier: \(keyIdentifier)")
        } else if status == errSecItemNotFound {
            // Key not found, generate a new one
            print("Cryptore: Key pair not found for identifier: \(keyIdentifier). Generating new one...")
            try generateAndStoreKeyPair(tag: tag)
        } else {
            // Other error during key retrieval
            let errorString = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            throw CryptoreError.keyRetrievalFailed("Status: \(status), Details: \(errorString)")
        }
    }

    private func generateAndStoreKeyPair(tag: Data) throws {
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: Cryptore.rsaKeySize,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true, // Store in Keychain
                kSecAttrApplicationTag as String: tag // Use identifier as tag
            ]
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw CryptoreError.keyGenerationFailed(errorDescription)
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CryptoreError.keyGenerationFailed("Failed to derive public key from private key.")
        }

        self.privateKey = privateKey
        self.publicKey = publicKey
        print("Cryptore: Generated and stored new RSA key pair for identifier: \(keyIdentifier)")
    }

    // MARK: - Encryption
    func encrypt(plainData: Data) throws -> Data {
        guard let publicKey = self.publicKey else {
            throw CryptoreError.encryptionFailed("Public key not available.")
        }

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, Cryptore.rsaPadding) else {
            throw CryptoreError.algorithmNotSupported("Public key does not support encryption with specified padding.")
        }

        var error: Unmanaged<CFError>?
        guard let cipherData = SecKeyCreateEncryptedData(publicKey, Cryptore.rsaPadding, plainData as CFData, &error) else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw CryptoreError.encryptionFailed(errorDescription)
        }

        return cipherData as Data
    }

    // MARK: - Decryption
    func decrypt(cipherData: Data) throws -> Data {
        guard let privateKey = self.privateKey else {
            throw CryptoreError.decryptionFailed("Private key not available.")
        }

        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, Cryptore.rsaPadding) else {
            throw CryptoreError.algorithmNotSupported("Private key does not support decryption with specified padding.")
        }

        var error: Unmanaged<CFError>?
        guard let plainData = SecKeyCreateDecryptedData(privateKey, Cryptore.rsaPadding, cipherData as CFData, &error) else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw CryptoreError.decryptionFailed(errorDescription)
        }

        return plainData as Data
    }
}
