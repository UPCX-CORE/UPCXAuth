//
//  PasswordlessAuthService.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/23.
//

import Amplify
import AWSCognitoAuthPlugin
import Foundation

public class PasswordlessAuthService {
    
    public init() {
        // Ensure Amplify is configured, usually done in AppDelegate or framework's host app
        // For a framework, you might want to provide a way for the host app to configure Amplify
    }
    
    /// Initiates the passwordless sign-in flow by sending an OTP to the user's identifier (email/phone).
    /// - Parameter username: The user's email address or phone number.
    /// - Parameter completion: A closure to handle the result: success or error.
    ///
    
    public func signUp(username: String, email: String, _ completion: ((Bool?) -> Void)? = nil) async {
        let userAttributes = [AuthUserAttribute(.email, value: email)]
        let options = AuthSignUpRequest.Options(userAttributes: userAttributes)
        
        do {
            let signUpResult = try await Amplify.Auth.signUp(
                username: username,
                password: "Temppassword123@",
                options: options
            )
            
            if case let .confirmUser(deliveryDetails, _, userId) = signUpResult.nextStep {
                print("Delivery details \(String(describing: deliveryDetails)) for userId: \(String(describing: userId)))")
            } else {
                print("Signup Complete")
                
                await initiateSignIn(username: username) { result in
                    guard let result = result else {
                        completion?(false)
                        return
                    }
                    completion?(true)
                }
            }
        } catch let error as AuthError {
            completion?(false)
            print("An error occurred while registering a user \(error)")
        } catch {
            print("Unexpected error: \(error)")
            completion?(false)
        }
    }
    
    public func initiateSignIn(username: String, _ completion: ((Bool?) -> Void)? = nil) async {
        do {
            let options = AWSAuthSignInOptions(authFlowType: .customWithoutSRP)
            let signInResult = try await Amplify.Auth.signIn(username: username,
                                                             options: .init(pluginOptions: options))
            
            switch signInResult.nextStep {
            case .confirmSignInWithSMSMFACode(_, _):
                // Handle SMS MFA
                print("OTP_SENT_SUCCESS")
                completion?(true)
            case .confirmSignInWithCustomChallenge(_):
                // Handle another step
                print("OTP_SENT_SUCCESS")
                completion?(true)
            default:
                break
            }
        } catch let error as AuthError {
            print("Sign in failed \(error)")
            await signUp(username: username, email: username) { result in
                completion?(result)
            }
        } catch {
            print("Unexpected error: \(error)")
            completion?(false)
        }
    }
    
    public func confirmSignIn(response: String, _ completion: ((String?) -> Void)? = nil) async {
        do {
            let signInResult = try await Amplify.Auth.confirmSignIn(challengeResponse: response)
            if signInResult.isSignedIn == false {
                completion?("Sign In failed")
                return
            }
            
            Task {
                let idToken = await fetchIDToken()
                let accessToken = await fetchAccessToken()
                let poolID = getUserPoolIDFromIDToken(idToken)
                let encKey = composeEncKey(idToken: idToken)
                
                AuthNodeService.init().getAuthShares(accessToken: accessToken, poolId: poolID) { result in
                    guard let response = result else {
                        completion?(nil)
                        return
                    }
                    
                    var authShares: [Secret.Share] = []
                    print(response)
                    response.shares.forEach({ value in
                        let key = AESCrypt.aesKeyFromString(encKey)
                        let decryptedShare = try! AESCrypt.decrypt(base64Key: key, base64CipherText: value)
                        print(decryptedShare)
                        
                        let share = try! Secret.Share(string: decryptedShare)
                        authShares.append(share)
                    })
                    
                    let priKey = try! Secret.combine(shares: authShares).utf8String()
                    completion?(priKey)
                }
                
                /*      Temp Code
                let priKey = createRandomPrivateKey()
                print(priKey?.wif)
                let message = Data([UInt8](priKey!.wif.utf8))
                
                let secret = try! Secret(data: message, threshold: 2, shares: 2)
                let shares = try! secret.split()
                        
                shares.forEach { share in
                    print(share.description)
                    
                    let key = AESCrypt.aesKeyFromString(encKey)
                    let decrypted = try! AESCrypt.encrypt(base64Key: key, plainText: share.description)
                    print(decrypted)
                }
                 */
            }
        } catch let error as AuthError {
            print("Confirm sign in failed \(error)")
        } catch {
            print("Unexpected error: \(error)")
        }
    }
    
    public func signOut() async {
        _ = await Amplify.Auth.signOut()
    }
    
    public func fetchAccessToken() async -> String {
        do {
            let authSession = try await Amplify.Auth.fetchAuthSession()

            if let cognitoSession = authSession as? AWSAuthCognitoSession {
                let cognitoTokens = cognitoSession.getCognitoTokens()
                
                let accessToken = try cognitoTokens.get().accessToken
                
                return accessToken
            }
        } catch let error as AuthError {
            print("Fetch auth session failed with error - \(error)")
        } catch {
            print("Unexpected error: \(error)")
        }
        
        return ""
    }
    
    public func fetchIDToken() async -> String {
        do {
            let authSession = try await Amplify.Auth.fetchAuthSession()

            if let cognitoSession = authSession as? AWSAuthCognitoSession {
                let cognitoTokens = cognitoSession.getCognitoTokens()
                
                let idToken = try cognitoTokens.get().idToken
                
                return idToken
            }
        } catch let error as AuthError {
            print("Fetch auth session failed with error - \(error)")
        } catch {
            print("Unexpected error: \(error)")
        }
        
        return ""
    }
    
    func getSubFromIDToken(_ idToken: String) -> String {
            // Decode the ID token (JWT) to access its claims
        let segments = idToken.split(separator: ".")
        
        guard segments.count == 3 else {
            print("Invalid ID Token format")
            return ""
        }
        
        let payload = segments[1]
        let paddingLength = (4 - payload.count % 4) % 4
        let paddedPayload = payload + String(repeating: "=", count: paddingLength)
        
        guard let decodedData = Data(base64Encoded: String(paddedPayload), options: .ignoreUnknownCharacters) else {
            print("Failed to decode ID token payload")
            return ""
        }
        
        do {
            // Parse the decoded data into a dictionary
            if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any],
               let sub = jsonObject["sub"] as? String {
                print("Sub: \(sub)")
                return sub
            } else {
                print("Failed to extract issuer from ID token")
            }
        } catch {
            print("Error parsing ID token: \(error)")
        }
    
        return ""
    }
    
    func getEmailFromIDToken(_ idToken: String) -> String {
            // Decode the ID token (JWT) to access its claims
        let segments = idToken.split(separator: ".")
        
        guard segments.count == 3 else {
            print("Invalid ID Token format")
            return ""
        }
        
        let payload = segments[1]
        let paddingLength = (4 - payload.count % 4) % 4
        let paddedPayload = payload + String(repeating: "=", count: paddingLength)
        
        guard let decodedData = Data(base64Encoded: String(paddedPayload), options: .ignoreUnknownCharacters) else {
            print("Failed to decode ID token payload")
            return ""
        }
        
        do {
            // Parse the decoded data into a dictionary
            if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any],
               let email = jsonObject["email"] as? String {
                print("Email: \(email)")
                return email
            } else {
                print("Failed to extract issuer from ID token")
            }
        } catch {
            print("Error parsing ID token: \(error)")
        }
    
        return ""
    }
    
    func getIssuerFromIDToken(_ idToken: String) -> String {
            // Decode the ID token (JWT) to access its claims
        let segments = idToken.split(separator: ".")
        
        guard segments.count == 3 else {
            print("Invalid ID Token format")
            return ""
        }
        
        let payload = segments[1]
        let paddingLength = (4 - payload.count % 4) % 4
        let paddedPayload = payload + String(repeating: "=", count: paddingLength)
        
        guard let decodedData = Data(base64Encoded: String(paddedPayload), options: .ignoreUnknownCharacters) else {
            print("Failed to decode ID token payload")
            return ""
        }
        
        do {
            // Parse the decoded data into a dictionary
            if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any],
               let issuer = jsonObject["iss"] as? String {
                print("Issuer: \(issuer)")
                return issuer
            } else {
                print("Failed to extract issuer from ID token")
            }
        } catch {
            print("Error parsing ID token: \(error)")
        }
    
        return ""
    }
    
    func getAudFromIDToken(_ idToken: String) -> String {
            // Decode the ID token (JWT) to access its claims
        let segments = idToken.split(separator: ".")
        
        guard segments.count == 3 else {
            print("Invalid ID Token format")
            return ""
        }
        
        let payload = segments[1]
        let paddingLength = (4 - payload.count % 4) % 4
        let paddedPayload = payload + String(repeating: "=", count: paddingLength)
        
        guard let decodedData = Data(base64Encoded: String(paddedPayload), options: .ignoreUnknownCharacters) else {
            print("Failed to decode ID token payload")
            return ""
        }
        
        do {
            // Parse the decoded data into a dictionary
            if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any],
               let aud = jsonObject["aud"] as? String {
                print("Aud: \(aud)")
                return aud
            } else {
                print("Failed to extract issuer from ID token")
            }
        } catch {
            print("Error parsing ID token: \(error)")
        }
    
        return ""
    }
    
    func getUserPoolIDFromIDToken(_ idToken: String) -> String {
            // Decode the ID token (JWT) to access its claims
        let segments = idToken.split(separator: ".")
        
        guard segments.count == 3 else {
            print("Invalid ID Token format")
            return ""
        }
        
        let payload = segments[1]
        let paddingLength = (4 - payload.count % 4) % 4
        let paddedPayload = payload + String(repeating: "=", count: paddingLength)
        
        guard let decodedData = Data(base64Encoded: String(paddedPayload), options: .ignoreUnknownCharacters) else {
            print("Failed to decode ID token payload")
            return ""
        }
        
        do {
            // Parse the decoded data into a dictionary
            if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any],
               let issuer = jsonObject["iss"] as? String {
                let components = issuer.split(separator: "/")
                return String(components[components.count - 1])
            } else {
                print("Failed to extract issuer from ID token")
            }
        } catch {
            print("Error parsing ID token: \(error)")
        }
    
        return ""
    }
    
    public func saveAuthData(accountName: String, namingServerUrl: String, shardId: String, _ completion: ((String?) -> Void)? = nil) async {
        let idToken = await fetchIDToken()
        let accessToken = await fetchAccessToken()
        let poolID = getUserPoolIDFromIDToken(idToken)
        let encKey = composeEncKey(idToken: idToken)
        
        let priKey = createRandomPrivateKey()
        
        AccountService.init().createAccount(namingServerUrl: namingServerUrl, shardId: shardId, accountName: accountName, pubKey: priKey!.upcxPublicKey) { result in
            let message = Data([UInt8](priKey!.wif.utf8))
            
            let secret = try! Secret(data: message, threshold: 2, shares: 2)
            let shares = try! secret.split()
            
            var encShares: [String] = []
                    
            shares.forEach { share in
                print(share.description)
                
                let key = AESCrypt.aesKeyFromString(encKey)
                let encryptedShare = try! AESCrypt.encrypt(base64Key: key, plainText: share.description)
                encShares.append(encryptedShare)
            }
            
            AuthNodeService.init().saveShares(accessToken: accessToken, poolID: poolID, shares: encShares) { result in
                guard result != nil else {
                    completion?(nil)
                    return
                }
                completion?(priKey?.wif)
            }
        }
    }
    
    public func getAccountDetails() {
        
    }
    
    func composeEncKey(idToken: String) -> String {
        let encKey = getEmailFromIDToken(idToken) + getSubFromIDToken(idToken) + getIssuerFromIDToken(idToken) + getAudFromIDToken(idToken)
        print(encKey)
        return encKey
    }
    
    func createRandomPrivateKey() -> UPCXPrivateKey? {
        let mnemonic = Mnemonic()
        let seed = mnemonic.seed.bytesToHex(spacing: "")
        let index = seed.index(seed.startIndex, offsetBy: 64)
        let entropy = String(seed[..<index])
        let privateKey = UPCXPrivateKey.fromSeed(entropy, index: 0)
        let pubKey = privateKey?.upcxPublicKey
        
        return privateKey
    }
}

public extension Array where Element == UInt8 {
    func bytesToHex(spacing: String) -> String {
        var hexString: String = ""
        var count = self.count
        for byte in self
        {
            hexString.append(String(format:"%02X", byte))
            count = count - 1
            if count > 0
            {
                hexString.append(spacing)
            }
        }
        return hexString
    }
}
