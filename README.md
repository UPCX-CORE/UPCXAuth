# UPCX Auth SDK for Swift

UPCX Auth is a simple, lightweight, flexible and easy to use library to create and recover UPCX Wallet by using Email Address.


> [!IMPORTANT]
> The current version is still in development. There can and will be breaking changes in version updates.

## Features:

* Passwordless Sign in using Email Address.
* Create/Recover UPCX Wallet from Email Address's unique information.


## Demo

## Installation

### Swift Package Manager
```swift
dependencies: [
    .package(url: "https://github.com/UPCX-CORE/UPCXAuth.git", from: "1.0.0")
]
```

### Cocoapods

> [Caution]
> CocoaPods support will be dropped with version 1.0. Prior to that, support will be minimal. Using SPM is highly recommended.

Add the following line to your Podfile:

```
pod 'UPCXAuth', '~> 0.0.1'
```

and run

```
pod install
```

or

```
pod update
```

## Usage

> Initialization

Create amplifyconfiguration.json file in the root directory.
```
{
  "UserAgent": "aws-amplify-cli/2.0",
  "Version": "1.0",
  "auth": {
    "plugins": {
      "awsCognitoAuthPlugin": {
        "UserAgent": "aws-amplify-cli-setup",
        "Version": "1.0",
        "CognitoUserPool": {
          "Default": {
            "PoolId": [Cognito-UserPool-ID],
            "AppClientId": [Cognito-App-Client-ID],
            "Region": [Cognito-Region]
          }
        },
        "AuthProviders": [],
        "IdentityPoolId": [Identity-Pool-ID]
      }
    }
  }
}
```

Add following code to AppDelegate.swift.
```swift
import Amplify
import AWSCognitoAuthPlugin

func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    do {
        try Amplify.add(plugin: AWSCognitoAuthPlugin())

        try Amplify.configure()
        print("Amplify configured successfully 🎉")
    } catch {
        print("Failed to configure Amplify ❌: \(error)")
    }
    return true
}
```

> Request Sign In
```swift
let service = PasswordlessAuthService()
await service.initiateSignIn(username: emailAddress!) { result in
    // true if sent verification code successfully
}
```

> Confirm Sign In
```swift
let service = PasswordlessAuthService()
await service.confirmSignIn(response: verificationCode!) { result in
    guard let priKey = result else {
        // No User Exists
        Task {
            await service.saveAuthData(accountName: emailAddress!, namingServerUrl: namingServerUrl, shardId: shardId) { result in
                print("PriKey:", result!)
            }
        }
        
        return
    }
    
    if priKey == "Sign In Failed" {
        return
    }
    
    print("PrivateKey", priKey)
}
```