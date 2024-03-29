# Trifork Identity Manager iOS

![iOS-9.0](https://img.shields.io/static/v1?logo=apple&label=iOS&message=9.0%2B&color=orange&style=for-the-badge)

This framework is designed for [Trifork Identity Manager](http://identitymanager.trifork.com/).

## Example
See our fully imlpemented example here (SwiftUI):

https://github.com/trifork/TIM-Example-iOS

## Setup

### Installation

Add this repo to your SPM 📦

https://github.com/trifork/TIM-iOS

### Setup configuration
Before using any function or property from `TIM` you have to configure the framework by calling the `configure` method (typically you want to do this on app startup):

```swift
import TIM
import AppAuth // Required for scopes

let config = TIMConfiguration(
    timBaseUrl: URL(string: "<TIM base URL>")!,
    realm: "<realm>",
    clientId: "<clientId>",
    redirectUri: URL(string:"<urlScheme>:/")!,
    scopes: [ OIDScopeOpenID, OIDScopeProfile ],
    encryptionMethod: .aesGcm
)
TIM.configure(configuration: config)
```

To configure TIM with custom implementations of dependencies, see the [custom setup instructions](#custom-setup-configuration).

### URL scheme
Setup your URL scheme or Universal Links to receive login redirects: [Apple Documentation](https://developer.apple.com/documentation/xcode/allowing_apps_and_websites_to_link_to_your_content/defining_a_custom_url_scheme_for_your_app)

Depending on your life cycle handling, you should handle URL requests in one of the following callbacks:

* SwiftUI: `.onOpenURL(perform:)`
* SceneDelegate: `scene(_:, openURLContexts:)`
* AppDelegate: `application(_:, open:, options:) -> Bool`

Example for `SceneDelegate`:
```swift
func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    for url: URL in URLContexts.map({ $0.url }) {
        TIM.auth.handleRedirect(url: url)
    }
}
```

### FaceID permission in Info.plist
Don't forget to set the `NSFaceIDUsageDescription` [Apple documentation](https://developer.apple.com/documentation/bundleresources/information_property_list/nsfaceidusagedescription) key in your Info.plist if you are using the biometric feature of `TIM`.

## Common use cases

The following exampes uses `TIM`'s `Combine` interface, which returns `Future` classes. If you are developing an app with a deployment target lower than iOS 13, the same interfaces exists with completion closures instead (those are deprecated from iOS 13 though).

### 1. Register / OIDC Login

All users will have to register through af OpenID Connect login. This is done so by the following:

```swift
TIM.auth.performOpenIDConnectLogin(presentingViewController: topViewController)
    .sink { (completion) in
        switch completion {
        case .failure(let error):
            print("Failed to perform OpenID Connect login: \(error.localizedDescription)")
        case .finished:
            break
        }
    } receiveValue: { (accessToken) in
        print("Successfully logged in, access and refresh token is now available. \nAT:\n\(accessToken)")
    }
    .store(in: &futureStorage)
```

### 2. Setting password
To avoid the OpenID Connect login everytime the user needs a valid session, you can provide a password, which will allow you to save an encrypted version of the refresh token, such that the user only needs to provide the password to get a valid access token. 

The user must have performed a successful OpenID Connect login before setting a password, since the refresh token has to be available.

```swift
guard let refreshToken = TIM.auth.refreshToken else {
    return
}

// UserId can be retrieved from the refresh token: `refreshToken.userId`

TIM.storage.storeRefreshToken(refreshToken, withNewPassword: password)
    .sink { (completion) in
        switch completion {
        case .failure(let error):
            print("Failed to store refresh token: \(error.localizedDescription)")
        case .finished:
            break
        }
    } receiveValue: { (keyId) in
        // TIM has saved the keyId for the userId of the refresh token - you don't need to do anything with the keyId at this point unless you are doing something custom work with TIMEncryptedStorage.
        print("Saved refresh token for keyId: \(keyId)")
    }
    .store(in: &futureStore)
```

### 3. Enable biometric login

After the user has created a password, you can enable biometric access for the login. You will need the user's password and the userId from the refresh token to do this.

The `userId` can be retrieved from the refresh token: `TIM.auth.refreshToken?.userId` 

```swift
TIM.storage.enableBiometricAccessForRefreshToken(password: password, userId: userId)
    .sink(
        receiveCompletion: { (completion} in 
            switch result {
            case .finished:
                print("Successfully enabled biometric login for user.")
            case .failure(let error):
                print("Whoops, something went wrong: \(error.localizedDescription)")
            }
        },
        receiveValue: { _ in }
    )
    .store(in: &futureStore)
```

### 4. Login with password/biometrics

You have to provide the user ID for the user, that wishes to login (this allows multiple users to login on the same device).

The user can use biometrics if it was enabled previously, otherwise you will have to provide the password.
You can set a `storeNewRefreshToken` to control whether the system should update the refresh token on successful login. This is **highly recommended** to store the new refresh token, since it will keep renewing the user's session everytime they login. Although, you can set this to false, if you have cases where you don't want to update it. 

The same completion handling can be used for password and biometrics, as shown in the example below.

```swift
// Login with password
TIM.auth.loginWithPassword(userId: userId, password: password, storeNewRefreshToken: true)
    .sink(
        receiveCompletion: handleResultCompletion,
        receiveValue: { _ in })
    .store(in: &futureStore)
    

// Login with biometrics
TIM.auth.loginWithBiometricId(
    userId: userId, 
    storeNewRefreshToken: true, 
    willBeginNetworkRequests: {
        // BioID succeeded, show loading indicator -> TIM will initiate network requests right now. 
    })
    .sink(
        receiveCompletion: handleResultCompletion,
        receiveValue: { _ in })
    .store(in: &futureStore)

// Completion handling
func handleResultCompletion(_ completion: Subscribers.Completion<TIMError>) {
    switch completion {
    case .failure(let error):
        print("Failed to login: \(error.localizedDescription)")
        
        switch error {
        case .storage(let storageError):
            switch storageError {
            case .incompleteUserDataSet:
                // Reset user! We cannot recover from this state!
                break
            case .encryptedStorageFailed:
                // Note that this is a simplified error handling, which uses the Bool extensions to avoid huge switch statements.
                // If you want to handle errors the right way, you should look into all error cases and decide which you need specific
                // error handling for. The ones you see here are the most common ones, which are very likely to happen.
                if storageError.isWrongPassword() {
                    // Handle wrong password
                } else if storageError.isKeyLocked() {
                    // Handle key locked (three wrong password logins)
                } else if storageError.isBiometricFailedError() {
                    // Bio failed or was cancelled, do nothing.
                } else if storageError.isKeyServiceError() {
                    // Something went wrong while communicating with the key service (possible network failure)
                } else {
                    // Something failed - please try again.
                }
            }
        case .auth(let authError):
            if case TIMAuthError.refreshTokenExpired = authError {
                // Refresh Token has expired.
            }
        }
    case .finished:
        print("Successfully logged in!")
    }
}
```

### 5. Make use of the data and the session
#### JWT data
The tokens are of the type `JWT`, which is just a `typealias` for `String`. The framework has extensions for `JWT`, which allows you to get the following data directly from the token:
* **Expiration timestamp:** `token.expireTimestamp`
* **UserId:** `token.userId`

#### Users
The framework keeps track of the user's which has created passwords and stored encrypted refresh tokens.

The `TIM.storage.availableUserIds` will return a list of identifiers from the available refresh tokens (`sub` field). Any other data related to the user and the mapping between the ID and the user's data is your responsibilty. `TIM` will only keep track of the identifier from the token.

#### Refresh token

In most cases you won't have to worry about your refresh token, since the `TIM` methods are handling this for you. If you should be in a situation, where you  need it, is can be accessed from the `storage`:

```swift
storage.getStoredRefreshToken(userId: userId, password: password)
    .sink(
        receiveCompletion: { _ in },
        receiveValue: { (rt) in
          //Valid refresh token!
        })
    .store(in: &futureStorage)
```

#### Access token

`TIM` makes sure that your access token always is valid and refreshed automatically. This is also why the `TIM.auth.accessToken()` is a async function.

Most of the time `TIM` will complete the call immediately when the token is available, and a bit slower when the token needs to be updated.

You should avoid assigning the value of the access token to a property, and instead always use this function when you need it to make sure the token is valid.

```swift
TIM.auth.accessToken()
    .sink(
        receiveCompletion: { _ in },
        receiveValue: { [weak self] (at) in
          //Valid access token!
        })
    .store(in: &futureStorage)
```

### 6. Log out
You can log out a user, which will throw away the current access token and refresh token, such that you will have to load it again by logging in.

```swift
TIM.auth.logout()
```

### 7. Delete user
You can delete all data stored for a user identifier, such that the refresh token no longer will be available and the user won't exist in the `availableUserIds` set anymore. Typically you would also want to log out in this situation:

```swift
TIM.auth.logout() // Logout of current session
TIM.storage.clear(userId: theUserId) // Delete the stored user data
```

### 8. Enable background timeout
You can configure TIM to monitor the time the app has been in the background and make it log out automatically if the desired duration is exceeded.

    1. The user logs in (background monitor timeout is set to 5 minutes)
    2. The user sends the app to the background
    3. The user opens the app after 6 minutes
    4. TIM automatically calls logout, which invalidates the current session and invokes the timeout callback.
    
```swift
TIM.auth.enableBackgroundTimeout(durationSeconds: 60 * 5) {
    // Handle the user log out event, e.g. present login screen.
}
```

### Understanding the errors

`TIM` can throw a large set of errors, because of the different dependencies. Common for all errors it that they are wrapped in a `TIMError.auth()` or `TIMError.storage()` type depending on the area that throws the error. The errors will contain other errors coming from the stomach of the framework and there are a couple of levels in this.

Most errors are helping you as a developer to figure out, what you might have configured wrongly. Once everything is configured at setup correctly it is a small set of errors, which is important to handle as specific errors:

```swift
// Refresh token has expired
TIMError.auth(TIMAuthError.refreshTokenExpired)

// The user pressed cancel in the safari view controller during the OpenID Connect login
TIMError.auth(TIMAuthError.safariViewControllerCancelled)

TIMError.storage(
    TIMStorageError.encryptedStorageFailed(
        TIMEncryptedStorageError.keyServiceFailed(TIMKeyServiceError.badPassword)
    )
) 

TIMError.storage(
    TIMStorageError.encryptedStorageFailed(
        TIMEncryptedStorageError.keyServiceFailed(TIMKeyServiceError.keyLocked)
    )
) 
```

Since the `TIMKeyServiceError`s are so deeply into the error structure, there are short hands for this on the `TIMStorageError` type:

```swift
if storageError.isKeyLocked() {
    // Handle key locked (happens on wrong password three times in a row)
}
if storageError.isWrongPassword() {
    // Handle wrong password
}
if storageError.isKeyServiceError() {
    // The communication with the KeyService failed. E.g. no internet connection.
}
if storageError.isBiometricFailedError() {
    // Handle biometric failed/was cancelled scenario.
}
```

Other errors should of course still be handled, but can be handled in a more generic way, since they might be caused by network issues, server updates, or other unpredictable cases.

## Custom setup configuration

You can configure TIM with custom dependencies by injecting your own implementations of the defined protocols.
This is available for specific projects, which are running on custom made versions of TIM.

**DISCLAIMER:** This is *not* intended to be used with TIM hosted products. You better know what you are doing, if you go down this road 😅 

The following is an example of how to do a custom configuration of TIM dependencies with the default implementations.
By implementing the required protocols you can replace default implementations with your own.
  
```swift
let keyServiceConfig = TIMKeyServiceConfiguration(
    realmBaseUrl: "<TIM base URL>/auth/realms/<realm>",
    version: .v1
)
let openIdConfiguration = TIMOpenIDConfiguration(
    issuer: URL(string: "<TIM base URL>/auth/realms/<realm>")!,
    clientId: "<clientId>",
    redirectUri: URL(string: "<urlScheme>:/")!,
    scopes: [OIDScopeOpenID, OIDScopeProfile]
)

let encryptedStorage = TIMEncryptedStorage(
    secureStorage: TIMKeychain(),
    keyService: TIMKeyService(
        configuration: keyServiceConfig),
    encryptionMethod: .aesGcm
)
let dataStorage = TIMDataStorageDefault(encryptedStorage: encryptedStorage)
let auth = TIMAuthDefault(
    dataStorage: dataStorage,
    openIdController: AppAuthController(openIdConfiguration),
    backgroundMonitor: TIMAppBackgroundMonitorDefault()
)
TIM.configure(
    dataStorage: dataStorage,
    auth: auth,
    customLogger: TIMLogger()
)
```

The above custom configuration is equivalent to this default configuration:
```swift
let config = TIMConfiguration(
    timBaseUrl: URL(string: "<TIM base URL>")!,
    realm: "<realm>",
    clientId: "<clientId>",
    redirectUri: URL(string: "<urlScheme>:/")!,
    scopes: [OIDScopeOpenID, OIDScopeProfile],
    encryptionMethod: .aesGcm
)
TIM.configure(configuration: config)
```

## Architecture

`TIM` depends on `AppAuth` and `TIMEncryptedStorage` and wraps their use for common use cases (see sections above), such that registering, login and encrypted storage is easy to manage.

#### Storage
The `TIM.storage: TIMDataStorage` handles all storage operations in terms of encrypted and raw data to a secure storage (default is the iOS Keychain).

This heavily depends on the `TIMEncryptedStorage` package, which communicates with the TIM KeyService, to handle encryption based on a user selected password and biometric access if enabled.

#### Auth
The `TIM.auth: TIMAuth` handles all OpenID Connect operations through the `AppAuth` framework. The main purpose of this is to handle access and refresh tokens and renewal of both. `TIMAuth` depends on the `TIMDataStorage` to store new refresh tokens. 

### TIMEncryptedStorage
`TIM` depends on `TIMEncryptedStorage` for encrypted data storage and access via TouchID/FaceID:
https://github.com/trifork/TIMEncryptedStorage-iOS

### AppAuth
`TIM` depends on `AppAuth` for OpenID Connect operations:
https://github.com/openid/AppAuth-iOS

## Testing

`TIM` is designed to be testable, such that you can mock the parts of the framework, that you would like to. The framework contains a custom `configure` method, which allows you to fully customise the inner implementations of the framework:
```swift
TIM.configure(dataStorage: TIMDataStorage, auth: TIMAuth, customLogger: TIMLoggerProtocol?)
```
Every dependency in `TIM` is build upon protocols, such that you can implement your own mock-classes for testing. 

⚠️ **NOTE:** This `configure` method allows you to change the `TIM` behaviour. We strongly recommend that you only use the above `configure` method for testing!

---

![Trifork Logo](https://jira.trifork.com/s/-p6q4kx/804003/9c3efa9da3fa1ef9d504f68de6c57528/_/jira-logo-scaled.png)
