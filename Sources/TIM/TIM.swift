import UIKit
import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

public typealias AccessTokenCallback = (Result<JWT, TIMError>) -> Void
public typealias StatusCallback = (Result<Void, TIMError>) -> Void


/// This class is divided into two namespaces: `storage` and `auth`
///
/// OpenID Connect (AppAuth) operations are done through the `auth` namespace and storing secure data is done through the `storage` namespace.
public final class TIM {

    /// Optional logger. Set to `nil` to stop logging
    public static var logger: TIMLoggerProtocol?

    /// Handles all secure storage operations and interfaces with the key service.
    public static var storage: TIMDataStorage {
        if let storageInstance = _storage {
            return storageInstance
        } else {
            fatalError("You have to call the `configure(configuration:)` method before using TIM.auth!")
        }
    }
    private static var _storage: TIMDataStorage?

    /// Handles all authentication through OpenID Connect (AppAuth).
    ///
    /// This also know the storage namespace and will load and store things.
    public static var auth: TIMAuth {
        if let authInstance = _auth {
            return authInstance
        } else {
            fatalError("You have to call the `configure(configuration:)` method before using TIM.auth!")
        }
    }
    private static var _auth: TIMAuth?

    /// Configures the `TIM` class with default instances based on your configuration.
    /// This should be called before any other function or property is called on this class.
    ///
    /// This is the recommended configure method of `TIM`.
    ///
    /// - Parameters:
    ///   - configuration: TIMConfiguration
    ///   - customLogger: An optional custom logger for logging messages internally from `TIM`. Set to `nil` to disable logging.
    public static func configure(configuration: TIMConfiguration, customLogger: TIMLoggerProtocol? = TIMLogger()) {
        let encryptedStorage = TIMEncryptedStorage(
            secureStorage: TIMKeychain(),
            keyService: TIMKeyService(configuration: configuration.keyServiceConfiguration),
            encryptionMethod: configuration.encryptionMethod
        )
        let storage = TIMDataStorageInternal(encryptedStorage: encryptedStorage)
        _auth = TIMAuthInternal(
            dataStorage: storage,
            openIdController: AppAuthController(configuration.oidcConfiguration)
        )
        _storage = storage
        logger = customLogger ?? TIMLogger()
    }

    /// Configures the `TIM` class with custom instances of the interfaces.
    ///
    /// This can be useful when mocking for testing or other very custom scenarios.
    ///
    /// **THIS IS NOT THE USUAL WAY TO CONFIGURE TIM**
    ///
    /// See `configure(configuration:)` for the default configuration method.
    ///
    /// - Parameters:
    ///   - dataStorage: The data storage instance to use.
    ///   - auth: The auth
    ///   - customLogger: An optional custom logger for logging messages internally from `TIM`. Set to `nil` to disable logging.
    public static func configure(dataStorage: TIMDataStorage, auth: TIMAuth, customLogger: TIMLoggerProtocol?) {
        _auth = auth
        _storage = dataStorage
        logger = customLogger
    }
}


/// Auth protocol
public protocol TIMAuth {

    /// Indicates whether the user as a valid auth state
    var isLoggedIn: Bool { get }

    /// Gets the refresh token from the current session if available
    var refreshToken: JWT? { get }

    /// Logs out the user of the current session, clearing the auth state with active tokens.
    func logout()

    /// Handles redirect from the `SFSafariViewController`. The return value determines whether the URL was handled by TIM.
    /// - Parameter url: The url that was directed to the app.
    @discardableResult
    func handleRedirect(url: URL) -> Bool

    /// Gets the current access token from the current session if available.
    /// This will automatically renew the access token if necessary (by using the refresh token)
    /// - Parameter completion: Invoked when access token is available / failed
    @available(iOS, deprecated: 13)
    func accessToken(_ completion: @escaping AccessTokenCallback)

    /// Performs OAuth login with OpenID Connect by presenting a `SFSafariViewController` on the `presentingViewController`
    ///
    /// The `refreshToken` property will be available after this, which can be used to encrypt and store it in the secure store by the `storage` namespace.
    /// - Parameters:
    ///   - presentingViewController: The view controller which the safari view controller should be presented on.
    ///   - completion: Invoked with access token after successful login (or with error)
    @available(iOS, deprecated: 13)
    func performOpenIDConnectLogin(presentingViewController: UIViewController, completion: @escaping AccessTokenCallback)

    /// Logs in using password. This can only be done if the user has stored the refresh token with a password after calling `performOpenIDConnectLogin`.
    /// - Parameters:
    ///   - userId: The userId of the user (can be found in the access token or refresh token)
    ///   - password: The password that was used when the refresh token was stored.
    ///   - storeNewRefreshToken: `true` if it should store the new refresh token, and `false` if not. Most people will need this as `true`
    ///   - completion: Invoked with the access token when the login was successful or an error if it fails.
    @available(iOS, deprecated: 13)
    func loginWithPassword(userId: String, password: String, storeNewRefreshToken: Bool, completion: @escaping AccessTokenCallback)

    /// Logs in using biometric login. This can only be done if the user has stored the refresh token with a password after calling `performOpenIDConnectLogin` AND enabled biometric protection for it.
    /// - Parameters:
    ///   - userId: The userId of the user (can be found in the access token or refresh token)
    ///   - storeNewRefreshToken: `true` if it should store the new refresh token, and `false` if not. Most people will need this as `true`
    ///   - completion: Invoked with the access token when the login was successful or an error if it fails.
    @available(iOS, deprecated: 13)
    func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool, completion: @escaping AccessTokenCallback)

    // MARK: - Combine wrappers

    #if canImport(Combine)
    /// Combine wrapper of `accessToken(_:)`
    @available(iOS 13, *)
    func accessToken() -> Future<JWT, TIMError>

    /// Combine wrapper of `performOpenIDConnectLogin(presentingViewController:completion:)`
    @available(iOS 13, *)
    func performOpenIDConnectLogin(presentingViewController: UIViewController) -> Future<JWT, TIMError>

    /// Combine wrapper of `loginWithPassword(userId:password:storeNewRefreshToken:completion:)`
    @available(iOS 13, *)
    func loginWithPassword(userId: String, password: String, storeNewRefreshToken: Bool) -> Future<JWT, TIMError>

    /// Combine wrapper of `loginWithBiometricId(userId:storeNewRefreshToken:completion:)`
    @available(iOS 13, *)
    func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool) -> Future<JWT, TIMError>
    #endif
}


/// Data Storage protocol
public protocol TIMDataStorage {

    /// A set of userIds, which there are refresh tokens stored for.
    var availableUserIds: Set<String> { get }

    /// Checks whether a `userId` has stored a refresh token.
    /// - Parameter userId: The userId from the refresh token
    func hasRefreshToken(userId: String) -> Bool

    /// Checks whether a `userId` has stored a refresh token with biometric protection access.
    /// - Parameter userId: The userId from the refresh token
    func hasBiometricAccessForRefreshToken(userId: String) -> Bool

    /// Disables biometric protection access for refresh token.
    /// - Parameter userId: The `userId` for the refresh token.
    func disableBiometricAccessForRefreshToken(userId: String)


    /// Clears all securely stored data for `userId`
    /// - Parameter userId: The `userId`.
    func clear(userId: String)

    // MARK: -

    /// Gets a stored refresh token for a `userId` and a `password`
    /// - Parameters:
    ///   - userId: The `userId` from the refresh token
    ///   - password: The password that was used to store it.
    ///   - completion: Invoked when the refresh token is loaded or the system fails to load it.
    @available(iOS, deprecated: 13)
    func getStoredRefreshToken(userId: String, password: String, completion: @escaping (Result<JWT, TIMError>) -> Void)


    /// Gets a stored refresh token with biometric protection for a `userId`.
    /// - Parameters:
    ///   - userId: The `userId` from the refresh token
    ///   - completion: Invoked when the refresh token is loaded or the system fails to load it. The result contains the `longSecret`, which was used as secret from the biometric secure store.
    @available(iOS, deprecated: 13)
    func getStoredRefreshTokenViaBiometric(userId: String, completion: @escaping (Result<BiometricRefreshToken, TIMError>) -> Void)

    /// Stores refresh token with existing password.
    /// - Parameters:
    ///   - refreshToken: The refresh token.
    ///   - password: The password that already has a encryption key.
    ///   - completion: Invoked when the refresh token is stored or the system fails to store it.
    @available(iOS, deprecated: 13)
    func storeRefreshToken(_ refreshToken: JWT, withExistingPassword password: String, completion: @escaping (Result<Void, TIMError>) -> Void)

    /// Stores refresh token with a new password and removes current biometric access for potential previous refresh token.
    /// - Parameters:
    ///   - refreshToken: The refresh token.
    ///   - newPassword: The new password that needs a new encryption key.
    ///   - completion: Invoked when the refresh token is stored or the system fails to store it.
    @available(iOS, deprecated: 13)
    func storeRefreshToken(_ refreshToken: JWT, withNewPassword newPassword: String, completion: @escaping (Result<TIMESKeyCreationResult, TIMError>) -> Void)


    /// Enables biometric protection access for refresh token.
    /// - Parameters:
    ///   - password: The password that was used to store the refresh token.
    ///   - userId: The `userId` for the refresh token.
    ///   - completion: Invoked when the biometric protection access is enabled or the system fails to enable it.
    @available(iOS, deprecated: 13)
    func enableBiometricAccessForRefreshToken(password: String, userId: String, completion: @escaping (Result<Void, TIMError>) -> Void)

    /// Enables biometric protection access for refresh token using longSecret.
    ///
    /// This method should only be used for older versions of the key service, where GET Key responses doesn't contain the `longSecret`.
    /// - Parameters:
    ///   - longSecret: The long secret that was created upon creation of the password.
    ///   - userId: The `userId` for the refresh token.
    func enableBiometricAccessForRefreshToken(longSecret: String, userId: String) -> Result<Void, TIMError>


    /// Stores a refresh token using long secret instead of password.
    /// It is unlikely, that you will need to use this method, unless you are doing something custom. TIM does use this method internally to keep refresh tokens up-to-date even when logging in with biometric access.
    ///
    /// - Parameters:
    ///   - refreshToken: The refresh token.
    ///   - longSecret: The long secret (can be obtained via biometric access)
    ///   - completion: Invoked when the refresh token is stored or when the operation fails.
    func storeRefreshTokenWithLongSecret(_ refreshToken: JWT, longSecret: String, completion: @escaping (Result<Void, TIMError>) -> Void)

    // MARK: - Combine wrappers
    #if canImport(Combine)
    /// Combine wrapper of `getStoredRefreshToken(userId:password:completion:)`
    @available(iOS 13, *)
    func getStoredRefreshToken(userId: String, password: String) -> Future<JWT, TIMError>

    /// Combine wrapper of `getStoredRefreshTokenViaBiometric(userId:completion:`
    @available(iOS 13, *)
    func getStoredRefreshTokenViaBiometric(userId: String) -> Future<BiometricRefreshToken, TIMError>

    /// Combine wrapper of `storeRefreshToken(_:withExistingPassword:completion:)`
    @available(iOS 13, *)
    func storeRefreshToken(_ refreshToken: JWT, withExistingPassword password: String) -> Future<Void, TIMError>

    /// Combine wrapper of `storeRefreshToken(_:withNewPassword:completion:)`
    @available(iOS 13, *)
    func storeRefreshToken(_ refreshToken: JWT, withNewPassword newPassword: String) -> Future<TIMESKeyCreationResult, TIMError>

    /// Combine wrapper of `enableBiometricAccessForRefreshToken(password:userId:completion:)`
    @available(iOS 13, *)
    func enableBiometricAccessForRefreshToken(password: String, userId: String) -> Future<Void, TIMError>

    /// Combine wrapper of `storeRefreshTokenWithLongSecret(_:longSecret:completion:)`
    @available(iOS 13, *)
    func storeRefreshTokenWithLongSecret(_ refreshToken: JWT, longSecret: String) -> Future<Void, TIMError>
    #endif
}
