import Foundation
import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

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
