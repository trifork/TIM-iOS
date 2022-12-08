import Foundation
import AppAuth
import TIMEncryptedStorage

/// Errors related to storage operations
public enum TIMStorageError: Error, LocalizedError {
    case encryptedStorageFailed(TIMEncryptedStorageError)

    // This error was implemented because we discovered missing keyIds for some users, where the user was cleared while waiting for response with a new refreshToken
    case incompleteUserDataSet

    public var errorDescription: String? {
        switch self {
        case .encryptedStorageFailed(let error):
            return "The encrypted storage failed: \(error.localizedDescription)"
        case .incompleteUserDataSet:
            return "Attempt to store a refresh token for a user, that does not have a valid data set. This can happen if you clear the user data while waiting for a login (which definitely should be avoided!). The invalid data has now been cleared from the framework. The user will have to perform OIDC login again."
        }
    }

    public func isKeyLocked() -> Bool {
        isKeyServiceError(.keyLocked)
    }

    public func isWrongPassword() -> Bool {
        isKeyServiceError(.badPassword)
    }

    public func isBiometricFailedError() -> Bool {
        switch self {
        case .encryptedStorageFailed(let storageError):
            switch storageError {
            case .secureStorageFailed(let secureStorageError) where secureStorageError == .authenticationFailedForData:
                return true
            default:
                return false
            }
        case .incompleteUserDataSet:
            return false
        }
    }

    /// Determines whether this error is an error thrown by the KeyService.
    ///
    /// This might be useful for handling unexpected cases from the encryption part of the framework.
    /// When the key service fails you don't want to do any drastic fallback, since the server might "just" be down or the user have no internet connection. You will be able to recover later on, from a key service error.
    public func isKeyServiceError() -> Bool {
        isKeyServiceError(nil)
    }

    /// Determines whether this error is a specific kind of key service error.
    /// - Parameter keyServiceError: The key service error to look for. If `nil` is passed it will look for any kind of key service error.
    private func isKeyServiceError(_ keyServiceError: TIMKeyServiceError?) -> Bool {
        let isKeyServiceError: Bool
        switch self {
        case .encryptedStorageFailed(let error):
            if case TIMEncryptedStorageError.keyServiceFailed(let ksError) = error {
                if let keyServiceError = keyServiceError {
                    isKeyServiceError = ksError == keyServiceError
                } else {
                    isKeyServiceError = true // Is any kind of key service error!
                }
            } else {
                isKeyServiceError = false
            }
        case .incompleteUserDataSet:
            isKeyServiceError = false
        }
        return isKeyServiceError
    }
}
