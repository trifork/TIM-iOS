import Foundation
import AppAuth
import TIMEncryptedStorage

/// Shared wrapper for Auth and Storage errors.
public enum TIMError: Error, LocalizedError {
    case auth(TIMAuthError)
    case storage(TIMStorageError)

    public var errorDescription: String? {
        switch self {
        case .auth(let error):
            return error.localizedDescription
        case .storage(let error):
            return error.localizedDescription
        }
    }
}

/// Errors related to AppAuth operations
public enum TIMAuthError: Error, LocalizedError {
    //TODO consider renaming this to "missingLogin" or alike which communicates the real issue.
    case authStateNil(stacktrace: [String] = Thread.callStackSymbols)
    case failedToDiscoverConfiguration
    case failedToBeginAuth
    case failedToGetAccessToken
    case failedToGetRefreshToken
    case networkError
    case refreshTokenExpired
    case appAuthFailed(Error?)
    case safariViewControllerCancelled
    case failedToGetRequiredDataInToken
    case failedToValidateIDToken

    public var errorDescription: String? {
        switch self {
        case .authStateNil(let stacktrace):
            return "The AuthState was nil, when it wasn't expected to be. Are you trying to get the access token, when there was no valid session? (stacktrace: \(stacktrace))"
        case .failedToDiscoverConfiguration:
            return "Failed to discover the configuration on the server. Check your configuration setup and try again."
        case .failedToBeginAuth:
            return "AppAuth returned a weird state, while we tried to begin the authentication."
        case .failedToGetAccessToken:
            return "Failed to get the access token."
        case .failedToGetRefreshToken:
            return "Failed to get the refresh token."
        case .networkError:
            return "Network error caused by AppAuth"
        case .refreshTokenExpired:
            return "The refresh token has expired."
        case .appAuthFailed(let error):
            return "Something went wrong in the AppAuth framework: \(error?.localizedDescription ?? "nil")"
        case .safariViewControllerCancelled:
            return "The user cancelled OpenID connect login via SafariViewController"
        case .failedToGetRequiredDataInToken:
            return "TIM did not find the required data (userId) in the token. The 'sub' property must be present in the token!"
        case .failedToValidateIDToken:
            return "AppAuth failed to validate the ID Token. This will happen if the client's time is more than 10 minutes off the current time."
        }
    }

    static func mapAppAuthError(_ error: Error?) -> TIMAuthError {
        guard let error = error as NSError? else {
            return .appAuthFailed(nil)
        }

        if error.domain == OIDGeneralErrorDomain {
            switch error.code {
            case OIDErrorCode.networkError.rawValue: return .networkError
            case OIDErrorCode.idTokenFailedValidationError.rawValue: return .failedToValidateIDToken
            default: return .appAuthFailed(error)
            }
        } else if error.domain == OIDOAuthTokenErrorDomain {
            switch error.code {
            case OIDErrorCodeOAuth.invalidGrant.rawValue: return .refreshTokenExpired
            default: return .appAuthFailed(error)
            }
        }

        return .appAuthFailed(error)
    }

    /// Tells whether the error was a `.safariViewControllerCancelled` or not.
    public func isSafariViewControllerCancelled() -> Bool {
        switch self {
        case .safariViewControllerCancelled:
            return true
        default:
            return false
        }
    }
}

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
