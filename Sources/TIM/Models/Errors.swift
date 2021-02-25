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
    case authStateNil
    case failedToDiscoverConfiguration
    case failedToBeginAuth
    case failedToGetAccessToken
    case failedToGetRefreshToken
    case networkError
    case refreshTokenExpired
    case appAuthFailed(Error?)

    public var errorDescription: String? {
        switch self {
        case .authStateNil:
            return "The AuthState was nil, when it wasn't expected to be. Are you trying to get the access token, when there was no valid session?"
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
        }
    }

    static func mapAppAuthError(_ error: Error?) -> TIMAuthError {
        guard let error = error as NSError? else {
            return .appAuthFailed(nil)
        }

        if error.domain == OIDGeneralErrorDomain {
            switch error.code {
            case OIDErrorCode.networkError.rawValue: return .networkError
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
}

/// Errors related to storage operations
public enum TIMStorageError: Error, LocalizedError {
    case encryptedStorageFailed(TIMEncryptedStorageError)

    public var errorDescription: String? {
        switch self {
        case .encryptedStorageFailed(let error):
            return "The encrypted storage failed: \(error.localizedDescription)"
        }
    }

    public func isKeyLocked() -> Bool {
        isKeyServiceError(.keyLocked)
    }

    public func isWrongPassword() -> Bool {
        isKeyServiceError(.badPassword)
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
        default:
            isKeyServiceError = false
        }
        return isKeyServiceError
    }
}
