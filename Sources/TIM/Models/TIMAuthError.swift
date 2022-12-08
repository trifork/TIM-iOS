import Foundation
import AppAuth
import TIMEncryptedStorage

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
        
        switch error.domain {
        case OIDGeneralErrorDomain:
            switch error.code {
                case OIDErrorCode.networkError.rawValue: return .networkError
                case OIDErrorCode.idTokenFailedValidationError.rawValue: return .failedToValidateIDToken
                default: break
            }
        case OIDOAuthTokenErrorDomain:
            switch error.code {
                case OIDErrorCodeOAuth.invalidGrant.rawValue: return .refreshTokenExpired
                default: break
            }
        default: break
        }
        
        return .appAuthFailed(error)
    }

    /// Tells whether the error was a `.safariViewControllerCancelled` or not.
    public func isSafariViewControllerCancelled() -> Bool {
        if case .safariViewControllerCancelled  = self {
           return true
        }
        return false
    }
}
