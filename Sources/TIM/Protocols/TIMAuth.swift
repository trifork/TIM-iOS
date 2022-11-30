import UIKit
#if canImport(Combine)
import Combine
#endif

public typealias WillBeginNetworkRequestsCallback = () -> Void
public typealias AccessTokenCallback = (Result<JWT, TIMError>) -> Void

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
    /// - Parameter forceRefresh: Force refresh an access token
    /// - Parameter completion: Invoked when access token is available / failed
    @available(iOS, deprecated: 13)
    func accessToken(forceRefresh: Bool, _ completion: @escaping AccessTokenCallback)
    
    /// Performs OAuth login with OpenID Connect by presenting a `SFSafariViewController` on the `presentingViewController`
    ///
    /// The `refreshToken` property will be available after this, which can be used to encrypt and store it in the secure store by the `storage` namespace.
    /// - Parameters:
    ///   - presentingViewController: The view controller which the safari view controller should be presented on.
    ///   - completion: Invoked with access token after successful login (or with error)
    @available(iOS, deprecated: 13)
    func performOpenIDConnectLogin(presentingViewController: UIViewController, authorizationRequestNonce: String?, completion: @escaping AccessTokenCallback)

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
    ///   - willBeginNetworkRequests: Invoked right after the biometric verification has succeeded and before the first network request is performed. Useful to show a loading indicator before the loading begins.
    ///   - completion: Invoked with the access token when the login was successful or an error if it fails.
    @available(iOS, deprecated: 13)
    func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool, willBeginNetworkRequests: WillBeginNetworkRequestsCallback?, completion: @escaping AccessTokenCallback)


    /// Enables timeout feature for when the app is in the background. The timeout will clear all current user session data within `TIM`.
    /// The timeoutHandler will be invoked when the app becomes active, iff the app has been in the background longer than the specified duration and the user is logged in.
    /// - Parameters:
    ///   - durationSeconds: The duration in seconds to timeout for.
    ///   - timeoutHandler: A handler
    @available(iOS, deprecated: 13)
    func enableBackgroundTimeout(durationSeconds: TimeInterval, timeoutHandler: @escaping () -> Void)

    /// Disables the background timeout
    func disableBackgroundTimeout()
}

/// Default parameters
public extension TIMAuth {
    /// Wrapper of `performOpenIDConnectLogin(presentingViewController:completion:authorizationRequestNonce)` adding nil as default value for authorizationRequestNonce
    func performOpenIDConnectLogin(presentingViewController: UIViewController, completion: @escaping AccessTokenCallback) {
        self.performOpenIDConnectLogin(presentingViewController: presentingViewController, authorizationRequestNonce: nil, completion: completion)
    }
}


public extension TIMAuth {
    /// Gets the current access token from the current session if available.
    /// This will automatically renew the access token if necessary (by using the refresh token)
    /// - Parameter completion: Invoked when access token is available / failed
    @available(iOS, deprecated: 13)
    func accessToken(_ completion: @escaping AccessTokenCallback) {
        accessToken(forceRefresh: false, completion)
    }
}

#if canImport(Combine)
/// Combine wrappers
public extension TIMAuth {
    /// Combine wrapper of `accessToken(_:)`
    @available(iOS 13, *)
    func accessToken(forceRefresh: Bool = false) -> Future<JWT, TIMError> {
        Future { promise in
            self.accessToken(forceRefresh: forceRefresh, promise)
        }
    }

    /// Combine wrapper of `performOpenIDConnectLogin(presentingViewController:completion:authorizationRequestNonce)`
    @available(iOS 13, *)
    func performOpenIDConnectLogin(presentingViewController: UIViewController, authorizationRequestNonce: String? = nil) -> Future<JWT, TIMError> {
        Future { promise in
            self.performOpenIDConnectLogin(presentingViewController: presentingViewController, authorizationRequestNonce: authorizationRequestNonce, completion: promise)
        }
    }

    /// Combine wrapper of `loginWithPassword(userId:password:storeNewRefreshToken:completion:)`
    @available(iOS 13, *)
    func loginWithPassword(userId: String, password: String, storeNewRefreshToken: Bool) -> Future<JWT, TIMError> {
        Future { promise in
            self.loginWithPassword(userId: userId, password: password, storeNewRefreshToken: storeNewRefreshToken, completion: promise)
        }
    }

    /// Combine wrapper of `loginWithBiometricId(userId:storeNewRefreshToken:completion:)`
    @available(iOS 13, *)
    func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool, willBeginNetworkRequests: WillBeginNetworkRequestsCallback?) -> Future<JWT, TIMError> {
        Future { promise in
            self.loginWithBiometricId(userId: userId, storeNewRefreshToken: storeNewRefreshToken, willBeginNetworkRequests: willBeginNetworkRequests, completion: promise)
        }
    }

    /// Combine wrapper of `enableBackgroundTimeout(durationSeconds:timeoutHandler:)`
    @available(iOS 13, *)
    func enableBackgroundTimeout(durationSeconds: TimeInterval) -> AnyPublisher<Void, Never> {
        let subject = PassthroughSubject<Void, Never>()
        enableBackgroundTimeout(durationSeconds: durationSeconds) {
            subject.send(Void())
        }
        return subject.eraseToAnyPublisher()
    }
}
#endif

