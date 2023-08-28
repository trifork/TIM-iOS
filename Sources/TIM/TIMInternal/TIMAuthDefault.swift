import UIKit
import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

public class TIMAuthDefault : TIMAuth {

    private let storage: TIMDataStorage
    private let openIdController: OpenIDConnectController
    private let backgroundMonitor: TIMAppBackgroundMonitor

    public init(dataStorage: TIMDataStorage, openIdController: OpenIDConnectController, backgroundMonitor: TIMAppBackgroundMonitor) {
        self.storage = dataStorage
        self.openIdController = openIdController
        self.backgroundMonitor = backgroundMonitor
    }

    public var isLoggedIn: Bool {
        return openIdController.isLoggedIn
    }

    public var refreshToken: JWT? {
        return openIdController.refreshToken()
    }

    public func logout() {
        openIdController.logout()
    }

    @discardableResult
    public func handleRedirect(url: URL) -> Bool {
        openIdController.handleRedirect(url: url)
    }
}

// MARK: - Actual callback implementations

/// Actual implementation using callbacks.
/// From iOS 13 these are still used, but wrapped in a Combine interface with `Future`.
@available(iOS, deprecated: 13)
extension TIMAuthDefault {
    public func accessToken(forceRefresh: Bool, _ completion: @escaping AccessTokenCallback) {
        openIdController.accessToken(forceRefresh: forceRefresh) { (result: Result<JWT, TIMAuthError>) in
            completion(result.mapError({ TIMError.auth($0) }))
        }
    }
    
    public func performOpenIDConnectLogin(presentingViewController: UIViewController, authorizationRequestNonce: String? = nil, completion: @escaping AccessTokenCallback) {
        openIdController.login(
            presentingViewController: presentingViewController,
            completion: { (result: Result<JWT, TIMAuthError>) in
                completion(result.mapError({ TIMError.auth($0) }))
            },
            didCancel: {
                completion(.failure(TIMError.auth(.safariViewControllerCancelled)))
            },
            willPresentSafariViewController: nil,
            shouldAnimate: nil,
            authorizationRequestNonce: authorizationRequestNonce
        )
    }
    
    public func performOpenIDConnectLogin(authorizationRequestNonce: String?, completion: @escaping AccessTokenCallback) {
        openIdController.login(
            presentingViewController: nil,
            completion: { (result: Result<JWT, TIMAuthError>) in
                completion(result.mapError({ TIMError.auth($0) }))
            },
            didCancel: {
                completion(.failure(TIMError.auth(.safariViewControllerCancelled)))
            },
            willPresentSafariViewController: nil,
            shouldAnimate: nil,
            authorizationRequestNonce: authorizationRequestNonce
        )
    }

    public func loginWithPassword(userId: String, password: String, storeNewRefreshToken: Bool = true, completion: @escaping AccessTokenCallback) {
        storage.getStoredRefreshToken(userId: userId, password: password) { (result: Result<JWT, TIMError>) in
            switch result {
            case .success(let refreshJWT):
                self.openIdController.silentLogin(refreshToken: refreshJWT) { (result: Result<JWT, TIMAuthError>) in
                    switch result {
                    case .success(let accessJWT):
                        if let newRefreshToken = self.openIdController.refreshToken() {
                            TIM.logger?.log("Did get access token: %@", accessJWT.token)
                            if storeNewRefreshToken {
                                self.storage.storeRefreshToken(newRefreshToken, withExistingPassword: password) { (result) in
                                    switch result {
                                    case .success:
                                        completion(.success(accessJWT))
                                    case .failure(let error):
                                        TIM.logger?.log("Failed to store refresh token after silent login: %@", error.localizedDescription)
                                        completion(.failure(error))
                                    }
                                }
                            } else {
                                completion(.success(accessJWT))
                            }
                        } else {
                            TIM.logger?.log("Failed to get access and refresh token via silent login.")
                            completion(.failure(.auth(TIMAuthError.failedToGetRefreshToken)))
                        }
                    case .failure(let error):
                        TIM.logger?.log("Silent login error: %@", error.localizedDescription)
                        completion(.failure(.auth(error)))
                    }
                }
            case .failure(let error):
                TIM.logger?.log("Failed to get refresh token for userId: %@", error.localizedDescription)
                completion(.failure(error))
            }
        }
    }

    public func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool = true, willBeginNetworkRequests: WillBeginNetworkRequestsCallback?, completion: @escaping AccessTokenCallback) {
        storage.getStoredRefreshTokenViaBiometric(userId: userId, willBeginNetworkRequests: willBeginNetworkRequests) { (result) in
            switch result {
            case .success(let bioResult):
                self.openIdController.silentLogin(refreshToken: bioResult.refreshToken) { (result: Result<JWT, TIMAuthError>) in
                    switch result {
                    case .success(let accessToken):
                        if let newRefreshToken = self.openIdController.refreshToken() {
                            TIM.logger?.log("Did get access token: %@", accessToken.token)
                            if storeNewRefreshToken {
                                self.storage.storeRefreshTokenWithLongSecret(
                                    newRefreshToken,
                                    longSecret: bioResult.longSecret) { (result) in
                                    switch result {
                                    case .success:
                                        completion(.success(accessToken))
                                    case .failure(let error):
                                        TIM.logger?.log("Failed to store refresh token after silent login: %@", error.localizedDescription)
                                        completion(.failure(error))
                                    }
                                }
                            } else {
                                completion(.success(accessToken))
                            }
                        } else {
                            TIM.logger?.log("Failed to get access and refresh token via silent login.")
                            completion(.failure(.auth(.failedToGetRefreshToken)))
                        }
                    case .failure(let error):
                        TIM.logger?.log("Silent login error: %@", error.localizedDescription)
                        completion(.failure(.auth(error)))
                    }
                }
            case .failure(let error):
                TIM.logger?.log("Failed to get refresh token for userId: %@", error.localizedDescription)
                completion(.failure(error))
            }
        }
    }

    public func enableBackgroundTimeout(durationSeconds: TimeInterval, timeoutHandler: @escaping () -> Void) {
        backgroundMonitor.enable(durationSeconds: durationSeconds, timeoutHandler: { [weak self] in
            if self?.isLoggedIn == true {
                self?.logout()
                timeoutHandler()
            }
        })
    }

    public func disableBackgroundTimeout() {
        backgroundMonitor.disable()
    }
}

