import UIKit
import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

class TIMAuthInternal : TIMAuth {

    private let storage: TIMDataStorage
    private let openIdController: OpenIDConnectController
    let backgroundMonitor: TIMAppBackgroundMonitor

    init(dataStorage: TIMDataStorage, openIdController: OpenIDConnectController, backgroundMonitor: TIMAppBackgroundMonitor) {
        self.storage = dataStorage
        self.openIdController = openIdController
        self.backgroundMonitor = backgroundMonitor
    }

    var isLoggedIn: Bool {
        return openIdController.isLoggedIn
    }

    var refreshToken: JWT? {
        return openIdController.refreshToken()
    }

    func logout() {
        openIdController.logout()
    }

    @discardableResult
    func handleRedirect(url: URL) -> Bool {
        openIdController.handleRedirect(url: url)
    }
}

// MARK: - Actual callback implementations

/// Actual implementation using callbacks.
/// From iOS 13 these are still used, but wrapped in a Combine interface with `Future`.
@available(iOS, deprecated: 13)
extension TIMAuthInternal {
    func accessToken(_ completion: @escaping AccessTokenCallback) {
        openIdController.accessToken(forceRefresh: false) { (result: Result<JWT, TIMAuthError>) in
            completion(result.mapError({ TIMError.auth($0) }))
        }
    }

    func performOpenIDConnectLogin(presentingViewController: UIViewController, completion: @escaping AccessTokenCallback) {
        openIdController.login(
            presentingViewController: presentingViewController,
            completion: { (result: Result<JWT, TIMAuthError>) in
                completion(result.mapError({ TIMError.auth($0) }))
            },
            didCancel: {
                completion(.failure(TIMError.auth(.safariViewControllerCancelled)))
            },
            willPresentSafariViewController: nil,
            shouldAnimate: nil
        )
    }

    func loginWithPassword(userId: String, password: String, storeNewRefreshToken: Bool = true, completion: @escaping AccessTokenCallback) {
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

    func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool = true, completion: @escaping AccessTokenCallback) {
        storage.getStoredRefreshTokenViaBiometric(userId: userId) { (result) in
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
}

//MARK: - Combine wrappers
#if canImport(Combine)
@available(iOS 13, *)
extension TIMAuthInternal {
    func accessToken() -> Future<JWT, TIMError> {
        Future { promise in
            self.accessToken(promise)
        }
    }

    func performOpenIDConnectLogin(presentingViewController: UIViewController) -> Future<JWT, TIMError> {
        Future { promise in
            self.performOpenIDConnectLogin(presentingViewController: presentingViewController, completion: promise)
        }
    }

    func loginWithPassword(userId: String, password: String, storeNewRefreshToken: Bool) -> Future<JWT, TIMError> {
        Future { promise in
            self.loginWithPassword(userId: userId, password: password, completion: promise)
        }
    }

    func loginWithBiometricId(userId: String, storeNewRefreshToken: Bool) -> Future<JWT, TIMError> {
        Future { promise in
            self.loginWithBiometricId(userId: userId, storeNewRefreshToken: storeNewRefreshToken, completion: promise)
        }
    }
}
#endif
