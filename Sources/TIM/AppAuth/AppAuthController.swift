import UIKit
import AppAuth
import SafariServices

final class AppAuthController {
    static let shared = AppAuthController()

    private var currentAuthorizationFlow: OIDExternalUserAgentSession? = nil

    private var authState: OIDAuthState?

    private var _credentials: TIMOpenIDConfiguration?
    private (set) var credentials: TIMOpenIDConfiguration {
        get {
            guard let cred = _credentials else {
                fatalError("No credentials were configured for AppAuthController.")
            }
            return cred
        }
        set {
            _credentials = newValue
        }
    }

    var isLoggedIn: Bool {
        authState != nil
    }

    private init() {

    }

    func configure(_ credentials: TIMOpenIDConfiguration) {
        self.credentials = credentials
    }

    private func discoverConfiguration(completion: @escaping (Result<OIDServiceConfiguration, TIMAuthError>) -> Void) {
        OIDAuthorizationService.discoverConfiguration(forIssuer: credentials.issuer) { [weak self] (config: OIDServiceConfiguration?, error: Error?) in
            self?.handleAppAuthCallback(
                value: config,
                error: error,
                fallbackError: TIMAuthError.failedToDiscoverConfiguration,
                completion: completion,
                preCompletionAction: { (res) in
                    if case Result.failure = res {
                        self?.authState = nil
                    }
                })
        }
    }

    private func doAuthState(
        request: OIDAuthorizationRequest,
        presentingViewController: UIViewController,
        willPresentSafariViewController: @escaping (SFSafariViewController) -> Void,
        shouldAnimate: @escaping () -> Bool,
        didCancel: @escaping () -> Void,
        callback: @escaping (Result<OIDAuthState, TIMAuthError>) -> Void) {
        currentAuthorizationFlow = OIDAuthState.authState(
            byPresenting: request,
            externalUserAgent: AuthSFController(
                presentingViewController: presentingViewController,
                willPresentSafariViewControllerCallback: willPresentSafariViewController,
                shouldAnimateCallback: shouldAnimate,
                didCancelCallback: didCancel
            )!,
            callback: { (authState: OIDAuthState?, error: Error?) in
                self.handleAppAuthCallback(
                    value: authState,
                    error: error,
                    fallbackError: TIMAuthError.failedToBeginAuth,
                    completion: callback
                )
            }
        )
    }

    private func createRestoreFakeLastAuthorizationResponse(configuration: OIDServiceConfiguration) -> OIDAuthorizationResponse {
        return OIDAuthorizationResponse(
            request: OIDAuthorizationRequest(
                configuration: configuration,
                clientId: credentials.clientId,
                scopes: credentials.scopes,
                redirectURL: credentials.redirectUri,
                responseType: OIDResponseTypeCode,
                additionalParameters: [:]
            ),
            parameters: [:])
    }

    func login(presentingViewController: UIViewController,
                completion: @escaping ((Result<JWT, TIMAuthError>) -> Void),
                didCancel: (() -> Void)? = nil,
                willPresentSafariViewController: ((SFSafariViewController) -> Void)? = nil,
                shouldAnimate: (() -> Bool)? = nil) {
        discoverConfiguration { [weak self] (res: Result<OIDServiceConfiguration, TIMAuthError>) in
            guard let `self` = self else {
                return
            }

            switch res {
            case .success(let config):
                let request = OIDAuthorizationRequest(
                    configuration: config,
                    clientId: self.credentials.clientId,
                    scopes: self.credentials.scopes,
                    redirectURL: self.credentials.redirectUri,
                    responseType: OIDResponseTypeCode,
                    additionalParameters: [:]
                )
                self.doAuthState(
                    request: request,
                    presentingViewController: presentingViewController,
                    willPresentSafariViewController: willPresentSafariViewController ?? { _ in },
                    shouldAnimate: shouldAnimate ?? { true },
                    didCancel: didCancel ?? { }) { [weak self] (authResult) in
                    guard let `self` = self else {
                        return
                    }

                    switch authResult {
                    case .success(let state):
                        self.authState = state
                        self.accessToken(completion)
                    case .failure(let error):
                        DispatchQueue.main.async {
                            completion(.failure(error))
                        }
                    }
                }
            case .failure(let error):
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func silentLogin(refreshToken: String, completion: @escaping (Result<JWT, TIMAuthError>) -> Void) {
        discoverConfiguration { [weak self] (res: Result<OIDServiceConfiguration, TIMAuthError>) in
            switch res {
            case .success(let configuration):
                guard let `self` = self else {
                    return
                }
                let request = OIDTokenRequest(
                    configuration: configuration,
                    grantType: OIDGrantTypeRefreshToken,
                    authorizationCode: nil,
                    redirectURL: nil,
                    clientID: self.credentials.clientId,
                    clientSecret: nil,
                    scopes: self.credentials.scopes,
                    refreshToken: refreshToken,
                    codeVerifier: nil,
                    additionalParameters: nil
                )
                OIDAuthorizationService.perform(request) { [weak self] (token: OIDTokenResponse?, error: Error?) in
                    let result: Result<JWT, TIMAuthError>
                    if let error = error {
                        result = .failure(.mapAppAuthError(error))
                    } else if let token = token, let jwt = token.accessToken {
                        let authResponse = self?.createRestoreFakeLastAuthorizationResponse(configuration: configuration)
                        self?.authState = OIDAuthState(authorizationResponse: authResponse, tokenResponse: token, registrationResponse: nil)
                        result = .success(jwt)
                    } else {
                        result = .failure(TIMAuthError.failedToGetAccessToken)
                    }
                    DispatchQueue.main.async {
                        completion(result)
                    }
                }
            case .failure(let error):
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }

    func accessToken(forceRefresh: Bool = false, _ completion: @escaping (Result<JWT, TIMAuthError>) -> Void) {
        guard let authState = self.authState else {
            completion(.failure(TIMAuthError.authStateNil))
            return
        }
        if forceRefresh {
            authState.setNeedsTokenRefresh()
        }
        authState.performAction { (accessToken: String?, _, error: Error?) in

            self.handleAppAuthCallback(
                value: accessToken,
                error: error,
                fallbackError: TIMAuthError.failedToGetAccessToken,
                completion: completion
            )
        }
    }

    func refreshToken() -> JWT? {
        authState?.refreshToken
    }

    func logout() {
        authState = nil
    }

    func handleRedirect(url: URL) -> Bool {
        let result: Bool
        if currentAuthorizationFlow?.resumeExternalUserAgentFlow(with: url) == true {
            currentAuthorizationFlow = nil
            result = true
        } else {
            result = false
        }
        return result
    }

    private func handleAppAuthCallback<T>(value: T?,
                                          error: Error?,
                                          fallbackError: TIMAuthError,
                                          completion: @escaping (Result<T, TIMAuthError>) -> Void,
                                          preCompletionAction: ((Result<T, TIMAuthError>) -> Void)? = nil) {
        let result: Result<T, TIMAuthError>
        if let error = error {
            result = .failure(TIMAuthError.mapAppAuthError(error))
        } else if let v = value {
            result = .success(v)
        } else {
            result = .failure(fallbackError)
        }
        DispatchQueue.main.async {
            preCompletionAction?(result)
            completion(result)
        }
    }

}
