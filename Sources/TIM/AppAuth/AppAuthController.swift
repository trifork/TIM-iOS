import AppAuth
import SafariServices

/// Protocol for OpenID Connect dependency.
public protocol OpenIDConnectController {
    var isLoggedIn: Bool { get }
    func login(presentingViewController: UIViewController, completion: @escaping ((Result<JWT, TIMAuthError>) -> Void), didCancel: (() -> Void)?, willPresentSafariViewController: ((SFSafariViewController) -> Void)?, shouldAnimate: (() -> Bool)?, authorizationRequestNonce: String?)
    func silentLogin(refreshToken: JWT, completion: @escaping (Result<JWT, TIMAuthError>) -> Void)
    func accessToken(forceRefresh: Bool, _ completion: @escaping (Result<JWT, TIMAuthError>) -> Void)
    func refreshToken() -> JWT?
    func logout()
    func handleRedirect(url: URL) -> Bool
}

/// AppAuth implementation of `OpenIDConnectController` protocol.
public final class AppAuthController: OpenIDConnectController {
    private var currentAuthorizationFlow: OIDExternalUserAgentSession? = nil

    private var authState: OIDAuthState?
    private let credentials: TIMOpenIDConfiguration
    private let customOIDExternalUserAgent: OIDExternalUserAgent?

    public var isLoggedIn: Bool {
        authState != nil
    }

    public init(_ credentials: TIMOpenIDConfiguration, customOIDExternalUserAgent: OIDExternalUserAgent? = nil) {
        self.credentials = credentials
        self.customOIDExternalUserAgent = customOIDExternalUserAgent
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
            let externalUserAgent = customOIDExternalUserAgent ?? AuthSFController(
                presentingViewController: presentingViewController,
                willPresentSafariViewControllerCallback: willPresentSafariViewController,
                shouldAnimateCallback: shouldAnimate,
                didCancelCallback: didCancel
            )!

        currentAuthorizationFlow = OIDAuthState.authState(
            byPresenting: request,
            externalUserAgent: externalUserAgent,
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

    func createRestoreFakeLastAuthorizationResponse(configuration: OIDServiceConfiguration) -> OIDAuthorizationResponse {
        return OIDAuthorizationResponse(
            request: OIDAuthorizationRequest(
                configuration: configuration,
                clientId: credentials.clientId,
                scopes: credentials.scopes,
                redirectURL: credentials.redirectUri,
                responseType: OIDResponseTypeCode,
                additionalParameters: credentials.additionalParameters
            ),
            parameters: [:])
    }

    public func login(presentingViewController: UIViewController,
                completion: @escaping ((Result<JWT, TIMAuthError>) -> Void),
                didCancel: (() -> Void)? = nil,
                willPresentSafariViewController: ((SFSafariViewController) -> Void)? = nil,
                shouldAnimate: (() -> Bool)? = nil,
                authorizationRequestNonce: String? = nil) {
        discoverConfiguration { [weak self] (res: Result<OIDServiceConfiguration, TIMAuthError>) in
            guard let `self` = self else {
                return
            }

            switch res {
            case .success(let config):
                let request = self.createAuthorizationRequest(config: config, authorizationRequestNonce: authorizationRequestNonce)
                
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
                        self.accessToken(forceRefresh: false, completion)
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

    public func silentLogin(refreshToken: JWT, completion: @escaping (Result<JWT, TIMAuthError>) -> Void) {
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
                    refreshToken: refreshToken.token,
                    codeVerifier: nil,
                    additionalParameters: self.credentials.additionalParameters
                )
                OIDAuthorizationService.perform(request) { [weak self] (token: OIDTokenResponse?, error: Error?) in
                    let result: Result<JWT, TIMAuthError>
                    if let error = error {
                        result = .failure(.mapAppAuthError(error))
                    } else if let token = token, let rawAccessToken = token.accessToken {
                        let authResponse = self?.createRestoreFakeLastAuthorizationResponse(configuration: configuration)
                        self?.authState = OIDAuthState(authorizationResponse: authResponse, tokenResponse: token, registrationResponse: nil)
                        if let jwt = JWT(token: rawAccessToken) {
                            result = .success(jwt)
                        } else {
                            result = .failure(.failedToGetRequiredDataInToken)
                        }
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

    public func accessToken(forceRefresh: Bool, _ completion: @escaping (Result<JWT, TIMAuthError>) -> Void) {
        guard let authState = self.authState else {
            completion(.failure(TIMAuthError.authStateNil()))
            return
        }
        if forceRefresh {
            authState.setNeedsTokenRefresh()
        }
        authState.performAction { (accessToken: String?, _, error: Error?) in
            if let accessToken = accessToken {
                if let jwt = JWT(token: accessToken) {
                    self.handleAppAuthCallback(
                        value: jwt,
                        error: error,
                        fallbackError: TIMAuthError.failedToGetAccessToken,
                        completion: completion
                    )
                } else {
                    completion(.failure(.failedToGetRequiredDataInToken))
                }
            } else {
                completion(.failure(.failedToGetAccessToken))
            }
        }
    }

    public func refreshToken() -> JWT? {
        if let refreshToken = authState?.refreshToken {
            return JWT(token: refreshToken)
        } else {
            return nil
        }
    }

    public func logout() {
        authState = nil
    }

    public func handleRedirect(url: URL) -> Bool {
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
    
    /// Create AuthorizationRequest using the authorizationRequestNonce in case it is provided
    private func createAuthorizationRequest(config: OIDServiceConfiguration, authorizationRequestNonce: String?) -> OIDAuthorizationRequest {
        
        if let authorizationRequestNonce = authorizationRequestNonce {
            let state: String? = OIDAuthorizationRequest.generateState()
            let codeVerifier: String? = OIDAuthorizationRequest.generateCodeVerifier()
            let codeChallenge: String? = OIDAuthorizationRequest.codeChallengeS256(forVerifier: codeVerifier)
            
            return OIDAuthorizationRequest(
                configuration: config,
                clientId: self.credentials.clientId,
                clientSecret: nil,
                scope: OIDScopeUtilities.scopes(with: self.credentials.scopes),
                redirectURL: self.credentials.redirectUri,
                responseType: OIDResponseTypeCode,
                state: state,
                nonce: authorizationRequestNonce,
                codeVerifier: codeVerifier,
                codeChallenge: codeChallenge,
                codeChallengeMethod: OIDOAuthorizationRequestCodeChallengeMethodS256,
                additionalParameters: self.credentials.additionalParameters
            )
        } else {
            return OIDAuthorizationRequest(
                configuration: config,
                clientId: self.credentials.clientId,
                scopes: self.credentials.scopes,
                redirectURL: self.credentials.redirectUri,
                responseType: OIDResponseTypeCode,
                additionalParameters: self.credentials.additionalParameters
            )
        }
    }

}
