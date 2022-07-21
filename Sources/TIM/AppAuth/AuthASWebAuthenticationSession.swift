//
//  File.swift
//  
//
//  Created by Kim de Vos on 21/07/2022.
//


#if canImport(AuthenticationServices)
import AppAuth
import AuthenticationServices

@available(iOS 12.0, *)
public class AuthASWebAuthenticationSession: NSObject, OIDExternalUserAgent {
    private let presentingViewController: UIViewController
    
    private var webAuthenticationSession: ASWebAuthenticationSession?
    private weak var session: OIDExternalUserAgentSession?

    public init(with presentingViewController: UIViewController) {
        self.presentingViewController = presentingViewController
        super.init()
    }

    public func present(_ request: OIDExternalUserAgentRequest, session: OIDExternalUserAgentSession) -> Bool {
        guard let requestURL = request.externalUserAgentRequestURL() else {
            return false
        }

        self.session = session
        var openedUserAgent = false

        let redirectScheme = request.redirectScheme()
        let webAuthenticationSession = ASWebAuthenticationSession(url: requestURL, callbackURLScheme: redirectScheme) { (callbackURL, error) in
            self.webAuthenticationSession = nil
            if let url = callbackURL {
                self.session?.resumeExternalUserAgentFlow(with: url)
            } else {
                let webAuthenticationError = OIDErrorUtilities.error(with: OIDErrorCode.userCanceledAuthorizationFlow,
                                                                     underlyingError: error,
                                                                     description: nil)
                self.session?.failExternalUserAgentFlowWithError(webAuthenticationError)
            }
        }
        
        if #available(iOS 13.0, *) {
            webAuthenticationSession.presentationContextProvider = self
            /// ** Key Line of code  -> `.prefersEphemeralWebBrowserSession` ** allows for private browsing
            webAuthenticationSession.prefersEphemeralWebBrowserSession = true
        }
        
        self.webAuthenticationSession = webAuthenticationSession
        openedUserAgent = webAuthenticationSession.start()

        return openedUserAgent
    }

    public func dismiss(animated: Bool, completion: @escaping () -> Void) {
        cleanUp()
        
        presentingViewController.dismiss(animated: animated, completion: completion)
    }
}

@available(iOS 12.0, *)
extension AuthASWebAuthenticationSession {
    /// Sets class variables to nil. Note 'weak references i.e. session are set to nil to avoid accidentally using them while not in an authorization flow.
    func cleanUp() {
        session = nil
        webAuthenticationSession = nil
    }
}

@available(iOS 12.0, *)
extension AuthASWebAuthenticationSession: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return presentingViewController.view.window!
    }
}
#endif
