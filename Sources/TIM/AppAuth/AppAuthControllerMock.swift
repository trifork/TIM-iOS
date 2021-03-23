import UIKit
import SafariServices
import AppAuth

final class AppAuthControllerMock: OpenIDConnectController {
    var isLoggedIn: Bool {
        rt != nil && at != nil
    }

    let mockRT: JWTString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.El5bSmm8IPR4M11wg6mMCwnlx2hP7x4XZiaORoTWafY"
    let mockAT: JWTString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMzJ9.oqmeclge0Oc1VzYMxAlQ-J_HKNJwDQVdlFjoMJAhuIg"

    private var rt: JWTString?
    private var at: JWTString?

    func login(presentingViewController: UIViewController, completion: @escaping ((Result<JWT, TIMAuthError>) -> Void), didCancel: (() -> Void)?, willPresentSafariViewController: ((SFSafariViewController) -> Void)?, shouldAnimate: (() -> Bool)?) {
        guard let atJwt = JWT(token: mockAT), let rtJwt = JWT(token: mockRT) else {
            completion(.failure(.failedToGetAccessToken))
            return
        }
        self.at = atJwt.token
        self.rt = rtJwt.token
        completion(.success(atJwt))
    }

    func silentLogin(refreshToken: JWT, completion: @escaping (Result<JWT, TIMAuthError>) -> Void) {
        if let atJwt = JWT(token: mockAT), refreshToken.token == mockRT {
            self.rt = refreshToken.token
            self.at = atJwt.token
            completion(.success(atJwt))
        } else {
            self.rt = nil
            completion(.failure(.failedToBeginAuth))
        }
    }

    func accessToken(forceRefresh: Bool, _ completion: @escaping (Result<JWT, TIMAuthError>) -> Void) {
        guard let accessToken = at, let jwt = JWT(token: accessToken) else {
            completion(.failure(.failedToGetAccessToken))
            return
        }
        completion(.success(jwt))
    }

    func refreshToken() -> JWT? {
        guard let refreshToken = rt else {
            return nil
        }
        return JWT(token: refreshToken)
    }

    func logout() {
        self.rt = nil
        self.at = nil
    }

    func handleRedirect(url: URL) -> Bool {
        return true
    }
}
