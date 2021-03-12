import XCTest
import AppAuth
@testable import TIM

final class AppAuthControllerTests: XCTestCase {
    func testCreateAuthState() {
        let clientId = "test-client-id"
        let redirectUri = URL(string: "test-redirect://")!
        let scope = "test-scope"
        let refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo5NTE2MjM5MDIyfQ.uABcDgaLYZTcO8PbD317GCngfBBYmxwg1DKDZU3YBZ4"

        let credentials = TIMOpenIDConfiguration(
            issuer: URL(string: "test-issuer://")!,
            clientId: clientId,
            redirectUri: redirectUri,
            scopes: [ scope ]
        )
        AppAuthController.shared.configure(credentials)

        let configuration = OIDServiceConfiguration(
            authorizationEndpoint: URL(string: "auth-test-url://")!,
            tokenEndpoint: URL(string: "token-test-url://")!
        )

        let authResponse = AppAuthController.shared.createRestoreFakeLastAuthorizationResponse(configuration: configuration)
        let tokenRequest = OIDTokenRequest(
            configuration: configuration,
            grantType: "grant",
            authorizationCode: "code",
            redirectURL: redirectUri,
            clientID: clientId,
            clientSecret: "secret",
            scope: scope,
            refreshToken: refreshToken,
            codeVerifier: nil,
            additionalParameters: nil
        )
        let tokenResponse = OIDTokenResponse(
            request: tokenRequest,
            parameters: [
                "refresh_token": refreshToken as NSString
            ]
        )
        let authState = OIDAuthState(
            authorizationResponse: authResponse,
            tokenResponse: tokenResponse,
            registrationResponse: nil
        )
        XCTAssertEqual(refreshToken, authState.refreshToken)
    }
}
