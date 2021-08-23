import XCTest
@testable import TIM

final class JWTExtensionsTests: XCTestCase {

    let simpleAccessToken: JWTString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxMzM3LCJpc3MiOiJodHRwczovL3RyaWZvcmsuY29tIn0.C_ERZ4zqvSLL0x1klZxERDzyDsjSFM-AYAsn0sdFmqE"
    let invalidJwt: JWTString = "INVALID"

    func testUserId() {
        XCTAssertEqual(simpleAccessToken.userId, "user")
    }

    func testExpireTime() {
        XCTAssertEqual(simpleAccessToken.expireTimestamp, 1337)
    }

    func testIssuer() {
        XCTAssertEqual(simpleAccessToken.issuer, "https://trifork.com")
    }

    func testInvalidToken() {
        XCTAssertNil(invalidJwt.userId)
    }

    func testJWTInit() {
        let jwt = JWT(token: simpleAccessToken)
        XCTAssertNotNil(jwt)

        // Missing exp
        let jwtWithoutExp = JWT(token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        XCTAssertNotNil(jwtWithoutExp)

        // Missing sub
        let jwtWithoutUserId = JWT(token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyMn0.yOZC0rjfSopcpJ-d3BWE8-BkoLR_SCqPdJpq8Wn-1Mc")
        XCTAssertNil(jwtWithoutUserId)
    }
}
