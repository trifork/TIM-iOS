import XCTest
@testable import TIM

final class JWTExtensionsTests: XCTestCase {

    let simpleAccessToken: JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxMzM3fQ.RfalLtiTT6j_rBKX5pGm_jGmwwL-hIh-Qut7eLHiwtg"
    let invalidJwt: JWT = "INVALID"

    func testUserId() {
        XCTAssertEqual(simpleAccessToken.userId, "user")
    }

    func testExpireTime() {
        XCTAssertEqual(simpleAccessToken.expireTimestamp, 1337)
    }

    func testInvalidToken() {
        XCTAssertNil(invalidJwt.userId)
    }

    static var allTests = [
        ("testUserId", testUserId),
        ("testExpireTime", testExpireTime),
        ("testInvalidToken", testInvalidToken),
    ]
}
