import XCTest
import TIMEncryptedStorage
@testable import TIM

final class TIMTests: XCTestCase {
    func testConfigure() {
        XCTAssertFalse(TIM.isConfigured)
        TIM.configure(
            configuration: TIMConfiguration(
                oidc: TIMOpenIDConfiguration(
                    issuer: URL(string: "https://trifork.com")!,
                    clientId: "clientId",
                    redirectUri: URL(string:"my-app://")!,
                    scopes: ["scope"]
                ),
                keyService: TIMKeyServiceConfiguration(
                    realmBaseUrl: "https://trifork.com",
                    version: .v1
                ),
                encryptionMethod: .aesCbc
            )
        )
        XCTAssertTrue(TIM.isConfigured)
    }
}
