import XCTest
import TIMEncryptedStorage
@testable import TIM

final class TIMTests: XCTestCase {
    let config = TIMConfiguration(
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

    func testConfigure() {
        XCTAssertFalse(TIM.isConfigured)
        TIM.configure(configuration: config)
        XCTAssertTrue(TIM.isConfigured)
    }

    func testReconfigure() {
        XCTAssertTrue(TIM.isConfigured)
        TIM.configure(configuration: config, allowReconfigure: true)
        XCTAssertTrue(TIM.isConfigured)
        TIM.configure(configuration: config, allowReconfigure: true)
        XCTAssertTrue(TIM.isConfigured)
    }
}
