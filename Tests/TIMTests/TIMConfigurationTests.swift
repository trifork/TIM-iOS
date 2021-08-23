import Foundation
import XCTest
@testable import TIM

final class TIMConfigurationTests: XCTestCase {
    func testDefaultConstructor() {
        let config = TIMConfiguration(
            timBaseUrl: URL(string: "https://trifork.com")!,
            realm: "my-test-realm",
            clientId: "clientId",
            redirectUri: URL(string:"my-app://")!,
            scopes: ["scope"],
            encryptionMethod: .aesCbc,
            keyServiceVersion: .v1
        )
        XCTAssertEqual(config.oidcConfiguration.issuer.absoluteString, "https://trifork.com/auth/realms/my-test-realm")
    }
}
