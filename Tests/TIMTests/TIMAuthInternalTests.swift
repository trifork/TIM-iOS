import XCTest
import AppAuth
#if canImport(Combine)
import Combine
#endif
@testable import TIM
@testable import TIMEncryptedStorage

final class TIMAuthInternalTests: XCTestCase {

    static private let keyServiceBaseUrl = "https://identitymanager.trifork.com"

    static let storage = TIMDataStorageInternal(
        encryptedStorage: TIMEncryptedStorage(
            secureStorage: SecureStorageMock(),
            keyService: TIMKeyService(
                configuration: TIMKeyServiceConfiguration(
                    realmBaseUrl: keyServiceBaseUrl,
                    version: .v1
                ),
                urlSession: .mockSession
            ),
            encryptionMethod: .aesCbc // Using CBC for these tests to support devices before iOS 13. Both encryption methods are tests throughly in the tests for the data storage.
        ))
    let auth = TIMAuthInternal(
        dataStorage: storage,
        openIdController: AppAuthControllerMock(),
        backgroundMonitor: TIMAppBackgroundMonitorInternal()
    )

    override class func setUp() {
        super.setUp()
        URLSessionStubResults.reset()
    }

    func testInitialState() {
        auth.accessToken { (result) in
            switch result {
            case .success:
                XCTFail("This should have failed.")
            case .failure: break
            }
        }
        XCTAssertFalse(auth.isLoggedIn)
        XCTAssertNil(auth.refreshToken)

        let expect = XCTestExpectation(description: "Login should have returned")
        auth.loginWithPassword(userId: "1", password: "1234") { (result) in
            switch result {
            case .failure(let error):
                if case TIMError.storage(.encryptedStorageFailed(.secureStorageFailed(.failedToLoadData))) = error {
                    // All good
                } else {
                    XCTFail(error.localizedDescription)
                }
            case .success:
                XCTFail("This should have failed.")
            }
            expect.fulfill()
        }
        wait(for: [expect], timeout: 1.0)
    }

    func testPerformOpenIDLogin() {
        performInitialLogin()
    }

    func testLoginWithPassword() {
        performInitialLogin()
        let expect1 = XCTestExpectation(description: "Store operation should have returned")
        // Store refresh token with new password
        let keyModel = TIMKeyModel(keyId: UUID().uuidString, key: "eC9BJUQqRy1LYVBkU2dWaw==", longSecret: "longSecret")
        URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .createKey, keyModel: keyModel)
        URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)
        Self.storage.storeRefreshToken(auth.refreshToken!, withNewPassword: "1234", completion: { result in
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
            case .success(let creationResult):
                XCTAssertEqual(creationResult.keyId, keyModel.keyId)
                XCTAssertEqual(creationResult.longSecret, keyModel.longSecret)
            }
            expect1.fulfill()
        })
        wait(for: [expect1], timeout: 1.0)
        XCTAssertTrue(Self.storage.hasRefreshToken(userId: "1"))
        XCTAssertEqual(auth.refreshToken!.userId, "1")
        XCTAssertTrue(auth.isLoggedIn)
        auth.logout()
        XCTAssertFalse(auth.isLoggedIn)
        XCTAssertNil(auth.refreshToken)

        let expect2 = XCTestExpectation(description: "Login operation should have returned")
        auth.loginWithPassword(userId: "1", password: "1234") { (result) in
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
                expect2.fulfill()
            case .success(let jwt):
                XCTAssertEqual(jwt.userId, "1")
                XCTAssertNotNil(self.auth.refreshToken)
                XCTAssertTrue(self.auth.isLoggedIn)

                self.auth.accessToken { (atResult) in
                    switch result {
                    case .success(let jwt):
                        XCTAssertEqual(jwt.userId, "1")
                    case .failure(let error):
                        XCTFail(error.localizedDescription)
                    }
                    expect2.fulfill()
                }
            }

        }
        wait(for: [expect2], timeout: 1.0)
    }

    func testLoginWithBiometric() {
        performInitialLogin()
        let expect1 = XCTestExpectation(description: "Store operation should have returned")
        // Store refresh token with new password
        let keyModel = TIMKeyModel(keyId: UUID().uuidString, key: "eC9BJUQqRy1LYVBkU2dWaw==", longSecret: "longSecret")
        URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .createKey, keyModel: keyModel)
        URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)

        Self.storage.storeRefreshToken(auth.refreshToken!, withNewPassword: "1234", completion: { result in
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
            case .success(let creationResult):
                XCTAssertEqual(creationResult.keyId, keyModel.keyId)
                XCTAssertEqual(creationResult.longSecret, keyModel.longSecret)

                let bioResult = Self.storage.enableBiometricAccessForRefreshToken(longSecret: creationResult.longSecret, userId: self.auth.refreshToken!.userId)
                switch bioResult {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success: break
                }
                expect1.fulfill()
            }
        })
        wait(for: [expect1], timeout: 1.0)
        XCTAssertTrue(Self.storage.hasRefreshToken(userId: "1"))
        XCTAssertTrue(Self.storage.hasBiometricAccessForRefreshToken(userId: self.auth.refreshToken!.userId))
        XCTAssertEqual(auth.refreshToken!.userId, "1")
        XCTAssertTrue(auth.isLoggedIn)
        auth.logout()
        XCTAssertFalse(auth.isLoggedIn)
        XCTAssertNil(auth.refreshToken)

        let expect2 = XCTestExpectation(description: "Login operation should have returned")
        auth.loginWithBiometricId(userId: "1") { (result) in
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
                expect2.fulfill()
            case .success(let jwt):
                XCTAssertEqual(jwt.userId, "1")
                XCTAssertNotNil(self.auth.refreshToken)
                XCTAssertTrue(self.auth.isLoggedIn)

                self.auth.accessToken { (atResult) in
                    switch result {
                    case .success(let jwt):
                        XCTAssertEqual(jwt.userId, "1")
                    case .failure(let error):
                        XCTFail(error.localizedDescription)
                    }
                    expect2.fulfill()
                }
            }
        }
        wait(for: [expect2], timeout: 1.0)
    }

    func testBackgroundTimeout() {
        performInitialLogin()
        XCTAssertTrue(auth.isLoggedIn)

        let expect = XCTestExpectation()
        auth.enableBackgroundTimeout(durationSeconds: 1) {
            XCTAssertFalse(self.auth.isLoggedIn)
            expect.fulfill()
        }

        // Go to background
        NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)

        // Wait for 2 seconds and return to foreground
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(2)) {
            NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
        }
        wait(for: [expect], timeout: 5.0)
        XCTAssertFalse(self.auth.isLoggedIn)
    }

    #if canImport(Combine)
    @available(iOS 13, *)
    func testBackgroundTimeoutForCombine() {
        let expect = XCTestExpectation()
        expect.expectedFulfillmentCount = 4
        auth.enableBackgroundTimeout(durationSeconds: 1) {
            XCTAssertFalse(self.auth.isLoggedIn)
            expect.fulfill()
        }

        for _ in 0 ..< 4 {
            performInitialLogin()  // Login again, since the time out logs the user out.
            XCTAssertTrue(auth.isLoggedIn)

            // Go to background
            NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)

            let waitExpect = XCTestExpectation()
            // Wait for 2 seconds and return to foreground
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(1100)) {
                NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
                waitExpect.fulfill()
            }
            wait(for: [waitExpect], timeout: 2.0)
            XCTAssertFalse(self.auth.isLoggedIn)
        }
        wait(for: [expect], timeout: 10.0)
    }
    #endif

    private func performInitialLogin() {
        let expect = XCTestExpectation(description: "Login should have returned")
        auth.performOpenIDConnectLogin(presentingViewController: UIViewController()) { (result) in
            switch result {
            case .success(let jwt):
                XCTAssertEqual("1", jwt.userId)
                XCTAssertNotNil(self.auth.refreshToken)
            case .failure(let error):
                XCTFail(error.localizedDescription)
            }
            expect.fulfill()
        }
        wait(for: [expect], timeout: 1.0)
    }
}
