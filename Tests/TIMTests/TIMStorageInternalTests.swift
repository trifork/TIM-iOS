import XCTest
import AppAuth
@testable import TIM
@testable import TIMEncryptedStorage

final class TIMStorageInternalTests: XCTestCase {

    static private let keyServiceBaseUrl = "https://identitymanager.trifork.com"
    private let testRefreshToken: JWTString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.fzHyQ0D6kSOr-6i4gEiJoOm5UutfqgivtqtXbwaRv1c"
    static private let getUrl = URL(string: keyServiceBaseUrl)!.appendingPathComponent("/keyservice/v1/key")
    static private let createUrl = URL(string: keyServiceBaseUrl)!.appendingPathComponent("/keyservice/v1/createkey")


    override class func setUp() {
        super.setUp()
        URLSessionStubResults.reset()
    }

    func testStoreRefreshTokenWithNewPassword() {
        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)
            XCTAssertFalse(storage.hasRefreshToken(userId: testRefreshToken.userId!))
            _ = storeRefreshTokenWithNewPassword(dataStorage: storage, password: "1234")
            XCTAssertTrue(storage.hasRefreshToken(userId: testRefreshToken.userId!))
        }
    }

    func testStoreRefreshTokenWithExistingPassword() {

        let newRefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.fzHyQ0D6kSOr-6i4gEiJoOm5UutfqgivtqtXbwaRv1c"
        let updatedRefreshTokenJwt = JWT(token: newRefreshToken)!
        XCTAssertEqual(newRefreshToken.userId!, testRefreshToken.userId!)

        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Try to store refresh token with existing password, without having created a new password.
            let expect1 = XCTestExpectation(description: "Store refresh token with existing password")
            storage.storeRefreshToken(updatedRefreshTokenJwt, withExistingPassword: "1234") { (result) in
                switch result {
                case .failure(let error):
                    if case TIMError.storage(.encryptedStorageFailed(TIMEncryptedStorageError.secureStorageFailed(TIMSecureStorageError.failedToLoadData))) = error {
                        // All good!
                    } else {
                        XCTFail("Should have produced failedToLoadData.")
                    }
                case .success:
                    XCTFail("This should have failed, because there is no keyId for the userId")
                }
                expect1.fulfill()
            }
            wait(for: [expect1], timeout: 1.0)
            XCTAssertFalse(storage.availableUserIds.contains(updatedRefreshTokenJwt.userId))

            // Store the refresh token with a new password
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, password: "1234")
            URLSessionStubResults.resultsForUrls[Self.getUrl] = .dataResponse(
                data: try! JSONEncoder().encode(keyModel),
                response: HTTPURLResponse(url: Self.getUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!
            )
            XCTAssertTrue(storage.availableUserIds.contains(testRefreshToken.userId!)) // Should be accessible as an available user now

            // Store an updated refresh token with an existing password.
            let expect2 = XCTestExpectation(description: "Store refresh token with existing password")
            storage.storeRefreshToken(updatedRefreshTokenJwt, withExistingPassword: "1234") { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success: break // all good
                }
                expect2.fulfill()
            }
            wait(for: [expect2], timeout: 1.0)
            XCTAssertTrue(storage.availableUserIds.contains(updatedRefreshTokenJwt.userId)) // Still in the list!
        }
    }

    func testGetRefreshToken() {
        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Store refresh token with new password
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, password: "1234")
            URLSessionStubResults.resultsForUrls[Self.getUrl] = .dataResponse(
                data: try! JSONEncoder().encode(keyModel),
                response: HTTPURLResponse(url: Self.getUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!
            )

            // Get stored refresh token
            let expect = XCTestExpectation(description: "Storage should have returned.")
            storage.getStoredRefreshToken(userId: testRefreshToken.userId!, password: "1234") { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let jwt):
                    XCTAssertEqual(self.testRefreshToken, jwt.token)
                }
                expect.fulfill()
            }

            wait(for: [expect], timeout: 1.0)
        }
    }

    func testBiometricAccessForRefreshToken() {
        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Store refresh token with new password
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, password: "1234")
            URLSessionStubResults.resultsForUrls[Self.getUrl] = .dataResponse(
                data: try! JSONEncoder().encode(keyModel),
                response: HTTPURLResponse(url: Self.getUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!
            )

            // Enable biometric access
            XCTAssertFalse(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))
            let expect1 = XCTestExpectation(description: "Storage should have returned.")
            storage.enableBiometricAccessForRefreshToken(password: "1234", userId: testRefreshToken.userId!, completion: { result in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success: break
                }
                expect1.fulfill()
            })
            wait(for: [expect1], timeout: 1.0)
            XCTAssertTrue(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))

            // Get stored refresh token
            let expect2 = XCTestExpectation(description: "Storage should have returned.")
            storage.getStoredRefreshTokenViaBiometric(userId: testRefreshToken.userId!, completion: { result in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let bioResult):
                    XCTAssertEqual(self.testRefreshToken, bioResult.refreshToken.token)
                    XCTAssertEqual(keyModel.longSecret!, bioResult.longSecret)
                }
                expect2.fulfill()
            })

            wait(for: [expect2], timeout: 1.0)

            // Disable biometric access
            XCTAssertTrue(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))
            storage.disableBiometricAccessForRefreshToken(userId: testRefreshToken.userId!)
            XCTAssertFalse(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))
        }
    }


    // MARK: - Private helpers
    private func dataStorage(for encryptionMethod: TIMESEncryptionMethod) -> TIMDataStorageInternal<SecureStorageMock> {
        TIMDataStorageInternal(
            encryptedStorage: TIMEncryptedStorage(
                secureStorage: SecureStorageMock(),
                keyService: TIMKeyService(
                    configuration: TIMKeyServiceConfiguration(
                        realmBaseUrl: Self.keyServiceBaseUrl,
                        version: .v1
                    ),
                    urlSession: .mockSession
                ),
                encryptionMethod: encryptionMethod
            )
        )
    }

    private func storeRefreshTokenWithNewPassword(dataStorage: TIMDataStorageInternal<SecureStorageMock>, password: String) -> TIMKeyModel {
        let createdKeyModel = TIMKeyModel(
            keyId: UUID().uuidString,
            key: "S2JQZVNoVm1ZcTN0Nnc5eQ==",
            longSecret: "longSecret"
        )
        URLSessionStubResults.resultsForUrls[Self.createUrl] = .dataResponse(
            data: try! JSONEncoder().encode(createdKeyModel),
            response: HTTPURLResponse(url: Self.createUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let refreshTokenJwt = JWT(token: testRefreshToken)!
        let expect = XCTestExpectation(description: "Store refresh token with new password")
        XCTAssertFalse(dataStorage.availableUserIds.contains(refreshTokenJwt.userId))
        dataStorage.storeRefreshToken(refreshTokenJwt, withNewPassword: password) { (result) in
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
            case .success(let creationResult):
                XCTAssertEqual(creationResult.longSecret, createdKeyModel.longSecret)
                XCTAssertEqual(creationResult.keyId, createdKeyModel.keyId)
            }
            expect.fulfill()
        }
        wait(for: [expect], timeout: 1.0)
        XCTAssertTrue(dataStorage.availableUserIds.contains(refreshTokenJwt.userId))
        return createdKeyModel
    }
}
