import XCTest
import AppAuth
@testable import TIM
@testable import TIMEncryptedStorage

final class TIMStorageInternalTests: XCTestCase {

    static private let keyServiceBaseUrl = "https://identitymanager.trifork.com"
    private let testRefreshToken: JWTString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.fzHyQ0D6kSOr-6i4gEiJoOm5UutfqgivtqtXbwaRv1c"


    override class func setUp() {
        super.setUp()
        URLSessionStubResults.reset()
    }

    func testStoreRefreshTokenWithNewPassword() {
        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)
            XCTAssertFalse(storage.hasRefreshToken(userId: testRefreshToken.userId!))
            _ = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
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
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)
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
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)

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
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)

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

    func testEnableBiometricAccessForRefreshTokenViaLongSecret() {
        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Store refresh token with new password
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)

            // Enable biometric access
            XCTAssertFalse(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))
            let result = storage.enableBiometricAccessForRefreshToken(longSecret: keyModel.longSecret!, userId: testRefreshToken.userId!)
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
            case .success:
                XCTAssertTrue(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))
            }
        }
    }

    func testStoreRefreshTokenWithLongSecret() {
        let newRefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.fzHyQ0D6kSOr-6i4gEiJoOm5UutfqgivtqtXbwaRv1c"

        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Store refresh token with new password
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)

            let expect = XCTestExpectation(description: "Storage failed to return")
            let jwt = JWT(token: newRefreshToken)!
            storage.storeRefreshTokenWithLongSecret(jwt, longSecret: "longSecret") { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success:
                    XCTAssertTrue(storage.hasRefreshToken(userId: newRefreshToken.userId!))
                }
                expect.fulfill()
            }
            wait(for: [expect], timeout: 1.0)
        }
    }

    func testClear() {
        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Store refresh token with new password
            let keyModel = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: self.testRefreshToken, password: "1234")
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel)
            XCTAssertTrue(storage.hasRefreshToken(userId: testRefreshToken.userId!))

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

            storage.clear(userId: testRefreshToken.userId!)
            XCTAssertEqual(0, storage.availableUserIds.count)
            XCTAssertFalse(storage.hasRefreshToken(userId: testRefreshToken.userId!))
            XCTAssertFalse(storage.hasBiometricAccessForRefreshToken(userId: testRefreshToken.userId!))
        }
    }

    func testMultipleUsers() {
        let user1RefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.El5bSmm8IPR4M11wg6mMCwnlx2hP7x4XZiaORoTWafY"
        let user2RefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk1MTYyMzkwMjJ9.q0FBllJKYNGIDEsHj8d0yIGLCaANkyjxER_l1Xm4P50"

        XCTAssertNotEqual(user1RefreshToken, user2RefreshToken)
        XCTAssertNotEqual(user1RefreshToken.userId!, user2RefreshToken.userId!)

        for encryptionMethod in TIMESEncryptionMethod.allCases {
            let storage = dataStorage(for: encryptionMethod)

            // Store refresh tokens with new passwords
            let keyModel1 = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: user1RefreshToken, password: "1234")
            let keyModel2 = storeRefreshTokenWithNewPassword(dataStorage: storage, refreshToken: user2RefreshToken, password: "4321")
            XCTAssertNotEqual(keyModel1.keyId, keyModel2.keyId)
            XCTAssertTrue(storage.hasRefreshToken(userId: user1RefreshToken.userId!))
            XCTAssertTrue(storage.hasRefreshToken(userId: user2RefreshToken.userId!))
            XCTAssertEqual(2, storage.availableUserIds.count)

            // Enable bio for user 1
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel1)
            let expect1 = XCTestExpectation(description: "Storage should have returned.")
            storage.enableBiometricAccessForRefreshToken(password: "1234", userId: user1RefreshToken.userId!, completion: { result in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success: break
                }
                expect1.fulfill()
            })
            wait(for: [expect1], timeout: 1.0)
            XCTAssertTrue(storage.hasBiometricAccessForRefreshToken(userId: user1RefreshToken.userId!))
            XCTAssertFalse(storage.hasBiometricAccessForRefreshToken(userId: user2RefreshToken.userId!))

            // Get refresh token via bio for user 1
            let expect2 = XCTestExpectation(description: "Bio result never returned for user 1")
            storage.getStoredRefreshTokenViaBiometric(userId: user1RefreshToken.userId!, completion: { result in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let bioResult):
                    XCTAssertEqual(user1RefreshToken, bioResult.refreshToken.token)
                }
                expect2.fulfill()
            })
            wait(for: [expect2], timeout: 1.0)

            // Get refresh token via bio for user 2 -> This should fail!
            URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .key, keyModel: keyModel2)
            let expect3 = XCTestExpectation(description: "Bio result never returned for user 2")
            storage.getStoredRefreshTokenViaBiometric(userId: user2RefreshToken.userId!, completion: { result in
                switch result {
                case .failure(let error):
                    if case TIMError.storage(.encryptedStorageFailed(.secureStorageFailed(.failedToLoadData))) = error {
                        // All good!
                    } else {
                        XCTFail("Should have caused failed to load data!")
                    }
                case .success:
                    XCTFail("There should not be bio access for user2!")
                }
                expect3.fulfill()
            })

            // Get refresh token via password for user 2
            let expect4 = XCTestExpectation(description: "Refresh token never returned for user 2")
            storage.getStoredRefreshToken(userId: user2RefreshToken.userId!, password: "4321") { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let token):
                    XCTAssertEqual(user2RefreshToken, token.token)
                }
                expect4.fulfill()
            }
            wait(for: [expect3, expect4], timeout: 1.0)

            // Delete user 2 and check that user 1 is still intact.
            storage.clear(userId: user2RefreshToken.userId!)
            XCTAssertEqual(1, storage.availableUserIds.count)
            XCTAssertFalse(storage.hasRefreshToken(userId: user2RefreshToken.userId!))
            XCTAssertTrue(storage.hasRefreshToken(userId: user1RefreshToken.userId!))
            XCTAssertTrue(storage.hasBiometricAccessForRefreshToken(userId: user1RefreshToken.userId!))
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

    private func storeRefreshTokenWithNewPassword(dataStorage: TIMDataStorageInternal<SecureStorageMock>, refreshToken: JWTString, password: String) -> TIMKeyModel {
        let createdKeyModel = TIMKeyModel(
            keyId: UUID().uuidString,
            key: "S2JQZVNoVm1ZcTN0Nnc5eQ==",
            longSecret: "longSecret"
        )
        URLSessionStubResults.setKeyModel(baseUrl: Self.keyServiceBaseUrl, endpoint: .createKey, keyModel: createdKeyModel)
        let refreshTokenJwt = JWT(token: refreshToken)!
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
