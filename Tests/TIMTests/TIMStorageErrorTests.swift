import XCTest
@testable import TIM

final class TIMStorageErrorTests: XCTestCase {

    func testIsKeyLocked() {
        XCTAssertFalse(TIMStorageError.failedToGetRefreshToken.isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.failedToLoadLongSecretViaBiometric).isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isKeyLocked())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.keyLocked)).isKeyLocked())
    }

    func testIsWrongPassword() {
        XCTAssertFalse(TIMStorageError.failedToGetRefreshToken.isWrongPassword())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.failedToLoadLongSecretViaBiometric).isWrongPassword())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isWrongPassword())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.keyLocked)).isWrongPassword())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isWrongPassword())
    }

    func testIsKeyServiceError() {
        XCTAssertFalse(TIMStorageError.failedToGetRefreshToken.isKeyServiceError())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.failedToLoadLongSecretViaBiometric).isKeyServiceError())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isKeyServiceError())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.keyLocked)).isKeyServiceError())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isKeyServiceError())
    }
}
