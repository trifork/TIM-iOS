import XCTest
@testable import TIM

final class TIMStorageErrorTests: XCTestCase {

    func testIsKeyLocked() {
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.secureStorageFailed(.failedToLoadData)).isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isKeyLocked())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.keyLocked)).isKeyLocked())
    }

    func testIsWrongPassword() {
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.secureStorageFailed(.failedToStoreData)).isWrongPassword())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isWrongPassword())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.keyLocked)).isWrongPassword())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isWrongPassword())
    }

    func testIsKeyServiceError() {
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.secureStorageFailed(.authenticationFailedForData)).isKeyServiceError())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isKeyServiceError())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.keyLocked)).isKeyServiceError())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isKeyServiceError())
    }

    func testIsBiometricError() {
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.secureStorageFailed(.failedToLoadData)).isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badInternet)).isKeyLocked())
        XCTAssertFalse(TIMStorageError.encryptedStorageFailed(.keyServiceFailed(.badPassword)).isKeyLocked())
        XCTAssertTrue(TIMStorageError.encryptedStorageFailed(.secureStorageFailed(.authenticationFailedForData)).isBiometricFailedError())
    }
}
