import Foundation
import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

protocol DataConvertable {
    func convert() -> Data
    static func convert(data: Data) -> Self?
}

private enum TIMDataStorageStoreId {
    case keyId(String)
    case refreshToken(String)
    case availableUserIds

    func storeID() -> StoreID {
        switch self {
        case .keyId(let uniqueUserId):
            return "keyId_\(uniqueUserId)"
        case .refreshToken(let uniqueUserId):
            return "refreshToken_\(uniqueUserId)"
        case .availableUserIds:
            return "availableUserIds"
        }
    }

    static func allUserSpecificCases(userId: String) -> [TIMDataStorageStoreId] {
        return [
            .keyId(userId),
            .refreshToken(userId)
        ]
    }
}

final class TIMDataStorageInternal : TIMDataStorage {

    // MARK: - Private helpers for raw data in key chain (NOT ENCRYPTED!)
    @discardableResult
    private func store<T : DataConvertable>(data: T, storeID: TIMDataStorageStoreId) -> Bool {
        let item = TIMKeychainStoreItem(id: storeID.storeID())
        return TIMKeychain.store(data: data.convert(), item: item)
    }

    private func get<T: DataConvertable>(storeID: TIMDataStorageStoreId) -> T? {
        let item = TIMKeychainStoreItem(id: storeID.storeID())
        if let data =  TIMKeychain.get(item: item) {
            return T.convert(data: data)
        } else {
            return nil
        }
    }

    private func addAvailableUserId(userId: String) {
        var currentUserIds = availableUserIds
        currentUserIds.insert(userId)
        store(data: currentUserIds, storeID: .availableUserIds)
    }

    private func removeAvailableUserId(userId: String) {
        var currentUserIds = availableUserIds
        currentUserIds.remove(userId)
        store(data: currentUserIds, storeID: .availableUserIds)
    }

    // MARK: - Internal
    func storeRefreshTokenWithBiometricAccess(_ refreshToken: JWT, longSecret: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        guard let userId: String = refreshToken.userId,
              let keyId: String = get(storeID: .keyId(userId)) else {
            completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
            return
        }

        TIMEncryptedStorage.store(
            id: TIMDataStorageStoreId.refreshToken(userId).storeID(),
            data: refreshToken.convert(),
            keyId: keyId,
            longSecret: longSecret) { (result) in
            completion(result.mapError({ TIMError.storage(.encryptedStorageFailed($0)) }))
        }
    }

    // MARK: -
    var availableUserIds: Set<String> {
        return get(storeID: .availableUserIds) ?? []
    }

    func hasRefreshToken(userId: String) -> Bool {
        TIMEncryptedStorage.hasValue(id: TIMDataStorageStoreId.refreshToken(userId).storeID()) &&
            TIMEncryptedStorage.hasValue(id: TIMDataStorageStoreId.keyId(userId).storeID())
    }

    func hasBiometricAccessForRefreshToken(userId: String) -> Bool {
        guard let keyId: String = get(storeID: .keyId(userId)) else {
            return false
        }
        return TIMEncryptedStorage.hasBiometricProtectedValue(id: TIMDataStorageStoreId.refreshToken(userId).storeID(), keyId: keyId)
    }

    func disableBiometricAccessForRefreshToken(userId: String) {
        guard let keyId: String = get(storeID: .keyId(userId)) else {
            return
        }
        TIMEncryptedStorage.removeLongSecret(keyId: keyId)
    }

    func clear(userId: String) {
        if let keyId: String = get(storeID: .keyId(userId)) {
            TIMEncryptedStorage.removeLongSecret(keyId: keyId)
        }

        for id in TIMDataStorageStoreId.allUserSpecificCases(userId: userId) {
            TIMEncryptedStorage.remove(id: id.storeID())
        }

        removeAvailableUserId(userId: userId)
    }
}

// MARK: - Actual callback implementation

/// Actual implementation using callbacks.
/// From iOS 13 these are still used, but wrapped in a Combine interface with `Future`.
@available(iOS, deprecated: 13)
extension TIMDataStorageInternal {
    func getStoredRefreshToken(userId: String, password: String, completion: @escaping (Result<String, TIMError>) -> Void) {
        guard let keyId: String = get(storeID: .keyId(userId)) else {
            completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
            return
        }
        TIMEncryptedStorage.get(id: TIMDataStorageStoreId.refreshToken(userId).storeID(), keyId: keyId, secret: password, completion: { (result) in
            switch result {
            case .success(let rtData):
                if let refreshToken = JWT.convert(data: rtData) {
                    completion(.success(refreshToken))
                } else {
                    completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
                }
            case .failure(let error):
                completion(.failure(.storage(.encryptedStorageFailed(error))))
            }
        })
    }

    func getStoredRefreshTokenViaBiometric(userId: String, completion: @escaping (Result<BiometricRefreshToken, TIMError>) -> Void) {
        guard let keyId: String = get(storeID: .keyId(userId)) else {
            completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
            return
        }
        TIMEncryptedStorage.getViaBiometric(id: TIMDataStorageStoreId.refreshToken(userId).storeID(), keyId: keyId) { (result) in
            switch result {
            case .success(let model):
                if let refreshToken = JWT.convert(data: model.data) {
                    let bioRT = BiometricRefreshToken(refreshToken: refreshToken, longSecret: model.longSecret)
                    completion(.success(bioRT))
                } else {
                    completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
                }
            case .failure(let error):
                completion(.failure(.storage(.encryptedStorageFailed(error))))
            }
        }
    }

    func storeRefreshToken(_ refreshToken: JWT, withExistingPassword password: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        guard let userId: String = refreshToken.userId,
              let keyId: String = get(storeID: .keyId(userId)) else {
            completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
            return
        }

        TIMEncryptedStorage.store(
            id: TIMDataStorageStoreId.refreshToken(userId).storeID(),
            data: refreshToken.convert(),
            keyId: keyId,
            secret: password) { (result) in
            switch result {
            case .success:
                self.addAvailableUserId(userId: userId)
                completion(.success(Void()))
            case .failure(let error):
                completion(.failure(.storage(.encryptedStorageFailed(error))))
            }
        }
    }

    func storeRefreshToken(_ refreshToken: JWT, withNewPassword newPassword: String, completion: @escaping (Result<TIMESKeyCreationResult, TIMError>) -> Void) {
        guard let userId: String = refreshToken.userId else {
            completion(.failure(.storage(.encryptedStorageFailed(.failedToStoreInKeychain))))
            return
        }

        TIMEncryptedStorage.storeWithNewKey(
            id: TIMDataStorageStoreId.refreshToken(userId).storeID(),
            data: refreshToken.convert(),
            secret: newPassword,
            completion: { (result) in
                switch result {
                case .success(let creationResult):
                    let success = self.store(data: creationResult.keyId, storeID: .keyId(userId))
                    if !success {
                        completion(.failure(.storage(.encryptedStorageFailed(.failedToStoreInKeychain))))
                    } else {
                        self.addAvailableUserId(userId: userId)
                        completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
                    }
                case .failure:
                    completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
                }
            }
        )
    }

    func enableBiometricAccessForRefreshToken(password: String, userId: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        guard let keyId: String = get(storeID: .keyId(userId)) else {
            completion(.failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain))))
            return
        }
        TIMEncryptedStorage.enableBiometric(keyId: keyId, secret: password) { (result) in
            completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
        }
    }

    func enableBiometricAccessForRefreshToken(longSecret: String, userId: String) -> Result<Void, TIMError> {
        guard let keyId: String = get(storeID: .keyId(userId)) else {
            return .failure(.storage(.encryptedStorageFailed(.failedToLoadDataInKeychain)))
        }
        return TIMEncryptedStorage.enableBiometric(keyId: keyId, longSecret: longSecret)
            .mapError({ TIMError.storage(.encryptedStorageFailed($0)) })
    }
}

//MARK: - Combine wrappers
#if canImport(Combine)
@available(iOS 13, *)
extension TIMDataStorageInternal {
    func getStoredRefreshToken(userId: String, password: String) -> Future<JWT, TIMError> {
        Future { promise in
            self.getStoredRefreshToken(userId: userId, password: password, completion: promise)
        }
    }

    func getStoredRefreshTokenViaBiometric(userId: String) -> Future<BiometricRefreshToken, TIMError> {
        Future { promise in
            self.getStoredRefreshTokenViaBiometric(userId: userId, completion: promise)
        }
    }

    func storeRefreshToken(_ refreshToken: JWT, withExistingPassword password: String) -> Future<Void, TIMError> {
        Future { promise in
            self.storeRefreshToken(refreshToken, withExistingPassword: password, completion: promise)
        }
    }

    func storeRefreshToken(_ refreshToken: JWT, withNewPassword newPassword: String) -> Future<TIMESKeyCreationResult, TIMError> {
        Future { promise in
            self.storeRefreshToken(refreshToken, withNewPassword: newPassword, completion: promise)
        }
    }

    func enableBiometricAccessForRefreshToken(password: String, userId: String) -> Future<Void, TIMError> {
        Future { promise in
            self.enableBiometricAccessForRefreshToken(password: password, userId: userId, completion: promise)
        }
    }
}
#endif
