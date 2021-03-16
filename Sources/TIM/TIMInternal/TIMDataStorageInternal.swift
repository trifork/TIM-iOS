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
    private func store<T : DataConvertable>(data: T, storeID: TIMDataStorageStoreId) -> Result<Void, TIMKeychainError> {
        let item = TIMKeychainStoreItem(id: storeID.storeID())
        return TIMKeychain.store(data: data.convert(), item: item)
    }

    private func get<T: DataConvertable>(storeID: TIMDataStorageStoreId) -> Result<T, TIMKeychainError> {
        let item = TIMKeychainStoreItem(id: storeID.storeID())
        return TIMKeychain.get(item: item)
            .flatMap { (data) -> Result<T, TIMKeychainError> in
                guard let converted = T.convert(data: data) else {
                    return .failure(TIMKeychainError.failedToLoadData)
                }
                return .success(converted)
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

    private func disableCurrentBiometricAccess(userId: String) {
        if let keyId: String = (try? get(storeID: .keyId(userId)).get()) {
            TIMEncryptedStorage.removeLongSecret(keyId: keyId)
        }
    }

    // MARK: - Internal
    func storeRefreshTokenWithBiometricAccess(_ refreshToken: JWT, longSecret: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMKeychainError> = get(storeID: .keyId(refreshToken.userId))
        switch keyIdResult {
        case .failure(let keychainError):
            completion(.failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError)))))
        case .success(let keyId):
            TIMEncryptedStorage.store(
                id: TIMDataStorageStoreId.refreshToken(refreshToken.userId).storeID(),
                data: refreshToken.token.convert(),
                keyId: keyId,
                longSecret: longSecret) { (result) in
                completion(result.mapError({ TIMError.storage(.encryptedStorageFailed($0)) }))
            }
        }
    }

    // MARK: -
    var availableUserIds: Set<String> {
        return (try? get(storeID: .availableUserIds).get()) ?? []
    }

    func hasRefreshToken(userId: String) -> Bool {
        TIMEncryptedStorage.hasValue(id: TIMDataStorageStoreId.refreshToken(userId).storeID()) &&
            TIMEncryptedStorage.hasValue(id: TIMDataStorageStoreId.keyId(userId).storeID())
    }

    func hasBiometricAccessForRefreshToken(userId: String) -> Bool {
        guard let keyId: String = (try? get(storeID: .keyId(userId)).get()) else {
            return false
        }
        return TIMEncryptedStorage.hasBiometricProtectedValue(id: TIMDataStorageStoreId.refreshToken(userId).storeID(), keyId: keyId)
    }

    func disableBiometricAccessForRefreshToken(userId: String) {
        guard let keyId: String = (try? get(storeID: .keyId(userId)).get()) else {
            return
        }
        TIMEncryptedStorage.removeLongSecret(keyId: keyId)
    }

    func clear(userId: String) {
        disableCurrentBiometricAccess(userId: userId)

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
    func getStoredRefreshToken(userId: String, password: String, completion: @escaping (Result<JWT, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMKeychainError> = get(storeID: .keyId(userId))
        switch keyIdResult {
        case .failure(let keychainError):
            completion(.failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError)))))
        case .success(let keyId):
            TIMEncryptedStorage.get(id: TIMDataStorageStoreId.refreshToken(userId).storeID(), keyId: keyId, secret: password, completion: { (result) in
                switch result {
                case .success(let rtData):
                    if let refreshToken = JWTString.convert(data: rtData),
                       let tokenResult = JWT(token: refreshToken) {
                        completion(.success(tokenResult))
                    } else {
                        completion(.failure(.storage(.encryptedStorageFailed(.unexpectedData))))
                    }
                case .failure(let error):
                    completion(.failure(.storage(.encryptedStorageFailed(error))))
                }
            })
        }

    }

    func getStoredRefreshTokenViaBiometric(userId: String, completion: @escaping (Result<BiometricRefreshToken, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMKeychainError> = get(storeID: .keyId(userId))

        switch keyIdResult {
        case .failure(let keychainError):
            completion(.failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError)))))
        case .success(let keyId):
            TIMEncryptedStorage.getViaBiometric(id: TIMDataStorageStoreId.refreshToken(userId).storeID(), keyId: keyId) { (result) in
                switch result {
                case .success(let model):
                    if let refreshToken = JWTString.convert(data: model.data), let jwt = JWT(token: refreshToken) {
                        let bioRT = BiometricRefreshToken(refreshToken: jwt, longSecret: model.longSecret)
                        completion(.success(bioRT))
                    } else {
                        completion(.failure(.storage(.encryptedStorageFailed(.unexpectedData))))
                    }
                case .failure(let error):
                    completion(.failure(.storage(.encryptedStorageFailed(error))))
                }
            }
        }
    }

    func storeRefreshToken(_ refreshToken: JWT, withExistingPassword password: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMKeychainError> = get(storeID: .keyId(refreshToken.userId))
        switch keyIdResult {
        case .failure(let keychainError):
            completion(.failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError)))))
        case .success(let keyId):
            TIMEncryptedStorage.store(
                id: TIMDataStorageStoreId.refreshToken(refreshToken.userId).storeID(),
                data: refreshToken.token.convert(),
                keyId: keyId,
                secret: password) { (result) in
                switch result {
                case .success:
                    self.addAvailableUserId(userId: refreshToken.userId)
                    completion(.success(Void()))
                case .failure(let error):
                    completion(.failure(.storage(.encryptedStorageFailed(error))))
                }
            }
        }
    }

    func storeRefreshToken(_ refreshToken: JWT, withNewPassword newPassword: String, completion: @escaping (Result<TIMESKeyCreationResult, TIMError>) -> Void) {
        TIMEncryptedStorage.storeWithNewKey(
            id: TIMDataStorageStoreId.refreshToken(refreshToken.userId).storeID(),
            data: refreshToken.token.convert(),
            secret: newPassword,
            completion: { (result) in
                switch result {
                case .success(let keyCreationData):
                    self.disableCurrentBiometricAccess(userId: refreshToken.userId)
                    let storeResult: Result<Void, TIMKeychainError> = self.store(data: keyCreationData.keyId, storeID: .keyId(refreshToken.userId))
                    switch storeResult {
                    case .failure(let keychainError):
                        completion(.failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError)))))
                    case .success:
                        self.addAvailableUserId(userId: refreshToken.userId)
                        completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
                    }
                case .failure:
                    completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
                }
            }
        )
    }

    func enableBiometricAccessForRefreshToken(password: String, userId: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMKeychainError> = get(storeID: .keyId(userId))
        switch keyIdResult {
        case .failure(let keychainError):
            completion(.failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError)))))
        case .success(let keyId):
            TIMEncryptedStorage.enableBiometric(keyId: keyId, secret: password) { (result) in
                completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
            }
        }
    }

    func enableBiometricAccessForRefreshToken(longSecret: String, userId: String) -> Result<Void, TIMError> {
        let keyIdResult: Result<String, TIMKeychainError> = get(storeID: .keyId(userId))
        switch keyIdResult {
        case .failure(let keychainError):
            return .failure(.storage(.encryptedStorageFailed(.keychainFailed(keychainError))))
        case .success(let keyId):
            return TIMEncryptedStorage.enableBiometric(keyId: keyId, longSecret: longSecret)
                .mapError({ TIMError.storage(.encryptedStorageFailed($0)) })
        }
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
