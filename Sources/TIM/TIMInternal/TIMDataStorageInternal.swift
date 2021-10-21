import Foundation
import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

protocol DataConvertable {
    func convert() -> Data
    static func convert(data: Data) -> Self?
}

private enum TIMDataStorageID {
    case keyId(String)
    case refreshToken(String)
    case availableUserIds

    func toStorageId() -> StorageID {
        switch self {
        case .keyId(let uniqueUserId):
            return "keyId_\(uniqueUserId)"
        case .refreshToken(let uniqueUserId):
            return "refreshToken_\(uniqueUserId)"
        case .availableUserIds:
            return "availableUserIds"
        }
    }

    static func allUserSpecificCases(userId: String) -> [TIMDataStorageID] {
        return [
            .keyId(userId),
            .refreshToken(userId)
        ]
    }
}

final class TIMDataStorageInternal<SecureStorage: TIMSecureStorage> : TIMDataStorage {

    private let encryptedStorage: TIMEncryptedStorage<SecureStorage>

    init(encryptedStorage: TIMEncryptedStorage<SecureStorage>) {
        self.encryptedStorage = encryptedStorage
    }

    // MARK: - Private helpers for raw data in secure storage (NOT ENCRYPTED!)
    @discardableResult
    private func store<T : DataConvertable>(data: T, storageId: TIMDataStorageID) -> Result<Void, TIMSecureStorageError> {
        let item = SecureStorage.SecureStorageItem(id: storageId.toStorageId())
        return encryptedStorage.secureStorage.store(data: data.convert(), item: item)
    }

    private func get<T: DataConvertable>(storageId: TIMDataStorageID) -> Result<T, TIMSecureStorageError> {
        let item = SecureStorage.SecureStorageItem(id: storageId.toStorageId())
        return encryptedStorage.secureStorage.get(item: item)
            .flatMap { (data) -> Result<T, TIMSecureStorageError> in
                guard let converted = T.convert(data: data) else {
                    return .failure(TIMSecureStorageError.failedToLoadData("Failed to convert `Data` object to specified `\(T.Type.self)` type."))
                }
                return .success(converted)
            }
    }

    private func addAvailableUserId(userId: String) {
        var currentUserIds = availableUserIds
        currentUserIds.insert(userId)
        store(data: currentUserIds, storageId: .availableUserIds)
    }

    private func removeAvailableUserId(userId: String) {
        var currentUserIds = availableUserIds
        currentUserIds.remove(userId)
        store(data: currentUserIds, storageId: .availableUserIds)
    }

    private func disableCurrentBiometricAccess(userId: String) {
        if let keyId: String = (try? get(storageId: .keyId(userId)).get()) {
            encryptedStorage.removeLongSecret(keyId: keyId)
        }
    }

    // MARK: -
    var availableUserIds: Set<String> {
        return (try? get(storageId: .availableUserIds).get()) ?? []
    }

    func hasRefreshToken(userId: String) -> Bool {
        encryptedStorage.hasValue(id: TIMDataStorageID.refreshToken(userId).toStorageId()) &&
            encryptedStorage.hasValue(id: TIMDataStorageID.keyId(userId).toStorageId())
    }

    func hasBiometricAccessForRefreshToken(userId: String) -> Bool {
        guard let keyId: String = (try? get(storageId: .keyId(userId)).get()) else {
            return false
        }
        return encryptedStorage.hasBiometricProtectedValue(id: TIMDataStorageID.refreshToken(userId).toStorageId(), keyId: keyId)
    }

    func disableBiometricAccessForRefreshToken(userId: String) {
        guard let keyId: String = (try? get(storageId: .keyId(userId)).get()) else {
            return
        }
        encryptedStorage.removeLongSecret(keyId: keyId)
    }

    func clear(userId: String) {
        disableCurrentBiometricAccess(userId: userId)

        for id in TIMDataStorageID.allUserSpecificCases(userId: userId) {
            encryptedStorage.remove(id: id.toStorageId())
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
        let keyIdResult: Result<String, TIMSecureStorageError> = get(storageId: .keyId(userId))
        switch keyIdResult {
        case .failure(let secureStorageError):
            let error = mapAndHandleKeyIdLoadError(secureStorageError, userId: userId)
            completion(.failure(error))
        case .success(let keyId):
            encryptedStorage.get(id: TIMDataStorageID.refreshToken(userId).toStorageId(), keyId: keyId, secret: password, completion: { (result) in
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

    func getStoredRefreshTokenViaBiometric(userId: String, willBeginNetworkRequests: WillBeginNetworkRequestsCallback? = nil, completion: @escaping (Result<BiometricRefreshToken, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMSecureStorageError> = get(storageId: .keyId(userId))

        switch keyIdResult {
        case .failure(let secureStorageError):
            let error = mapAndHandleKeyIdLoadError(secureStorageError, userId: userId)
            completion(.failure(error))
        case .success(let keyId):
            encryptedStorage.getViaBiometric(id: TIMDataStorageID.refreshToken(userId).toStorageId(), keyId: keyId, willBeginNetworkRequests: willBeginNetworkRequests) { (result) in
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
        let keyIdResult: Result<String, TIMSecureStorageError> = get(storageId: .keyId(refreshToken.userId))
        switch keyIdResult {
        case .failure(let secureStorageError):
            let error = mapAndHandleKeyIdLoadError(secureStorageError, userId: refreshToken.userId)
            completion(.failure(error))
        case .success(let keyId):
            encryptedStorage.store(
                id: TIMDataStorageID.refreshToken(refreshToken.userId).toStorageId(),
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
        encryptedStorage.storeWithNewKey(
            id: TIMDataStorageID.refreshToken(refreshToken.userId).toStorageId(),
            data: refreshToken.token.convert(),
            secret: newPassword,
            completion: { (result) in
                switch result {
                case .success(let keyCreationData):
                    self.disableCurrentBiometricAccess(userId: refreshToken.userId)
                    let storeResult: Result<Void, TIMSecureStorageError> = self.store(data: keyCreationData.keyId, storageId: .keyId(refreshToken.userId))
                    switch storeResult {
                    case .failure(let secureStorageError):
                        completion(.failure(.storage(.encryptedStorageFailed(.secureStorageFailed(secureStorageError)))))
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
        let keyIdResult: Result<String, TIMSecureStorageError> = get(storageId: .keyId(userId))
        switch keyIdResult {
        case .failure(let secureStorageError):
            let error = mapAndHandleKeyIdLoadError(secureStorageError, userId: userId)
            completion(.failure(error))
        case .success(let keyId):
            encryptedStorage.enableBiometric(keyId: keyId, secret: password) { (result) in
                completion(result.mapError({ .storage(.encryptedStorageFailed($0)) }))
            }
        }
    }

    func enableBiometricAccessForRefreshToken(longSecret: String, userId: String) -> Result<Void, TIMError> {
        let keyIdResult: Result<String, TIMSecureStorageError> = get(storageId: .keyId(userId))
        switch keyIdResult {
        case .failure(let secureStorageError):
            let error = mapAndHandleKeyIdLoadError(secureStorageError, userId: userId)
            return .failure(error)
        case .success(let keyId):
            return encryptedStorage.enableBiometric(keyId: keyId, longSecret: longSecret)
                .mapError({ TIMError.storage(.encryptedStorageFailed($0)) })
        }
    }

    func storeRefreshTokenWithLongSecret(_ refreshToken: JWT, longSecret: String, completion: @escaping (Result<Void, TIMError>) -> Void) {
        let keyIdResult: Result<String, TIMSecureStorageError> = get(storageId: .keyId(refreshToken.userId))
        switch keyIdResult {
        case .failure(let secureStorageError):
            completion(.failure(.storage(.encryptedStorageFailed(.secureStorageFailed(secureStorageError)))))
        case .success(let keyId):
            encryptedStorage.store(
                id: TIMDataStorageID.refreshToken(refreshToken.userId).toStorageId(),
                data: refreshToken.token.convert(),
                keyId: keyId,
                longSecret: longSecret) { (result) in
                completion(result.mapError({ TIMError.storage(.encryptedStorageFailed($0)) }))
            }
        }
    }

    private func mapAndHandleKeyIdLoadError(_ secureStorageError: TIMSecureStorageError, userId: String) -> TIMError {
        switch secureStorageError {
        case .failedToLoadData: // Failed to load keyId!
            clear(userId: userId)
            return .storage(.incompleteUserDataSet)
        default:
            return .storage(.encryptedStorageFailed(.secureStorageFailed(secureStorageError)))
        }
    }
}
