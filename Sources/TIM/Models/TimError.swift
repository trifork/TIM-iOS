import Foundation
import AppAuth
import TIMEncryptedStorage

/// Shared wrapper for Auth and Storage errors.
public enum TIMError: Error, LocalizedError {
    case auth(TIMAuthError)
    case storage(TIMStorageError)

    public var errorDescription: String? {
        switch self {
        case .auth(let error):
            return error.localizedDescription
        case .storage(let error):
            return error.localizedDescription
        }
    }
}
