import TIMEncryptedStorage

#if canImport(Combine)
import Combine
#endif

/// This class is divided into two namespaces: `storage` and `auth`
///
/// OpenID Connect (AppAuth) operations are done through the `auth` namespace and storing secure data is done through the `storage` namespace.
public final class TIM {

    /// Optional logger. Set to `nil` to stop logging
    public static var logger: TIMLoggerProtocol?

    /// Handles all secure storage operations and interfaces with the key service.
    public static var storage: TIMDataStorage {
        if let storageInstance = _storage {
            return storageInstance
        } else {
            fatalError("You have to call the `configure(configuration:)` method before using TIM.storage!")
        }
    }
    private static var _storage: TIMDataStorage?

    /// Handles all authentication through OpenID Connect (AppAuth).
    ///
    /// This also know the storage namespace and will load and store things.
    public static var auth: TIMAuth {
        if let authInstance = _auth {
            return authInstance
        } else {
            fatalError("You have to call the `configure(configuration:)` method before using TIM.auth!")
        }
    }
    private static var _auth: TIMAuth?

    /// Indicates whether `TIM` was configured or not.
    public static var isConfigured: Bool {
        _auth != nil && _storage != nil
    }

    /// Configures the `TIM` class with default instances based on your configuration.
    /// This should be called before any other function or property is called on this class.
    ///
    /// This is the recommended configure method of `TIM`.
    ///
    /// **NOTE:** You should only call this method once. If called more than once, it will cause a `fatalError`. You can use the other configuration method for testing, which allows multiple invocations.
    ///
    /// - Parameters:
    ///   - configuration: TIMConfiguration
    ///   - customLogger: An optional custom logger for logging messages internally from `TIM`. Set to `nil` to disable logging.
    ///   - allowReconfigure: Controls whether you are allowed to call this method multiple times. It is **discouraged**, but possible if really needed... Default value is `false`.
    public static func configure(configuration: TIMConfiguration, customLogger: TIMLoggerProtocol? = TIMLogger(), allowReconfigure: Bool = false) {
        guard (_auth == nil && _storage == nil) || allowReconfigure else {
            fatalError("🛑 You shouldn't configure TIM more than once!")
        }

        let encryptedStorage = TIMEncryptedStorage(
            secureStorage: TIMKeychain(),
            keyService: TIMKeyService(configuration: configuration.keyServiceConfiguration),
            encryptionMethod: configuration.encryptionMethod
        )
        let storage = TIMDataStorageDefault(encryptedStorage: encryptedStorage)
        _auth = TIMAuthDefault(
            dataStorage: storage,
            openIdController: AppAuthController(configuration.oidcConfiguration),
            backgroundMonitor: TIMAppBackgroundMonitorDefault()
        )
        _storage = storage
        logger = customLogger
    }

    /// Configures the `TIM` class with custom instances of the interfaces.
    ///
    /// This can be useful when mocking for testing or other very custom scenarios.
    ///
    /// **THIS IS NOT THE USUAL WAY TO CONFIGURE TIM**
    ///
    /// See `configure(configuration:)` for the default configuration method.
    ///
    /// - Parameters:
    ///   - dataStorage: The data storage instance to use.
    ///   - auth: The auth
    ///   - customLogger: An optional custom logger for logging messages internally from `TIM`. Set to `nil` to disable logging.
    public static func configure(dataStorage: TIMDataStorage, auth: TIMAuth, customLogger: TIMLoggerProtocol?) {
        _auth = auth
        _storage = dataStorage
        logger = customLogger
    }
}
