import Foundation
import TIMEncryptedStorage

/// Combined configuration for AppAuth and TIMEncryptedStorage
public struct TIMConfiguration {
    /// OIDC configuration
    public let oidcConfiguration: TIMOpenIDConfiguration

    /// KeyService configuration
    public let keyServiceConfiguration: TIMKeyServiceConfiguration

    /// The encryption method used by TIM, AES GCM is recommended!
    public let encryptionMethod: TIMESEncryptionMethod


    /// Default constructor
    /// - Parameters:
    ///   - timBaseUrl: TIM base URL, e.g. https://trifork.com
    ///   - realm: Realm, e.g. `"my-test-realm"`
    ///   - clientId: Client Id, e.g. `"my-client"`
    ///   - redirectUri: Redirect URI, e.g. `"my-app:/"`
    ///   - scopes: Scopes, e.g. `["scope"]`
    ///   - encryptionMethod: Encryption method, e.g. `.aesGcm`
    ///   - keyServiceVersion: Optional key service version, defaults to `.v1`
    ///   - additionalParameters: Optional additional parameters, for e.g. app-switch `[:]`
    public init(timBaseUrl: URL, realm: String, clientId: String, redirectUri: URL, scopes: [String], encryptionMethod: TIMESEncryptionMethod, keyServiceVersion: TIMKeyServiceVersion = .v1, additionalParameters: [String, String]? = nil) {

        let fullTimUrl = timBaseUrl.appendingPathComponent("/auth/realms/\(realm)")
        self.oidcConfiguration = TIMOpenIDConfiguration(
            issuer: fullTimUrl,
            clientId: clientId,
            redirectUri: redirectUri,
            scopes: scopes,
            additionalParameters: additionalParameters
        )
        self.keyServiceConfiguration = TIMKeyServiceConfiguration(realmBaseUrl: fullTimUrl.absoluteString, version: keyServiceVersion)
        self.encryptionMethod = encryptionMethod
    }

    /// Advanced custom constructor, `import TIMEncryptedStorage` to construct key service model.
    public init(oidc: TIMOpenIDConfiguration, keyService: TIMKeyServiceConfiguration, encryptionMethod: TIMESEncryptionMethod) {
        self.oidcConfiguration = oidc
        self.keyServiceConfiguration = keyService
        self.encryptionMethod = encryptionMethod
    }
}
