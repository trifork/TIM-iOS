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


    /// Constructor, `import TIMEncryptedStorage` to construct key service model.
    public init(oidc: TIMOpenIDConfiguration, keyService: TIMKeyServiceConfiguration, encryptionMethod: TIMESEncryptionMethod) {
        self.oidcConfiguration = oidc
        self.keyServiceConfiguration = keyService
        self.encryptionMethod = encryptionMethod
    }
}
