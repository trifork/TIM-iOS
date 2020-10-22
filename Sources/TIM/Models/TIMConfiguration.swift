import Foundation
import TIMEncryptedStorage

/// Combined configuration for AppAuth and TIMEncryptedStorage
public struct TIMConfiguration {
    /// OIDC configuration
    public let oidcConfiguration: TIMOpenIDConfiguration

    /// KeyService configuration
    public let keyServiceConfiguration: TIMKeyServiceConfiguration


    /// Constructor, `import TIMEncryptedStorage` to construct key service model.
    public init(oidc: TIMOpenIDConfiguration, keyService: TIMKeyServiceConfiguration) {
        self.oidcConfiguration = oidc
        self.keyServiceConfiguration = keyService
    }
}
