import Foundation

/// Configuration for OpenID Connect server (TIM server)
public struct TIMOpenIDConfiguration {

    /// The issuer
    public let issuer: URL

    /// The clientId
    public let clientId: String

    /// The redirectUri received by the app
    public let redirectUri: URL

    /// Scopes
    public let scopes: [String]
    
    /// Scopes
    public let additionalParameters: [String: String]

    /// Constructor
    public init(issuer: URL, clientId: String, redirectUri: URL, scopes: [String], additionalParameters: [String: String] = [:]) {
        self.issuer = issuer
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.scopes = scopes
        self.additionalParameters = additionalParameters
    }
}
