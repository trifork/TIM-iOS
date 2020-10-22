import Foundation

/// Biometric protected refreshtoken load result
public struct BiometricRefreshToken {

    /// Refresh token
    public let refreshToken: String

    /// Long secret used to load the refresh token
    public let longSecret: String
}
