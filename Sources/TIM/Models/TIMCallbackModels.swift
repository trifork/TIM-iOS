import Foundation

/// Biometric protected refreshtoken load result
public struct BiometricRefreshToken {

    /// Refresh token
    public let refreshToken: JWT

    /// Long secret used to load the refresh token
    public let longSecret: String
}

/// Wrapper class for a `JWTString`. This class is used to guarantee that a token always is accompanied with a valid userId and expire timestamp.
public struct JWT {
    /// JWT token
    public let token: JWTString

    /// User ID from token's `sub` parameter
    public let userId: String

    /// The expiration date from the `exp` parameter
    /// This value is optional, since isn't required on refresh tokens.
    public let expireDate: Date?

    /// Failable initializer for `JWT`.
    /// This will only succeed if the token contains a `sub` parameter.
    public init?(token: JWTString) {
        self.token = token
        if let userId = token.userId {
            self.userId = userId
        } else {
            return nil
        }

        if let expireTimestamp = token.expireTimestamp {
            self.expireDate = Date(timeIntervalSince1970: expireTimestamp)
        } else {
            self.expireDate = nil
        }
    }
}
