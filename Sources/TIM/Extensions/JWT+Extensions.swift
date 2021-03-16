import Foundation

private let EXPIRE_KEY: String = "exp"
private let SUB_KEY: String = "sub"

/// Type alias for tokens - just a string.
public typealias JWTString = String

/// Extensions for default data on a JWT.
extension JWTString {

    /// `exp` value
    var expireTimestamp: TimeInterval? {
        JWTDecoder.decode(jwtToken: self)[EXPIRE_KEY] as? TimeInterval
    }

    /// `sub` value
    var userId: String? {
        JWTDecoder.decode(jwtToken: self)[SUB_KEY] as? String
    }
}
