import Foundation
import os.log

/// Logger protocol to receive log messages internally from TIM.
public protocol TIMLoggerProtocol {

    /// Logs a `StaticString` with some optional arguments.
    /// - Parameters:
    ///   - message: Message
    ///   - args: Arguments for `message`
    func log(_ message: StaticString, _ args: CVarArg...)
}


/// Default logger implementation for TIM (using `os_log` or `print` depending on the iOS version)
public final class TIMLogger : TIMLoggerProtocol {

    /// Constructor
    public init() {
        
    }

    /// Console logging
    public func log(_ message: StaticString, _ args: CVarArg...) {
        if #available(iOS 10, *) {
            os_log(message, args)
        } else {
            print(message, args)
        }
    }
}
