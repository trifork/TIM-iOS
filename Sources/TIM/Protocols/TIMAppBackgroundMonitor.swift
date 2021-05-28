import Foundation
#if canImport(Combine)
import Combine
#endif

/// Registers how long the app has been in the background, and
/// invokes a timeout event when the app becomes active if the background time has exceeded the timeout value.
public protocol TIMAppBackgroundMonitor {

    /// Enables detection of the duration the app has been in the background.
    /// - Parameters:
    ///   - durationSeconds: The duration (seconds) the app may be in the background. When this value is exceeded it will invoke "handleTimeout".
    ///   - handleTimeout: The function that is invoked when the timeout occurs.
    func enable(durationSeconds: TimeInterval, handleTimeout: @escaping () -> Void)

    /// Disables the background duration detection.
    func disable()
}

#if canImport(Combine)
extension TIMAppBackgroundMonitor {
    /// Combine wrapper of `enable(durationSeconds:handleTimeout:)`
    @available(iOS 13, *)
    func enable(durationSeconds: TimeInterval) -> Future<Void, Never> {
        Future { promise in
            enable(durationSeconds: durationSeconds) {
                promise(.success(Void()))
            }
        }
    }
}
#endif

