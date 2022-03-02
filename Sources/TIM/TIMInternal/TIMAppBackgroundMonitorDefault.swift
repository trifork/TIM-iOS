import UIKit

public class TIMAppBackgroundMonitorDefault : TIMAppBackgroundMonitor {
    private (set) var timeoutDurationSeconds: TimeInterval?
    private (set) var backgroundTimestamp: Date?
    private var handleTimeoutEvent: (() -> Void)?

    public init() { }

    deinit {
        disable()
    }

    public func enable(durationSeconds: TimeInterval, timeoutHandler: @escaping () -> Void) {
        disable()
        timeoutDurationSeconds = durationSeconds
        handleTimeoutEvent = timeoutHandler
        subscribeForEvents()
    }

    public func disable() {
        handleTimeoutEvent = nil
        timeoutDurationSeconds = nil
        unsubscribeForEvents()
    }

    private func subscribeForEvents() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidBecomeActive),
            name: UIApplication.didBecomeActiveNotification,
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidResignActive),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
    }

    private func unsubscribeForEvents() {
        NotificationCenter.default.removeObserver(
            self,
            name: UIApplication.didBecomeActiveNotification,
            object: nil
        )
        NotificationCenter.default.removeObserver(
            self,
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
    }

    @objc
    private func appDidBecomeActive() {
        guard  let timeoutDurationSeconds = timeoutDurationSeconds,
               let backgroundTimestamp = backgroundTimestamp else {
            return
        }
        if -backgroundTimestamp.timeIntervalSinceNow > timeoutDurationSeconds {
            handleTimeoutEvent?()
            self.backgroundTimestamp = nil // Reset
        }
    }

    @objc
    private func appDidResignActive() {
        backgroundTimestamp = Date()
    }
}
