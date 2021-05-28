@testable import TIM
import XCTest

final class TIMAppBackgroundMonitorInternalTests: XCTestCase {
    func testNoTimeout() {

        let expect = XCTestExpectation()
        let monitor = TIMAppBackgroundMonitorInternal()
        monitor.enable(durationSeconds: 10) {
            XCTFail("Should not be invoked!")
        }
        XCTAssertEqual(monitor.timeoutDurationSeconds, 10)

        // Go to background, wait a second, and go active again.
        NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
        XCTAssertNotNil(monitor.backgroundTimestamp)

        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(1)) {
            NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
            expect.fulfill()
        }
        wait(for: [expect], timeout: 2.0)
    }

    func testTimeout() {
        let expect = XCTestExpectation()
        let monitor = TIMAppBackgroundMonitorInternal()
        monitor.enable(durationSeconds: 1) {
            expect.fulfill()
        }
        XCTAssertEqual(monitor.timeoutDurationSeconds, 1)

        // Go to background, wait a second, and go active again.
        NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
        XCTAssertNotNil(monitor.backgroundTimestamp)

        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(2)) {
            NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
        }
        wait(for: [expect], timeout: 10.0)
    }

    func testDisable() {
        let expect = XCTestExpectation()
        let monitor = TIMAppBackgroundMonitorInternal()
        monitor.enable(durationSeconds: 1) {
            XCTFail("Should not be invoked, since it was disabled!")
        }
        XCTAssertEqual(monitor.timeoutDurationSeconds, 1)
        monitor.disable()

        // Go to background and see that nothing happens...
        NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
        XCTAssertNil(monitor.backgroundTimestamp)


        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(2)) {
            NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
            expect.fulfill()
        }
        wait(for: [expect], timeout: 10.0)
    }
}
