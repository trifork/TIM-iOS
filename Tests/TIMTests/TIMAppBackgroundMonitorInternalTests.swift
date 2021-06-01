@testable import TIM
import XCTest

#if canImport(Combine)
import Combine
#endif

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

    #if canImport(Combine)
    @available(iOS 13, *)
    func testMultipleTimeoutsForCombine() {
        var cancelBag = Set<AnyCancellable>()
        let expect = XCTestExpectation(description: "Combine publisher should be invoked 4 times.")
        expect.expectedFulfillmentCount = 4
        let monitor = TIMAppBackgroundMonitorInternal()
        monitor.enable(durationSeconds: 1)
            .sink { _ in
                expect.fulfill()
            }
            .store(in: &cancelBag)

        XCTAssertEqual(monitor.timeoutDurationSeconds, 1)

        for _ in 0 ..< 4 {
            // Go to background, wait two seconds and go active again. Repeat 4 times to verify that the publisher is invoked multiple times.
            NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
            XCTAssertNotNil(monitor.backgroundTimestamp)

            let waitExpect = XCTestExpectation()
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(1100)) {
                NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
                waitExpect.fulfill()
            }
            wait(for: [waitExpect], timeout: 2.0)
        }
        wait(for: [expect], timeout: 10.0)
    }
    #endif
}
