import XCTest
@testable import TIM

final class DataConvertableTests: XCTestCase {

    func testString() {
        let data = "someData".convert()
        let string = String.convert(data: data)
        XCTAssertEqual(string, "someData")
    }

    func testTimeInterval() {
        let data = TimeInterval(1337).convert()
        let timeInterval = TimeInterval.convert(data: data)
        XCTAssertEqual(timeInterval, 1337)
    }

    func testStringSet() {
        let data = Set(["1", "2"]).convert()
        let set = Set<String>.convert(data: data)
        XCTAssertEqual(set, ["1", "2"])
    }
}
