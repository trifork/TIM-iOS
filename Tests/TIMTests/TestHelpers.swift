import XCTest
import Foundation

func XCTFailTest(
    message: String = "Should not have been called",
    file: StaticString = #filePath,
    line: UInt = #line
){
    XCTAssertTrue(false, message, file: file, line: line)
}
