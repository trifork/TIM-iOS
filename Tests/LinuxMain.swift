import XCTest

import TIMTests

var tests = [XCTestCaseEntry]()
tests += DataConvertableTests.allTests()
tests += JWTExtensionsTests.allTests()
XCTMain(tests)
