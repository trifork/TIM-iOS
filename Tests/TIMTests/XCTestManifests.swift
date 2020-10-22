import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(DataConvertableTests.allTests),
        testCase(JWTExtensionsTests.allTests),
    ]
}
#endif
