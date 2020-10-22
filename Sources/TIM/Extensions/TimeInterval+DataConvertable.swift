import Foundation

extension TimeInterval : DataConvertable {
    func convert() -> Data {
        var value = self
        return withUnsafePointer(to: &value) {
            Data(bytes: UnsafePointer($0), count: MemoryLayout.size(ofValue: self))
        }
    }

    static func convert(data: Data) -> TimeInterval? {
        data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> TimeInterval in
            ptr.load(as: TimeInterval.self)
        }
    }
}
