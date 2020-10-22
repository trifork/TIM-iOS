import Foundation

extension String : DataConvertable {
    func convert() -> Data {
        Data(self.utf8)
    }

    static func convert(data: Data) -> String? {
        String(data: data, encoding: .utf8)
    }
}

extension Set: DataConvertable where Element == String {
    func convert() -> Data {
        (try? JSONEncoder().encode(self)) ?? Data()
    }

    static func convert(data: Data) -> Set<Element>? {
        try? JSONDecoder().decode(Set<Element>.self, from: data)
    }
}
