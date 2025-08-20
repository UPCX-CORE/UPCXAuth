//
//  Util.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/28.
//

import Foundation

extension UInt8 {
    var hex:String {
        return "0x" + String(format: "%02x", self)
    }
}

enum DataError : Error {
    case encoding
    case cryptoRandom
    case range(Range<Int>)
    case utfEncoding
}

extension Data {
    static func random(size:Int) throws -> Data {
        var result = [UInt8](repeating: 0, count: size)
        let res = SecRandomCopyBytes(kSecRandomDefault, size, &result)
        
        guard res == 0 else {
            throw DataError.cryptoRandom
        }
        
        return Data(result)
    }
    
    func utf8String() throws -> String {
        guard let utf8String = String(data: self, encoding: String.Encoding.utf8) else {
            throw DataError.utfEncoding
        }
        return utf8String
    }
    
    var bytes: [UInt8] {
        return self.toArray(type: UInt8.self)
    }
    
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }

    init<T>(fromArray values: [T]) {
        self = values.withUnsafeBytes { Data($0) }
    }
    
    func toArray<T>(type: T.Type) -> [T] where T: ExpressibleByIntegerLiteral {
        var array = Array<T>(repeating: 0, count: self.count/MemoryLayout<T>.stride)
        _ = array.withUnsafeMutableBytes { copyBytes(to: $0) }
        return array
    }
}
