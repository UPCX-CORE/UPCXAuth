//
//  Base58.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/24.
//

import Foundation
import BigInt

enum Base58 {
    static let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    static func encode(_ data: Data) -> String {
        var x = BigUInt(data)
        var result = ""
        while x > 0 {
            let (quotient, remainder) = x.quotientAndRemainder(dividingBy: 58)
            result = String(alphabet[String.Index(utf16Offset: Int(remainder), in: alphabet)]) + result
            x = quotient
        }

        // Leading zero bytes become '1'
        for byte in data {
            if byte == 0 {
                result = "1" + result
            } else {
                break
            }
        }

        return result
    }

    static func decode(_ string: String) -> Data? {
        var x = BigUInt(0)
        for char in string {
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            let digit = alphabet.distance(from: alphabet.startIndex, to: index)
            x = x * 58 + BigUInt(digit)
        }

        var data = x.serialize()

        // Add leading zero bytes
        for char in string {
            if char == "1" {
                data.insert(0, at: 0)
            } else {
                break
            }
        }

        return data
    }
}
