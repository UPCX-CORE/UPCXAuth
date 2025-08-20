//
//  ShareDetails.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/29.
//

import Foundation

public class ShareDetails: Codable {
    var shares: [String]
    
    enum CodingKeys: String, CodingKey {
        case shares = "shares"
    }
    
    init(shares: [String]) {
        self.shares = shares
    }
}
