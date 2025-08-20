//
//  AccountDetails.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/29.
//

import Foundation

public class AccountDetails: Codable {
    var id: Int
    var accountId: String
    var accountName: String
    var pubKey: String
    var priKey: String?
    var seedPhrase: String?
    var shardId: String?
    var delFlag: Bool?
    
    enum CodingKeys: String, CodingKey {
        case id = "id"
        case accountId = "accountId"
        case accountName = "accountName"
        case pubKey = "pubKey"
        case priKey = "priKey"
        case seedPhrase = "seedPhrase"
        case shardId = "shardId"
        case delFlag = "delFlag"
    }
    
    init(id: Int, accountId: String, accountName: String, pubKey: String, priKey: String? = nil, seedPhrase: String? = nil) {
        self.id = id
        self.accountId = accountId
        self.accountName = accountName
        self.pubKey = pubKey
        self.priKey = priKey
        self.seedPhrase = seedPhrase
        self.shardId = ""
    }
}
