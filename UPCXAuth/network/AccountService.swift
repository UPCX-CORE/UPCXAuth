//
//  AccountService.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/29.
//

import Foundation

public class AccountService {
    public func getAccountFromName(accountName: String, namingServerUrl: String, _ completion: ((AccountDetails?) -> Void)? = nil) {
        let callUrl = namingServerUrl + "/users/" + accountName
        let url = URL(string: callUrl)!
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data,
                  let response = response as? HTTPURLResponse,
                  error == nil else {
                      print("error", error ?? "Unknown error")
                    completion?(nil)
                      return
                  }
            
            guard (200 ... 299) ~= response.statusCode else {
                print("statusCode should be 2xx, but is \(response.statusCode)")
                print("response = \(response)")
                completion?(nil)
                return
            }
            
            do {
                let decodedObject = try JSONDecoder().decode(AccountDetails.self, from: data)
                completion?(decodedObject)
            } catch {
                debugPrint(error)
            }
        }
        
        task.resume()
    }
    
    public func getAccountFromPubkey(pubKey: String, namingServerUrl: String, _ completion: (([AccountDetails]?) -> Void)? = nil) {
        let callUrl = namingServerUrl + "/users/pubkey/" + pubKey
        let url = URL(string: callUrl)!
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data,
                  let response = response as? HTTPURLResponse,
                  error == nil else {
                      print("error", error ?? "Unknown error")
                    completion?(nil)
                      return
                  }
            
            guard (200 ... 299) ~= response.statusCode else {
                print("statusCode should be 2xx, but is \(response.statusCode)")
                print("response = \(response)")
                completion?(nil)
                return
            }
            
            do {
                let decodedObject = try JSONDecoder().decode([AccountDetails].self, from: data)
                completion?(decodedObject)
            } catch {
                debugPrint(error)
            }
        }
        
        task.resume()
    }
    
    public func createAccount(namingServerUrl: String, shardId: String, accountName: String, pubKey: String, _ completion: ((AccountDetails?) -> Void)? = nil) {
        let callUrl = namingServerUrl + "/users"
        let url = URL(string: callUrl)!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        let parameters: [String: String] = [
            "shardId": shardId,
            "accountName": accountName,
            "pubKey": pubKey
        ]
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .prettyPrinted) // pass dictionary to nsdata object and set it as request body
        } catch let error {
            print(error.localizedDescription)
            completion!(nil)
        }
        
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data,
                  let response = response as? HTTPURLResponse,
                  error == nil else {
                      print("error", error ?? "Unknown error")
                    completion?(nil)
                      return
                  }
            
            guard (200 ... 299) ~= response.statusCode else {
                print(data)
                print("statusCode should be 2xx, but is \(response.statusCode)")
                print("response = \(response)")
                completion?(nil)
                return
            }
            
            do {
                let decodedObject = try JSONDecoder().decode(AccountDetails.self, from: data)
                completion?(decodedObject)
            } catch {
                debugPrint(error)
            }
        }
        
        task.resume()
    }
}
