//
//  AuthNodeService.swift
//  UPCXAuth
//
//  Created by arthur on 2025/07/29.
//

import Foundation

public class AuthNodeService {
    
    let AUTH_NODE_SERVER = "https://upcx-auth.com:5000"
    
    public func getAuthShares(accessToken: String, poolId: String, _ completion: ((ShareDetails?) -> Void)? = nil) {
        let callUrl = AUTH_NODE_SERVER + "/auth?accessToken=\(accessToken)&poolID=\(poolId)"
        print(callUrl)
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
                let decodedObject = try JSONDecoder().decode(ShareDetails.self, from: data)
                completion?(decodedObject)
            } catch {
                debugPrint(error)
            }
        }
        
        task.resume()
    }
    
    public func saveShares(accessToken: String, poolID: String, shares: [String], _ completion: ((Bool?) -> Void)? = nil) {
        let callUrl = AUTH_NODE_SERVER + "/auth"
        let url = URL(string: callUrl)!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        let parameters: [String: Any] = [
            "poolID": poolID,
            "accessToken": accessToken,
            "shares": shares
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
                let decodedObject = try JSONDecoder().decode(Bool.self, from: data)
                completion?(decodedObject)
            } catch {
                debugPrint(error)
            }
        }
        
        task.resume()
    }
}
