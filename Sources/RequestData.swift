//
//  RequestData.swift
//  PlayusOAuth1a
//
//  Created by nacho on 10/30/17.
//
//

import Foundation

public struct RequestData {
    
    public var includeBodyHash: Bool  = true
    public let url: String
    public let method: String
    public let data: String
    
    init(url: String, method: String) {
        self.init(url: url, method: method, data: nil)
    }
    
    init(url: String, method: String, data: String?) {
        self.url = url
        self.method = method
        self.data = data ?? "{}"
    }
}
