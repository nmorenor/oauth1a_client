//
//  Token.swift
//  PlayusOAuth1a
//
//  Created by nacho on 10/30/17.
//
//

import Foundation

public struct Token {
    
    public let key: String
    public let secret: String
    
    init(key: String, secret: String) {
        self.key = key
        self.secret = secret
    }
}
