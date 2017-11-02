//
//  OauthConsumer.swift
//  PlayusOAuth1a
//
//  Created by nacho on 10/28/17.
//
//

import Foundation

public struct OAuthConsumer {
    
    public let key: String
    public let secret: String
    
    init(key: String, secret: String) {
        self.key = key
        self.secret = secret
    }
}
