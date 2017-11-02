//
//  OAuthData.swift
//  PlayusOAuth1a
//
//  Created by nacho on 10/30/17.
//
//

import Foundation

public class OAuthData {
    
    public var consumerKey: String
    public var nonce: String
    public var signatureMethod: String
    public var timestamp: String
    public var oauthVersion: String
    public var oauthToken: String?
    public var oauthSecret: String?
    public var oauthBodyHash: String?
    public var oauthSignature: String?
    
    convenience init(consumerKey: String, nonce: String, signatureMethod: String, timestamp: String, version: String) {
        self.init(consumerKey: consumerKey, nonce: nonce, signatureMethod: signatureMethod, timestamp: timestamp, version: version, token: nil, secret: nil)
    }
    
    init(consumerKey: String, nonce: String, signatureMethod: String, timestamp: String, version: String, token: String?, secret: String?) {
        self.consumerKey = consumerKey
        self.nonce = nonce;
        self.signatureMethod = signatureMethod
        self.oauthVersion = version
        self.timestamp = timestamp
        self.oauthSecret = secret
        self.oauthToken = token
    }
    
    public func asParameters() -> Array<Parameter> {
        var result: Array<Parameter> = []
        result.append(Parameter(k: OAuth.OAUTH_CONSUMER_KEY, val: self.consumerKey))
        result.append(Parameter(k: OAuth.OAUTH_NONCE, val: self.nonce))
        result.append(Parameter(k: OAuth.OAUTH_SIGNATURE_METHOD, val: self.signatureMethod))
        result.append(Parameter(k: OAuth.OAUTH_TIMESTAMP, val: self.timestamp))
        result.append(Parameter(k: OAuth.OAUTH_VERSION, val: self.oauthVersion))
        if let token = self.oauthToken {
            result.append(Parameter(k: OAuth.OAUTH_TOKEN, val: token))
        }
        if let bodyHash = self.oauthBodyHash {
            result.append(Parameter(k: OAuth.OAUTH_BODY_HASH, val: bodyHash))
        }
        if let signature = self.oauthSignature {
            result.append(Parameter(k: OAuth.OAUTH_SIGNATURE, val: signature))
        }
        result.sort()
        return result
    }
}
