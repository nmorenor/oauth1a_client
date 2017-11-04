//
//  OAuth.swift
//  OAuth
//
//  Created by nacho on 9/11/17.
//
//
import PerfectLib

import Foundation
import CryptoSwift

#if os(Linux)
    import Glibc
#else
    import Darwin.C
#endif

public enum StringEncodeError: Error {
    case DecodingError
    case EncodingError
}

public typealias HashFunction = (String, String) throws -> String

public struct OAuth {
    
    public static let VERSION_1_0 = "1.0"
    //only support UTF-8
    public static let ENCODING = "UTF-8"
    public static let FORM_ENCODING = "application/x-www-form-urlencoded"
    
    public static let OAUTH_CONSUMER_KEY = "oauth_consumer_key"
    public static let OAUTH_TOKEN = "oauth_token"
    public static let OAUTH_TOKEN_SECRET = "oauth_token_secret"
    public static let OAUTH_SIGNATURE_METHOD = "oauth_signature_method"
    public static let OAUTH_SIGNATURE = "oauth_signature"
    public static let OAUTH_TIMESTAMP = "oauth_timestamp"
    public static let OAUTH_NONCE = "oauth_nonce"
    public static let OAUTH_VERSION = "oauth_version"
    public static let OAUTH_BODY_HASH = "oauth_body_hash"
    
    public static let HMAC_SHA1 = "HMAC-SHA1"
    public static let RSA_SHA1 = "RSA-SHA1"
    
    public static let HMAC_SHA1_HASH_FUNCTION: HashFunction = { (base: String, secret: String) throws -> String in
        return try UTF8Encoding.encode(bytes: HMAC(key: UTF8Encoding.decode(string: secret), variant: .sha1).authenticate(UTF8Encoding.decode(string: base)))
    }
    
    private let consumer: OAuthConsumer
    private let nonce_length: Int
    private let version: String
    private let parameterSeparator: String
    private let signatureMethod: String
    private let hashFunction: HashFunction
    
    init(consumer: OAuthConsumer, hashFunction: @escaping HashFunction, signatureMethod: String?) {
        self.init(consumer: consumer, hashFunction: hashFunction, signatureMethod: signatureMethod, nonceLength: nil, version: nil, parameterSeparator: nil)
    }
    
    init(consumer: OAuthConsumer, hashFunction: @escaping HashFunction, signatureMethod: String?, nonceLength: Int?, version: String?, parameterSeparator: String?) {
        self.consumer = consumer;
        self.nonce_length = nonceLength ?? 32
        self.version = version ?? "1.0"
        self.parameterSeparator = parameterSeparator ?? ", "
        self.hashFunction = hashFunction
        self.signatureMethod = signatureMethod ?? "PLAINTEXT"
        
        #if os(Linux)
            srand(UInt32(time(nil)))
        #endif
    }
    
    public func authorize(request: RequestData, token: Token, timestamp: String) throws -> OAuthData {
        let oauthData: OAuthData = OAuthData(consumerKey: self.consumer.key, nonce: self.getNonce(), signatureMethod: self.signatureMethod, timestamp: timestamp, version: self.version, token: token.key, secret: token.secret)
        if (request.includeBodyHash) {
            oauthData.oauthBodyHash = try self.getBodyHash(request: request, tokenSecret: token.secret)
        }
        oauthData.oauthSignature = try self.getSignature(request: request, tokenSecret: token.secret, oauthData: oauthData)
        
        return oauthData
    }
    
    private func getSignature(request: RequestData, tokenSecret: String, oauthData: OAuthData) throws -> String {
        return try self.hashFunction(self.getBaseString(request: request, oauthData: oauthData), self.getSigningKey(tokenSecret: tokenSecret))
    }
    
    private func getBodyHash(request: RequestData, tokenSecret: String) throws -> String {
        return try self.hashFunction(request.data, self.getSigningKey(tokenSecret: tokenSecret))
    }
    
    private func getBaseString(request: RequestData, oauthData: OAuthData) throws -> String {
        var params: Array<Parameter> = try self.deParamUrl(url: request.url) + oauthData.asParameters()
        params.sort()
        return "\(self.signatureMethod.uppercased())&\(OAuth.percentEncode(value: request.url))&\(OAuth.percentEncode(value: OAuth.formEncode(parameters: params)))"
    }
    
    private func getSigningKey(tokenSecret: String?) -> String {
        let secret = tokenSecret ?? ""
        return "\(OAuth.percentEncode(value: self.consumer.secret))&\(OAuth.percentEncode(value: secret))"
    }
    
    private func percentEncode(values: Array<String>) -> String {
        var result = "";
        for value in values {
            if (result.characters.count > 0) {
                result.append("&")
            }
            result.append(value)
        }
        return result
    }
    
    private func getNonce() -> String {
        let wordCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        var result = ""
        
        for _ in 0 ..< nonce_length {
            #if os(Linux)
                let idx = Int(random() % wordCharacters.count)
            #else
                let idx = Int(arc4random_uniform(UInt32(wordCharacters.characters.count)))
            #endif
            result += wordCharacters[idx]
        }
        return result
    }
    
    private func deParamUrl(url: String) throws -> Array<Parameter> {
        var result = [Parameter]()
        if let _url = URL(string: url) {
            let queryItems = _url.queryItems
            for (key, value) in queryItems {
                result.append(Parameter(k: key, val: value))
            }
        }
        return result
    }
    
    public static func percentEncode(value: String) -> String {
        //Oauth encodes some characters differently
        return value.stringByEncodingURL.stringByReplacing(string: "+", withString: "%20").stringByReplacing(string: "*", withString: "%2A").stringByReplacing(string: "%7E", withString: "~")
    }
    
    static func decodePercent(value: String) throws -> String {
        guard let result = value.stringByDecodingURL else {
            Log.error(message: "Can't decode string: \(value)")
            throw StringEncodeError.DecodingError
        }
        return result
    }
    
    static func decodeForm(frm: String) throws -> Array<Parameter> {
        var result = [Parameter]()
        let nvp = frm.components(separatedBy: "&")
        for next in nvp {
            guard let range = frm.range(of: "=") else {
                try result.append(Parameter(k: OAuth.decodePercent(value: next), val: nil))
                continue
            }
            let name = next.substring(to: range.lowerBound)
            let value = next.substring(from: range.upperBound)
            
            result.append(Parameter(k: name, val: value))
        }
        return result
    }
    
    static func formEncode(parameters: [Parameter]) -> String {
        var result = ""
        var first = true;
        for next in parameters {
            if (first) {
                first = false;
            } else {
                result.append("&")
            }
            if let value = next.value {
                result.append("\(OAuth.percentEncode(value: next.key))=\(OAuth.percentEncode(value: value))")
            } else {
                result.append("\(OAuth.percentEncode(value: next.key))=")
            }
        }
        return result;
    }
}


extension URL {
    public var queryItems: [String: String] {
        var params = [String: String]()
        return URLComponents(url: self, resolvingAgainstBaseURL: false)?
            .queryItems?
            .reduce([:], { (_, item) -> [String: String] in
                params[item.name] = item.value
                return params
            }) ?? [:]
    }
}

extension String {
    
    subscript (i: Int) -> Character {
        return self[index(startIndex, offsetBy: i)]
    }
    
    subscript (i: Int) -> String {
        return String(self[i] as Character)
    }
    
    subscript (r: Range<Int>) -> String {
        let start = index(startIndex, offsetBy: r.lowerBound)
        let end = index(startIndex, offsetBy: r.upperBound)
        return self[Range(start ..< end)]
    }
}

