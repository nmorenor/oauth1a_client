//
//  Parameter.swift
//  PlayusOAuth1a
//
//  Created by nacho on 9/11/17.
//
//

public struct Parameter: Equatable, CustomStringConvertible, Hashable, Comparable {
    var key: String
    var value: String?
    
    public var description: String {
        guard let val = value else {
            return "\(OAuth1A.percentEncode(value: key)) = nil)"
        }
        return "\(OAuth1A.percentEncode(value: key)) = \(OAuth1A.percentEncode(value: val))"
    }
    
    public var hashValue: Int {
        let prime = 31
        var result = 1
        result = prime * result + key.hashValue
        if let val = value {
            result = prime * result + val.hashValue
        } else {
            result = prime * result
        }
        return result
    }
    
    init(k: String, val: String?) {
        key = k
        value = val
    }
    
    public mutating func setValue(val: String) {
        value = val
    }
    
    public static func ==(lhs: Parameter, rhs: Parameter) -> Bool {
        return lhs.key == rhs.key && lhs.value == rhs.value
    }
    
    public static func <(lhs: Parameter, rhs: Parameter) -> Bool {
        return lhs.key < rhs.key
    }
}
