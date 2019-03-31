//
//  RsaHelper.swift
//  RsaHelper
//
//  Inspired by https://github.com/DigitalLeaves/CryptoExportImportManager/blob/master/CryptoLoadExternalCertificate/CryptoExportImportManager.swift
//  Created by Anders Knutsson on 31/03/2019.
//

import Foundation
import Security
import UIKit

// RSA OID header
private let kCryptoExportImportManagerRSAOIDHeader: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
private let kCryptoExportImportManagerRSAOIDHeaderLength = 15

// ASN.1 encoding parameters.
private let kCryptoExportImportManagerASNHeaderSequenceMark: UInt8 = 48 // 0x30
private let kCryptoExportImportManagerASNHeaderIntegerMark: UInt8 = 02 // 0x32
private let kCryptoExportImportManagerASNHeaderBitstringMark: UInt8 = 03 //0x03
private let kCryptoExportImportManagerASNHeaderNullMark: UInt8 = 05 //0x05
private let kCryptoExportImportManagerASNHeaderRSAEncryptionObjectMark: UInt8 = 06 //0x06
private let kCryptoExportImportManagerExtendedLengthMark: UInt8 = 128  // 0x80
private let kCryptoExportImportManagerASNHeaderLengthForRSA = 15

// PEM encoding constants
private let kCryptoExportImportManagerPublicKeyInitialTag = "-----BEGIN PUBLIC KEY-----\r\n"
private let kCryptoExportImportManagerPublicKeyFinalTag = "-----END PUBLIC KEY-----"
private let kCryptoExportImportManagerPrivateKeyInitialTag = "-----BEGIN PRIVATE KEY-----\r\n"
private let kCryptoExportImportManagerPrivateKeyFinalTag = "-----END PRIVATE KEY-----"
private let kCryptoExportImportManagerPublicNumberOfCharactersInALine = 64


@available(iOS 10.0, *)
@objc public class RsaHelper: NSObject {
    
    @objc public static func getKeyFromKeychain(_ tagName: String) -> SecKey? {
        return RSAUtils.getRSAKeyFromKeychain(tagName);
    }
    
    @objc public static func importPublicKeyFromPEM(_ pemString: String, tagName: String) -> SecKey? {
        do {
            return try RSAUtils.addRSAPublicKey(pemString, tagName: tagName)
        }
        catch {
            return nil;
        }
    }
    
    @objc public static func importPrivateKeyFromPEM(_ pemString: String, tagName: String) -> SecKey? {
        do {
            return try RSAUtils.addRSAPrivateKey(pemString, tagName: tagName)
        }
        catch {
            return nil;
        }
    }
    
    @objc public static func removeKeyFromKeychain(_ tagName: String) {
        RSAUtils.deleteRSAKeyFromKeychain(tagName)
    }
    
    @objc public static func exportPublicKeyToPEM(_ pubKey: SecKey) -> String? {
        let pubKeyData = SecKeyCopyExternalRepresentation(pubKey, nil);
        let encodedKey = exportPublicKeyToDER(pubKeyData! as NSData as Data);
        return PEMKeyFromDERKey(encodedKey, prefix: kCryptoExportImportManagerPublicKeyInitialTag, suffix: kCryptoExportImportManagerPublicKeyFinalTag);
    }
    
    @objc public static func exportPrivateKeyToPEM(_ privKey: SecKey) -> String? {
        let privKeyData = SecKeyCopyExternalRepresentation(privKey, nil);
        let encodedKey = exportPublicKeyToDER(privKeyData! as NSData as Data);
        return PEMKeyFromDERKey(encodedKey, prefix: kCryptoExportImportManagerPrivateKeyInitialTag, suffix: kCryptoExportImportManagerPrivateKeyFinalTag);
    }
    
    /**
     * Returns the number of bytes needed to represent an integer.
     */
    private static func bytesNeededForRepresentingInteger(_ number: Int) -> Int {
        if number <= 0 { return 0 }
        var i = 1
        while (i < 8 && number >= (1 << (i * 8))) { i += 1 }
        return i
    }
    
    /**
     * This function prepares a RSA public key generated with Apple SecKeyGeneratePair to be exported
     * and used outisde iOS, be it openSSL, PHP, Perl, whatever. By default Apple exports RSA public
     * keys in a very raw format. If we want to use it on OpenSSL, PHP or almost anywhere outside iOS, we
     * need to remove add the full PKCS#1 ASN.1 wrapping. Returns a DER representation of the key.
     */
   
    private static func exportPublicKeyToDER(_ rawPublicKeyBytes: Data) -> Data {
        // first we create the space for the ASN.1 header and decide about its length
        var headerData = Data(count: kCryptoExportImportManagerASNHeaderLengthForRSA)
        let bitstringEncodingLength = bytesNeededForRepresentingInteger(rawPublicKeyBytes.count)
        
        // start building the ASN.1 header
        let headerBuffer = headerData.withUnsafeMutableBytes {
            (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            bytes[0] = kCryptoExportImportManagerASNHeaderSequenceMark // sequence start
            return bytes
        }
        
        // total size (OID + encoding + key size) + 2 (marks)
        let totalSize = kCryptoExportImportManagerRSAOIDHeaderLength + bitstringEncodingLength + rawPublicKeyBytes.count + 2
        let totalSizebitstringEncodingLength = encodeASN1LengthParameter(totalSize, buffer: &(headerBuffer[1]))
        
        // bitstring header
        var bitstringData = Data(count: kCryptoExportImportManagerASNHeaderLengthForRSA)
        var keyLengthBytesEncoded = 0
        let bitstringBuffer = bitstringData.withUnsafeMutableBytes {
            (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            bytes[0] = kCryptoExportImportManagerASNHeaderBitstringMark // key length mark
            keyLengthBytesEncoded = encodeASN1LengthParameter(rawPublicKeyBytes.count+1, buffer: &(bytes[1]))
            bytes[keyLengthBytesEncoded + 1] = 0x00
            return bytes
        }
        
        // build DER key.
        var derKey = Data(capacity: totalSize + totalSizebitstringEncodingLength)
        derKey.append(headerBuffer, count: totalSizebitstringEncodingLength + 1)
        derKey.append(kCryptoExportImportManagerRSAOIDHeader, count: kCryptoExportImportManagerRSAOIDHeaderLength) // Add OID header
        derKey.append(bitstringBuffer, count: keyLengthBytesEncoded + 2) // 0x03 + key bitstring length + 0x00
        derKey.append(rawPublicKeyBytes) // public key raw data.
        
        return derKey
    }
    
    /**
     * Generates an ASN.1 length sequence for the given length. Modifies the buffer parameter by
     * writing the ASN.1 sequence. The memory of buffer must be initialized (i.e: from an NSData).
     * Returns the number of bytes used to write the sequence.
     */
    private static func encodeASN1LengthParameter(_ length: Int, buffer: UnsafeMutablePointer<UInt8>) -> Int {
        if length < Int(kCryptoExportImportManagerExtendedLengthMark) {
            buffer[0] = UInt8(length)
            return 1 // just one byte was used, no need for length starting mark (0x80).
        } else {
            let extraBytes = bytesNeededForRepresentingInteger(length)
            var currentLengthValue = length
            
            buffer[0] = kCryptoExportImportManagerExtendedLengthMark + UInt8(extraBytes)
            for i in 0 ..< extraBytes {
                buffer[extraBytes - i] = UInt8(currentLengthValue & 0xff)
                currentLengthValue = currentLengthValue >> 8
            }
            return extraBytes + 1 // 1 byte for the starting mark (0x80 + bytes used) + bytes used to encode length.
        }
    }
    
    /**
     * This method transforms a DER encoded key to PEM format. It gets a Base64 representation of
     * the key and then splits this base64 string in 64 character chunks. Then it wraps it in
     * BEGIN and END key tags.
     */
    private static func PEMKeyFromDERKey(_ data: Data, prefix: String, suffix: String) -> String {
        // base64 encode the result
        let base64EncodedString = data.base64EncodedString(options: [])
        
        // split in lines of 64 characters.
        var currentLine = ""
        var resultString = prefix
        var charCount = 0
        for character in base64EncodedString {
            charCount += 1
            currentLine.append(character)
            if charCount == kCryptoExportImportManagerPublicNumberOfCharactersInALine {
                resultString += currentLine + "\r\n"
                charCount = 0
                currentLine = ""
            }
        }
        // final line (if any)
        if currentLine.count > 0 { resultString += currentLine + "\r\n" }
        // final tag
        resultString += suffix
        return resultString
    }
    
}
