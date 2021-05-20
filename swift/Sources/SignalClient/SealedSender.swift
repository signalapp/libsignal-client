//
// Copyright 2020-2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

@inlinable
public func sealedSenderEncrypt<Bytes: ContiguousBytes>(message: Bytes,
                                                        for address: ProtocolAddress,
                                                        from senderCert: SenderCertificate,
                                                        sessionStore: SessionStore,
                                                        identityStore: IdentityKeyStore,
                                                        context: StoreContext) throws -> [UInt8] {
    let ciphertextMessage = try signalEncrypt(message: message,
                                              for: address,
                                              sessionStore: sessionStore,
                                              identityStore: identityStore,
                                              context: context)

    let usmc = try UnidentifiedSenderMessageContent(ciphertextMessage,
                                                    from: senderCert,
                                                    contentHint: .default,
                                                    groupId: [])

    return try sealedSenderEncrypt(usmc, for: address, identityStore: identityStore, context: context)
}

public class UnidentifiedSenderMessageContent: ClonableHandleOwner {
    public struct ContentHint: RawRepresentable, Hashable {
        public var rawValue: UInt32
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        internal init(_ knownType: SignalContentHint) {
            self.init(rawValue: UInt32(knownType.rawValue))
        }

        public static var `default`: Self {
            return Self(SignalContentHint_Default)
        }
        public static var supplementary: Self {
            return Self(SignalContentHint_Supplementary)
        }
        public static var retry: Self {
            return Self(SignalContentHint_Retry)
        }
    }

    public init<Bytes: ContiguousBytes>(message sealedSenderMessage: Bytes,
                                        identityStore: IdentityKeyStore,
                                        context: StoreContext) throws {
        let identity = try identityStore.identityKeyPair(context: context)
        var result: OpaquePointer?
        try sealedSenderMessage.withUnsafeBytes { messageBytes in
            try checkError(
                signal_sealed_session_cipher_decrypt_to_usmc(
                    &result,
                    messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    messageBytes.count,
                    identity.privateKey.nativeHandle,
                    identity.publicKey.nativeHandle))
        }
        super.init(owned: result!)
    }

    public init<GroupIdBytes: ContiguousBytes>(_ message: CiphertextMessage,
                                               from sender: SenderCertificate,
                                               contentHint: ContentHint,
                                               groupId: GroupIdBytes) throws {
        var result: OpaquePointer?
        try groupId.withUnsafeBytes { groupIdBytes in
            try checkError(
                signal_unidentified_sender_message_content_new(&result,
                                                               message.nativeHandle,
                                                               sender.nativeHandle,
                                                               contentHint.rawValue,
                                                               groupIdBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                               groupIdBytes.count))
        }
        super.init(owned: result!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_unidentified_sender_message_content_destroy(handle)
    }

    public var senderCertificate: SenderCertificate {
        var result: OpaquePointer?
        failOnError(signal_unidentified_sender_message_content_get_sender_cert(&result, self.nativeHandle))
        return SenderCertificate(owned: result!)
    }

    public var messageType: CiphertextMessage.MessageType {
        let rawType = failOnError {
            try invokeFnReturningInteger {
                signal_unidentified_sender_message_content_get_msg_type($0, self.nativeHandle)
            }
        }
        return .init(rawValue: rawType)
    }

    public var contents: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_unidentified_sender_message_content_get_contents($0, $1, self.nativeHandle)
            }
        }
    }

    public var groupId: [UInt8]? {
        return failOnError {
            try invokeFnReturningOptionalArray {
                signal_unidentified_sender_message_content_get_group_id($0, $1, self.nativeHandle)
            }
        }
    }

    public var contentHint: ContentHint {
        let rawHint = failOnError {
            try invokeFnReturningInteger {
                signal_unidentified_sender_message_content_get_content_hint($0, self.nativeHandle)
            }
        }
        return .init(rawValue: rawHint)
    }
}

public func sealedSenderEncrypt(_ content: UnidentifiedSenderMessageContent,
                                for recipient: ProtocolAddress,
                                identityStore: IdentityKeyStore,
                                context: StoreContext) throws -> [UInt8] {
    return try context.withOpaquePointer { context in
        try withIdentityKeyStore(identityStore) { ffiIdentityStore in
            try invokeFnReturningArray {
                signal_sealed_session_cipher_encrypt($0, $1,
                                                     recipient.nativeHandle,
                                                     content.nativeHandle,
                                                     ffiIdentityStore, context)
            }
        }
    }
}

public func sealedSenderMultiRecipientEncrypt(_ content: UnidentifiedSenderMessageContent,
                                              for recipients: [ProtocolAddress],
                                              identityStore: IdentityKeyStore,
                                              context: StoreContext) throws -> [UInt8] {
    return try context.withOpaquePointer { context in
        try withIdentityKeyStore(identityStore) { ffiIdentityStore in
            try invokeFnReturningArray {
                signal_sealed_sender_multi_recipient_encrypt($0, $1,
                                                             recipients.map { $0.nativeHandle },
                                                             recipients.count,
                                                             content.nativeHandle,
                                                             ffiIdentityStore, context)
            }
        }
    }
}

// For testing only.
internal func sealedSenderMultiRecipientMessageForSingleRecipient(_ message: [UInt8]) throws -> [UInt8] {
    return try invokeFnReturningArray {
        signal_sealed_sender_multi_recipient_message_for_single_recipient($0, $1, message, message.count)
    }
}

public struct SealedSenderAddress: Hashable {
    public var e164: String?
    public var uuidString: String
    public var deviceId: UInt32

    public init(e164: String?, uuidString: String, deviceId: UInt32) throws {
        self.e164 = e164
        self.uuidString = uuidString
        self.deviceId = deviceId
    }
}

public struct SealedSenderResult {
    public var message: [UInt8]
    public var sender: SealedSenderAddress
}

public func sealedSenderDecrypt<Bytes: ContiguousBytes>(message: Bytes,
                                                        from localAddress: SealedSenderAddress,
                                                        trustRoot: PublicKey,
                                                        timestamp: UInt64,
                                                        sessionStore: SessionStore,
                                                        identityStore: IdentityKeyStore,
                                                        preKeyStore: PreKeyStore,
                                                        signedPreKeyStore: SignedPreKeyStore,
                                                        context: StoreContext) throws -> SealedSenderResult {
    var senderE164: UnsafePointer<CChar>?
    var senderUUID: UnsafePointer<CChar>?
    var senderDeviceId: UInt32 = 0

    let plaintext = try message.withUnsafeBytes { messageBytes in
        try context.withOpaquePointer { context in
            try withSessionStore(sessionStore) { ffiSessionStore in
                try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                    try withPreKeyStore(preKeyStore) { ffiPreKeyStore in
                        try withSignedPreKeyStore(signedPreKeyStore) { ffiSignedPreKeyStore in
                            try invokeFnReturningArray {
                                signal_sealed_session_cipher_decrypt(
                                    $0,
                                    $1,
                                    &senderE164,
                                    &senderUUID,
                                    &senderDeviceId,
                                    messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                    messageBytes.count,
                                    trustRoot.nativeHandle,
                                    timestamp,
                                    localAddress.e164,
                                    localAddress.uuidString,
                                    localAddress.deviceId,
                                    ffiSessionStore,
                                    ffiIdentityStore,
                                    ffiPreKeyStore,
                                    ffiSignedPreKeyStore,
                                    context)
                            }
                        }
                    }
                }
            }
        }
    }

    defer {
        signal_free_string(senderE164)
        signal_free_string(senderUUID)
    }

    return SealedSenderResult(message: plaintext,
                              sender: try SealedSenderAddress(e164: senderE164.map(String.init(cString:)),
                                                              uuidString: String(cString: senderUUID!),
                                                              deviceId: senderDeviceId))
}
