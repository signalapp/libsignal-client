//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class Aes256GcmEncryption: ClonableHandleOwner {
    public init<KeyBytes, NonceBytes, AssociatedDataBytes>(
        _ key: KeyBytes,
        _ nonce: NonceBytes,
        _ associated_data: AssociatedDataBytes) throws
        where KeyBytes: ContiguousBytes,
              NonceBytes: ContiguousBytes,
              AssociatedDataBytes: ContiguousBytes {

        let handle: OpaquePointer? = try key.withUnsafeBytes { keyBytes in
            try nonce.withUnsafeBytes { nonceBytes in
                try associated_data.withUnsafeBytes { adBytes in
                    var result: OpaquePointer?
                    let error = signal_aes256_gcm_encryption_new(&result,
                                                                 keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                                 keyBytes.count,
                                                                 nonceBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                                 nonceBytes.count,
                                                                 adBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                                 adBytes.count)
                    try checkError(error)
                    return result
                }
            }
        }
        super.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_gcm_encryption_destroy(handle)
    }

    public func encrypt<MutableBytes: ContiguousMutableBytes>(_ bytes: inout MutableBytes) throws {
        try bytes.withUnsafeMutableBytes {
            let error = signal_aes256_gcm_encryption_update(nativeHandle,
                                                            $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                            $0.count,
                                                            0,
                                                            UInt32($0.count))
            try checkError(error)
        }
    }

    public func encrypt<MutableBytes: ContiguousMutableBytes>(
        _ bytes: inout MutableBytes,
        _ offset: UInt32,
        _ length: UInt32) throws {
        try bytes.withUnsafeMutableBytes {
            let error = signal_aes256_gcm_encryption_update(nativeHandle,
                                                            $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                            $0.count,
                                                            offset,
                                                            length)
            try checkError(error)
        }
    }

    public func computeTag() throws -> [UInt8] {
        try invokeFnReturningArray {
            signal_aes256_gcm_encryption_compute_tag($0, $1, nativeHandle)
        }
    }
}
