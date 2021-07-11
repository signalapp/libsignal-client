//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class Aes256Ctr32: ClonableHandleOwner {
    public init<KeyBytes, NonceBytes>(
        _ key: KeyBytes,
        _ nonce: NonceBytes,
        _ initial_ctr: UInt32) throws
        where KeyBytes: ContiguousBytes,
              NonceBytes: ContiguousBytes {

        let handle: OpaquePointer? = try key.withUnsafeBytes { keyBytes in
            try nonce.withUnsafeBytes { nonceBytes in
                var result: OpaquePointer?
                let error = signal_aes256_ctr32_new(&result,
                                                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                    keyBytes.count,
                                                    nonceBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                    nonceBytes.count,
                                                    initial_ctr)
                try checkError(error)
                return result
            }
        }
        super.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_aes256_ctr32_destroy(handle)
    }

    public func process<MutableBytes: ContiguousMutableBytes>(_ bytes: inout MutableBytes) throws {
        try bytes.withUnsafeMutableBytes {
            let error = signal_aes256_ctr32_process(nativeHandle,
                                                    $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                    $0.count,
                                                    0,
                                                    UInt32($0.count))
            try checkError(error)
        }
    }

    public func process<MutableBytes: ContiguousMutableBytes>(
        _ bytes: inout MutableBytes,
        _ offset: UInt32,
        _ length: UInt32) throws {
        try bytes.withUnsafeMutableBytes {
            let error = signal_aes256_ctr32_process(nativeHandle,
                                                    $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                    $0.count,
                                                    offset,
                                                    length)
            try checkError(error)
        }
    }
}
