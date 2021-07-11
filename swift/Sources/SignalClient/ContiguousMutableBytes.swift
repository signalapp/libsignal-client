//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol ContiguousMutableBytes {
    @inlinable mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R
}

extension Data: ContiguousMutableBytes {}
extension Array: ContiguousMutableBytes {}
