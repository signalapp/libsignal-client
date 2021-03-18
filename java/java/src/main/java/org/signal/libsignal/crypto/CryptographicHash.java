//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;

public class CryptographicHash {
  private final long handle;

  public CryptographicHash(String algo) {
    this.handle = Native.CryptographicHash_New(algo);
  }

  @Override
  protected void finalize() {
    Native.CryptographicHash_Destroy(this.handle);
  }

  public void update(byte[] input, int offset, int len) {
    Native.CryptographicHash_UpdateWithOffset(this.handle, input, offset, len);
  }

  public void update(byte[] input) {
    Native.CryptographicHash_Update(this.handle, input);
  }

  public byte[] finish() {
    return Native.CryptographicHash_Finalize(this.handle);
  }
}
