//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;

public class CryptographicMac {
  private final long handle;

  public CryptographicMac(String algo, byte[] key) {
    this.handle = Native.CryptographicMac_New(algo, key);
  }

  @Override
  protected void finalize() {
    Native.CryptographicMac_Destroy(this.handle);
  }

  public void update(byte[] input, int offset, int len) {
    Native.CryptographicMac_UpdateWithOffset(this.handle, input, offset, len);
  }

  public void update(byte[] input) {
    Native.CryptographicMac_Update(this.handle, input);
  }

  public byte[] finish() {
    return Native.CryptographicMac_Finalize(this.handle);
  }
}
