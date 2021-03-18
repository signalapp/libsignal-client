//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;

class Aes256GcmSiv {
  private final long handle;

  public Aes256GcmSiv(byte[] key) throws InvalidKeyException {
    this.handle = Native.Aes256GcmSiv_New(key);
  }

  @Override
  protected void finalize() {
    Native.Aes256GcmSiv_Destroy(this.handle);
  }

  byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException, IllegalArgumentException {
    return Native.Aes256GcmSiv_Encrypt(this.handle, plaintext, nonce, associated_data);
  }

  byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException {
    return Native.Aes256GcmSiv_Decrypt(this.handle, ciphertext, nonce, associated_data);
  }
}
