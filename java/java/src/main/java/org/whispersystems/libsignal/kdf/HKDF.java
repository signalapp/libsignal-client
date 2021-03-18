/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.kdf;

import org.signal.client.internal.Native;

public abstract class HKDF {
  private static final int HASH_OUTPUT_SIZE = 32;

  public static HKDF createFor(int messageVersion) {
    switch (messageVersion) {
      case 2:
        return new HKDFv2();
      case 3:
        return new HKDFv3();
      default:
        throw new AssertionError("Unknown version: " + messageVersion);
    }
  }

  public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    return Native.HKDF_DeriveSecrets(outputLength, getVersion(), inputKeyMaterial, info, null);
  }

  public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
    return Native.HKDF_DeriveSecrets(outputLength, getVersion(), inputKeyMaterial, info, salt);
  }

  protected abstract int getVersion();
}
