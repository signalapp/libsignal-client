/**
 * Copyright (C) 2013-2021 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import org.signal.client.internal.Native;
import java.util.Arrays;

public class ECPublicKey implements Comparable<ECPublicKey> {

  public static final int KEY_SIZE = 33;

  private final long handle;

  public ECPublicKey(byte[] serialized, int offset) {
    this.handle = Native.ECPublicKey_Deserialize(serialized, offset);
  }

  public ECPublicKey(byte[] serialized) {
    this.handle = Native.ECPublicKey_Deserialize(serialized, 0);
  }

  static public ECPublicKey fromPublicKeyBytes(byte[] key) {
    byte[] with_type = new byte[33];
    with_type[0] = Curve.CURVE_25519_TYPE;
    System.arraycopy(key, 0, with_type, 1, 32);
    return new ECPublicKey(Native.ECPublicKey_Deserialize(with_type, 0));
  }

  public ECPublicKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.handle = nativeHandle;
  }

  @Override
  protected void finalize() {
     Native.ECPublicKey_Destroy(this.handle);
  }

  public boolean verifySignature(byte[] message, byte[] signature) {
    return Native.ECPublicKey_Verify(this.handle, message, signature);
  }

  public byte[] serialize() {
    return Native.ECPublicKey_Serialize(this.handle);
  }

  public byte[] getPublicKeyBytes() {
    return Native.ECPublicKey_GetPublicKeyBytes(this.handle);
  }

  public int getType() {
    byte[] serialized = this.serialize();
    return serialized[0];
  }

  public long nativeHandle() {
    return this.handle;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                      return false;
    if (!(other instanceof ECPublicKey)) return false;

    ECPublicKey that = (ECPublicKey)other;
    return Arrays.equals(this.serialize(), that.serialize());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.serialize());
  }

  @Override
  public int compareTo(ECPublicKey another) {
    return Native.ECPublicKey_Compare(this.nativeHandle(), another.nativeHandle());
  }
}
