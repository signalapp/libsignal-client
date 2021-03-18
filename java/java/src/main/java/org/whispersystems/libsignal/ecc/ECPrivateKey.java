/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import org.signal.client.internal.Native;

public class ECPrivateKey {
  private long handle;

  static ECPrivateKey generate() {
    return new ECPrivateKey(Native.ECPrivateKey_Generate());
  }

  ECPrivateKey(byte[] privateKey) {
    this.handle = Native.ECPrivateKey_Deserialize(privateKey);
  }

  public ECPrivateKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.handle = nativeHandle;
  }

  @Override
  protected void finalize() {
    Native.ECPrivateKey_Destroy(this.handle);
  }

  public byte[] serialize() {
    return Native.ECPrivateKey_Serialize(this.handle);
  }

  public byte[] calculateSignature(byte[] message) {
    return Native.ECPrivateKey_Sign(this.handle, message);
  }

  public byte[] calculateAgreement(ECPublicKey other) {
    return Native.ECPrivateKey_Agree(this.handle, other.nativeHandle());
  }

  public long nativeHandle() {
    return this.handle;
  }

  public ECPublicKey publicKey() {
    return new ECPublicKey(Native.ECPrivateKey_GetPublicKey(this.handle));
  }
}
