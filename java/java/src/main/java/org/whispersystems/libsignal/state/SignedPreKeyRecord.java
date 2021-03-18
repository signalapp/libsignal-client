/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import java.io.IOException;
import org.signal.client.internal.Native;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class SignedPreKeyRecord {
  private long handle;

  @Override
  protected void finalize() {
    Native.SignedPreKeyRecord_Destroy(this.handle);
  }

  public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
    this.handle =
        Native.SignedPreKeyRecord_New(
            id,
            timestamp,
            keyPair.getPublicKey().nativeHandle(),
            keyPair.getPrivateKey().nativeHandle(),
            signature);
  }

  public SignedPreKeyRecord(byte[] serialized) throws IOException {
    this.handle = Native.SignedPreKeyRecord_Deserialize(serialized);
  }

  public int getId() {
    return Native.SignedPreKeyRecord_GetId(this.handle);
  }

  public long getTimestamp() {
    return Native.SignedPreKeyRecord_GetTimestamp(this.handle);
  }

  public ECKeyPair getKeyPair() {
    ECPublicKey publicKey = new ECPublicKey(Native.SignedPreKeyRecord_GetPublicKey(this.handle));
    ECPrivateKey privateKey =
        new ECPrivateKey(Native.SignedPreKeyRecord_GetPrivateKey(this.handle));
    return new ECKeyPair(publicKey, privateKey);
  }

  public byte[] getSignature() {
    return Native.SignedPreKeyRecord_GetSignature(this.handle);
  }

  public byte[] serialize() {
    return Native.SignedPreKeyRecord_GetSerialized(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
