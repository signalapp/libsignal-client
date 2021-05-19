/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.io.IOException;

public class PreKeyRecord {
  private long handle;

  @Override
  protected void finalize() {
    Native.PreKeyRecord_Destroy(this.handle);
  }

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    this.handle = Native.PreKeyRecord_New(id, keyPair.getPublicKey().nativeHandle(), keyPair.getPrivateKey().nativeHandle());
  }

  public PreKeyRecord(byte[] serialized) throws IOException {
    this.handle = Native.PreKeyRecord_Deserialize(serialized);
  }

  public int getId() {
    return Native.PreKeyRecord_GetId(this.handle);
  }

  public ECKeyPair getKeyPair() {
    ECPublicKey publicKey = new ECPublicKey(Native.PreKeyRecord_GetPublicKey(this.handle));
    ECPrivateKey privateKey = new ECPrivateKey(Native.PreKeyRecord_GetPrivateKey(this.handle));
    return new ECKeyPair(publicKey, privateKey);
  }

  public byte[] serialize() {
    return Native.PreKeyRecord_GetSerialized(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
