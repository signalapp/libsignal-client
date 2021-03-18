/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.ecc.ECPrivateKey;

/**
 * Holder for public and private identity key pair.
 *
 * @author Moxie Marlinspike
 */
public class IdentityKeyPair {
  private final IdentityKey publicKey;
  private final ECPrivateKey privateKey;

  public IdentityKeyPair(IdentityKey publicKey, ECPrivateKey privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public IdentityKeyPair(byte[] serialized) {
    long[] tuple = Native.IdentityKeyPair_Deserialize(serialized);
    long publicKeyHandle = tuple[0];
    long privateKeyHandle = tuple[1];

    this.publicKey = new IdentityKey(publicKeyHandle);
    this.privateKey = new ECPrivateKey(privateKeyHandle);
  }

  public IdentityKey getPublicKey() {
    return publicKey;
  }

  public ECPrivateKey getPrivateKey() {
    return privateKey;
  }

  public byte[] serialize() {
    return Native.IdentityKeyPair_Serialize(
        this.publicKey.nativeHandle(), this.privateKey.nativeHandle());
  }
}
