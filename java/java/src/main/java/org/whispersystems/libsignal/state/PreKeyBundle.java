/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * A class that contains a remote PreKey and collection of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle {
  private long handle;

  @Override
  protected void finalize() {
    Native.PreKeyBundle_Destroy(this.handle);
  }

  public PreKeyBundle(
      int registrationId,
      int deviceId,
      int preKeyId,
      ECPublicKey preKeyPublic,
      int signedPreKeyId,
      ECPublicKey signedPreKeyPublic,
      byte[] signedPreKeySignature,
      IdentityKey identityKey) {
    long preKeyPublicHandle = 0;
    if (preKeyPublic != null) {
      preKeyPublicHandle = preKeyPublic.nativeHandle();
    }

    this.handle =
        Native.PreKeyBundle_New(
            registrationId,
            deviceId,
            preKeyId,
            preKeyPublicHandle,
            signedPreKeyId,
            signedPreKeyPublic.nativeHandle(),
            signedPreKeySignature,
            identityKey.getPublicKey().nativeHandle());
  }

  /** @return the device ID this PreKey belongs to. */
  public int getDeviceId() {
    return Native.PreKeyBundle_GetDeviceId(this.handle);
  }

  /** @return the unique key ID for this PreKey. */
  public int getPreKeyId() {
    return Native.PreKeyBundle_GetPreKeyId(this.handle);
  }

  /** @return the public key for this PreKey. */
  public ECPublicKey getPreKey() {
    long handle = Native.PreKeyBundle_GetPreKeyPublic(this.handle);
    if (handle != 0) {
      return new ECPublicKey(handle);
    }
    return null;
  }

  /** @return the unique key ID for this signed prekey. */
  public int getSignedPreKeyId() {
    return Native.PreKeyBundle_GetSignedPreKeyId(this.handle);
  }

  /** @return the signed prekey for this PreKeyBundle. */
  public ECPublicKey getSignedPreKey() {
    return new ECPublicKey(Native.PreKeyBundle_GetSignedPreKeyPublic(this.handle));
  }

  /** @return the signature over the signed prekey. */
  public byte[] getSignedPreKeySignature() {
    return Native.PreKeyBundle_GetSignedPreKeySignature(this.handle);
  }

  /** @return the {@link org.whispersystems.libsignal.IdentityKey} of this PreKeys owner. */
  public IdentityKey getIdentityKey() {
    return new IdentityKey(new ECPublicKey(Native.PreKeyBundle_GetIdentityKey(this.handle)));
  }

  /** @return the registration ID associated with this PreKey. */
  public int getRegistrationId() {
    return Native.PreKeyBundle_GetRegistrationId(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
