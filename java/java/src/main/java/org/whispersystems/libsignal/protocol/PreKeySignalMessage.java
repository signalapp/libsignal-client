/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

public class PreKeySignalMessage implements CiphertextMessage {

  private long handle;

  @Override
  protected void finalize() {
    Native.PreKeySignalMessage_Destroy(this.handle);
  }

  public PreKeySignalMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException {
    this.handle = Native.PreKeySignalMessage_Deserialize(serialized);
  }

  public PreKeySignalMessage(long handle) {
    this.handle = handle;
  }

  public PreKeySignalMessage(
      int messageVersion,
      int registrationId,
      Optional<Integer> preKeyId,
      int signedPreKeyId,
      ECPublicKey baseKey,
      IdentityKey identityKey,
      SignalMessage message) {
    this.handle =
        Native.PreKeySignalMessage_New(
            messageVersion,
            registrationId,
            preKeyId.or(-1),
            signedPreKeyId,
            baseKey.nativeHandle(),
            identityKey.getPublicKey().nativeHandle(),
            message.nativeHandle());
  }

  public int getMessageVersion() {
    return Native.PreKeySignalMessage_GetVersion(this.handle);
  }

  public IdentityKey getIdentityKey() throws InvalidKeyException {
    return new IdentityKey(Native.PreKeySignalMessage_GetIdentityKey(this.handle), 0);
  }

  public int getRegistrationId() {
    return Native.PreKeySignalMessage_GetRegistrationId(this.handle);
  }

  public Optional<Integer> getPreKeyId() {
    int pre_key = Native.PreKeySignalMessage_GetPreKeyId(this.handle);
    if (pre_key < 0) {
      return Optional.absent();
    } else {
      return Optional.of(pre_key);
    }
  }

  public int getSignedPreKeyId() {
    return Native.PreKeySignalMessage_GetSignedPreKeyId(this.handle);
  }

  public ECPublicKey getBaseKey() throws InvalidKeyException {
    return new ECPublicKey(Native.PreKeySignalMessage_GetBaseKey(this.handle));
  }

  public SignalMessage getWhisperMessage() throws InvalidMessageException, LegacyMessageException {
    return new SignalMessage(Native.PreKeySignalMessage_GetSignalMessage(this.handle));
  }

  @Override
  public byte[] serialize() {
    return Native.PreKeySignalMessage_GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.PREKEY_TYPE;
  }

  public long nativeHandle() {
    return this.handle;
  }
}
