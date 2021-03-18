/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import javax.crypto.spec.SecretKeySpec;
import org.signal.client.internal.Native;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;

public class SignalMessage implements CiphertextMessage {
  private final long handle;

  @Override
  protected void finalize() {
    Native.SignalMessage_Destroy(this.handle);
  }

  public SignalMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    handle = Native.SignalMessage_Deserialize(serialized);
  }

  public SignalMessage(long handle) {
    this.handle = handle;
  }

  public SignalMessage(
      int messageVersion,
      SecretKeySpec macKey,
      ECPublicKey senderRatchetKey,
      int counter,
      int previousCounter,
      byte[] ciphertext,
      IdentityKey senderIdentityKey,
      IdentityKey receiverIdentityKey) {
    handle =
        Native.SignalMessage_New(
            messageVersion,
            macKey.getEncoded(),
            senderRatchetKey.nativeHandle(),
            counter,
            previousCounter,
            ciphertext,
            senderIdentityKey.getPublicKey().nativeHandle(),
            receiverIdentityKey.getPublicKey().nativeHandle());
  }

  public ECPublicKey getSenderRatchetKey() {
    return new ECPublicKey(Native.SignalMessage_GetSenderRatchetKey(this.handle));
  }

  public int getMessageVersion() {
    return Native.SignalMessage_GetMessageVersion(this.handle);
  }

  public int getCounter() {
    return Native.SignalMessage_GetCounter(this.handle);
  }

  public byte[] getBody() {
    return Native.SignalMessage_GetBody(this.handle);
  }

  public void verifyMac(
      IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)
      throws InvalidMessageException {
    if (!Native.SignalMessage_VerifyMac(
        this.handle,
        senderIdentityKey.getPublicKey().nativeHandle(),
        receiverIdentityKey.getPublicKey().nativeHandle(),
        macKey.getEncoded())) {
      throw new InvalidMessageException("Bad Mac!");
    }
  }

  @Override
  public byte[] serialize() {
    return Native.SignalMessage_GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.WHISPER_TYPE;
  }

  public long nativeHandle() {
    return this.handle;
  }

  public static boolean isLegacy(byte[] message) {
    return message != null
        && message.length >= 1
        && ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
  }
}
