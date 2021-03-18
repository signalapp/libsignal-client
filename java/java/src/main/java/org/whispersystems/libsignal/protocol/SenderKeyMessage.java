/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class SenderKeyMessage implements CiphertextMessage {

  private long handle;

  @Override
  protected void finalize() {
    Native.SenderKeyMessage_Destroy(this.handle);
  }

  public SenderKeyMessage(byte[] serialized)
      throws InvalidMessageException, LegacyMessageException {
    handle = Native.SenderKeyMessage_Deserialize(serialized);
  }

  public SenderKeyMessage(int keyId, int iteration, byte[] ciphertext, ECPrivateKey signatureKey) {
    handle = Native.SenderKeyMessage_New(keyId, iteration, ciphertext, signatureKey.nativeHandle());
  }

  public int getKeyId() {
    return Native.SenderKeyMessage_GetKeyId(this.handle);
  }

  public int getIteration() {
    return Native.SenderKeyMessage_GetIteration(this.handle);
  }

  public byte[] getCipherText() {
    return Native.SenderKeyMessage_GetCipherText(this.handle);
  }

  public void verifySignature(ECPublicKey signatureKey) throws InvalidMessageException {
    if (!Native.SenderKeyMessage_VerifySignature(this.handle, signatureKey.nativeHandle())) {
      throw new InvalidMessageException("Invalid signature!");
    }
  }

  @Override
  public byte[] serialize() {
    return Native.SenderKeyMessage_GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.SENDERKEY_TYPE;
  }
}
