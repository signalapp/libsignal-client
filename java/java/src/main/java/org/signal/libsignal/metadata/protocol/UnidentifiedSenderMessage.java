package org.signal.libsignal.metadata.protocol;

import org.signal.client.internal.Native;
import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class UnidentifiedSenderMessage {
  private final long handle;

  @Override
  protected void finalize() {
    Native.UnidentifiedSenderMessage_Destroy(this.handle);
  }

  public UnidentifiedSenderMessage(byte[] serialized) throws InvalidMetadataMessageException {
    try {
      this.handle = Native.UnidentifiedSenderMessage_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidMetadataMessageException(e);
    }
  }

  public UnidentifiedSenderMessage(
      ECPublicKey ephemeral, byte[] encryptedStatic, byte[] encryptedMessage) {
    this.handle =
        Native.UnidentifiedSenderMessage_New(
            ephemeral.nativeHandle(), encryptedStatic, encryptedMessage);
  }

  public ECPublicKey getEphemeral() {
    return new ECPublicKey(Native.UnidentifiedSenderMessage_GetEphemeralPublic(this.handle));
  }

  public byte[] getEncryptedStatic() {
    return Native.UnidentifiedSenderMessage_GetEncryptedStatic(this.handle);
  }

  public byte[] getEncryptedMessage() {
    return Native.UnidentifiedSenderMessage_GetEncryptedMessage(this.handle);
  }

  public byte[] getSerialized() {
    return Native.UnidentifiedSenderMessage_GetSerialized(this.handle);
  }
}
