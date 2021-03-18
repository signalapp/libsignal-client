package org.signal.libsignal.metadata.protocol;

import org.signal.client.internal.Native;
import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;

public class UnidentifiedSenderMessageContent {
  private final long handle;

  @Override
  protected void finalize() {
    Native.UnidentifiedSenderMessageContent_Destroy(this.handle);
  }

  public UnidentifiedSenderMessageContent(long nativeHandle) {
    this.handle = nativeHandle;
  }

  public UnidentifiedSenderMessageContent(byte[] serialized)
      throws InvalidMetadataMessageException, InvalidCertificateException {
    try {
      this.handle = Native.UnidentifiedSenderMessageContent_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidMetadataMessageException(e);
    }
  }

  public UnidentifiedSenderMessageContent(
      int type, SenderCertificate senderCertificate, byte[] content) {
    this.handle =
        Native.UnidentifiedSenderMessageContent_New(
            type, senderCertificate.nativeHandle(), content);
  }

  public int getType() {
    return Native.UnidentifiedSenderMessageContent_GetMsgType(this.handle);
  }

  public SenderCertificate getSenderCertificate() {
    return new SenderCertificate(
        Native.UnidentifiedSenderMessageContent_GetSenderCert(this.handle));
  }

  public byte[] getContent() {
    return Native.UnidentifiedSenderMessageContent_GetContents(this.handle);
  }

  public byte[] getSerialized() {
    return Native.UnidentifiedSenderMessageContent_GetSerialized(this.handle);
  }
}
