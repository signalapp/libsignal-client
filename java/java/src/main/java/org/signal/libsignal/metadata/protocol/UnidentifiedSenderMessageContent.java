package org.signal.libsignal.metadata.protocol;

import org.signal.client.internal.Native;
import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.util.guava.Optional;

public class UnidentifiedSenderMessageContent {
  // Must be kept in sync with sealed_sender.proto.
  public static final int CONTENT_HINT_DEFAULT       = 0;
  public static final int CONTENT_HINT_SUPPLEMENTARY = 1;
  public static final int CONTENT_HINT_RETRY         = 2;

  private final long handle;

  @Override
  protected void finalize() {
     Native.UnidentifiedSenderMessageContent_Destroy(this.handle);
  }

  public UnidentifiedSenderMessageContent(long nativeHandle) {
    this.handle = nativeHandle;
  }

  public long nativeHandle() {
    return this.handle;
  }

  public UnidentifiedSenderMessageContent(byte[] serialized) throws InvalidMetadataMessageException, InvalidCertificateException {
    try {
      this.handle = Native.UnidentifiedSenderMessageContent_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidMetadataMessageException(e);
    }
  }

  public UnidentifiedSenderMessageContent(CiphertextMessage message,
                                          SenderCertificate senderCertificate,
                                          int contentHint,
                                          Optional<byte[]> groupId) {
    this.handle = Native.UnidentifiedSenderMessageContent_New(message,
                                                              senderCertificate.nativeHandle(),
                                                              contentHint,
                                                              groupId.orNull());
  }

  public int getType() {
    return Native.UnidentifiedSenderMessageContent_GetMsgType(this.handle);
  }

  public SenderCertificate getSenderCertificate() {
    return new SenderCertificate(Native.UnidentifiedSenderMessageContent_GetSenderCert(this.handle));
  }

  public byte[] getContent() {
    return Native.UnidentifiedSenderMessageContent_GetContents(this.handle);
  }

  public byte[] getSerialized() {
    return Native.UnidentifiedSenderMessageContent_GetSerialized(this.handle);
  }

  public int getContentHint() {
    return Native.UnidentifiedSenderMessageContent_GetContentHint(this.handle);
  }

  public Optional<byte[]> getGroupId() {
    return Optional.fromNullable(Native.UnidentifiedSenderMessageContent_GetGroupId(this.handle));
  }
}
