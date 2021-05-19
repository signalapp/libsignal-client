package org.signal.libsignal.metadata.certificate;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

public class SenderCertificate {
  private long handle;

  @Override
  protected void finalize() {
     Native.SenderCertificate_Destroy(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }

  public SenderCertificate(byte[] serialized) throws InvalidCertificateException {
    try {
      handle = Native.SenderCertificate_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  public SenderCertificate(long handle) {
    this.handle = handle;
  }

  public ServerCertificate getSigner() {
    return new ServerCertificate(Native.SenderCertificate_GetServerCertificate(this.handle));
  }

  public ECPublicKey getKey() {
    return new ECPublicKey(Native.SenderCertificate_GetKey(this.handle));
  }

  public int getSenderDeviceId() {
    return Native.SenderCertificate_GetDeviceId(this.handle);
  }

  public String getSenderUuid() {
    return Native.SenderCertificate_GetSenderUuid(this.handle);
  }

  public Optional<String> getSenderE164() {
    return Optional.fromNullable(Native.SenderCertificate_GetSenderE164(this.handle));
  }

  public String getSender() {
    return getSenderE164().or(getSenderUuid());
  }

  public long getExpiration() {
    return Native.SenderCertificate_GetExpiration(this.handle);
  }

  public byte[] getSerialized() {
    return Native.SenderCertificate_GetSerialized(this.handle);
  }

  public byte[] getCertificate() {
    return Native.SenderCertificate_GetCertificate(this.handle);
  }

  public byte[] getSignature() {
    return Native.SenderCertificate_GetSignature(this.handle);
  }
}
