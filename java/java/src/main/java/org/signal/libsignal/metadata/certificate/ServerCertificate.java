package org.signal.libsignal.metadata.certificate;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class ServerCertificate {
  private final long handle;

  @Override
  protected void finalize() {
    Native.ServerCertificate_Destroy(this.handle);
  }

  public ServerCertificate(long handle) {
    this.handle = handle;
  }

  public ServerCertificate(byte[] serialized) throws InvalidCertificateException {
    try {
      this.handle = Native.ServerCertificate_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  public int getKeyId() {
    return Native.ServerCertificate_GetKeyId(this.handle);
  }

  public ECPublicKey getKey() {
    return new ECPublicKey(Native.ServerCertificate_GetKey(this.handle));
  }

  public byte[] getSerialized() {
    return Native.ServerCertificate_GetSerialized(this.handle);
  }

  public byte[] getCertificate() {
    return Native.ServerCertificate_GetCertificate(this.handle);
  }

  public byte[] getSignature() {
    return Native.ServerCertificate_GetSignature(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
