package org.signal.libsignal.metadata.certificate;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class CertificateValidator {
  private final ECPublicKey trustRoot;

  public CertificateValidator(ECPublicKey trustRoot) {
    this.trustRoot = trustRoot;
  }

  public ECPublicKey getTrustRoot() {
    return this.trustRoot;
  }

  public void validate(SenderCertificate certificate, long validationTime)
      throws InvalidCertificateException {
    try {
      if (!Native.SenderCertificate_Validate(
          certificate.nativeHandle(), trustRoot.nativeHandle(), validationTime)) {
        throw new InvalidCertificateException("Validation failed");
      }
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  // VisibleForTesting
  void validate(ServerCertificate certificate) throws InvalidCertificateException {
    try {
      if (!Curve.verifySignature(
          trustRoot, certificate.getCertificate(), certificate.getSignature())) {
        throw new InvalidCertificateException("Signature failed");
      }
    } catch (InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }
}
