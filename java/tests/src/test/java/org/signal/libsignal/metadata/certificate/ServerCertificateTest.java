package org.signal.libsignal.metadata.certificate;

import junit.framework.TestCase;
import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class ServerCertificateTest extends TestCase {

  public void testSignature() throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair = Curve.generateKeyPair();

    ServerCertificate certificate =
        new ServerCertificate(
            Native.ServerCertificate_New(
                1,
                keyPair.getPublicKey().nativeHandle(),
                trustRoot.getPrivateKey().nativeHandle()));

    new CertificateValidator(trustRoot.getPublicKey()).validate(certificate);

    byte[] serialized = certificate.getSerialized();
    new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));
  }

  public void testBadSignature() throws Exception {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair = Curve.generateKeyPair();

    ServerCertificate certificate =
        new ServerCertificate(
            Native.ServerCertificate_New(
                1,
                keyPair.getPublicKey().nativeHandle(),
                trustRoot.getPrivateKey().nativeHandle()));

    byte[] badSignature = certificate.getSerialized();

    badSignature[badSignature.length - 1] ^= 1;

    ServerCertificate badCert = new ServerCertificate(badSignature);

    try {
      new CertificateValidator(trustRoot.getPublicKey())
          .validate(new ServerCertificate(badSignature));
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }
}
