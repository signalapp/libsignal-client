package org.signal.libsignal.metadata.certificate;

import java.util.UUID;
import junit.framework.TestCase;
import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class SenderCertificateTest extends TestCase {

  private final ECKeyPair trustRoot = Curve.generateKeyPair();

  public void testSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();
    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            31337,
            key.getPublicKey(),
            31337);

    new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31336);
  }

  public void testExpiredSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();

    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            31338,
            key.getPublicKey(),
            31337);
    try {
      new CertificateValidator(trustRoot.getPublicKey()).validate(senderCertificate, 31338);
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  public void testBadSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key = Curve.generateKeyPair();

    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            31338,
            key.getPublicKey(),
            31337);

    byte[] badSignature = senderCertificate.getSerialized();

    badSignature[badSignature.length - 1] ^= 1;

    SenderCertificate badCert = new SenderCertificate(badSignature);

    try {
      new CertificateValidator(trustRoot.getPublicKey()).validate(badCert, 31336);
      throw new AssertionError();
    } catch (InvalidCertificateException e) {
      // good
    }
  }

  private SenderCertificate createCertificateFor(
      ECKeyPair trustRoot,
      UUID uuid,
      String e164,
      int deviceId,
      ECPublicKey identityKey,
      long expires)
      throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair serverKey = Curve.generateKeyPair();

    ServerCertificate serverCertificate =
        new ServerCertificate(
            Native.ServerCertificate_New(
                1,
                serverKey.getPublicKey().nativeHandle(),
                trustRoot.getPrivateKey().nativeHandle()));

    return new SenderCertificate(
        Native.SenderCertificate_New(
            uuid.toString(),
            e164,
            deviceId,
            identityKey.nativeHandle(),
            expires,
            serverCertificate.nativeHandle(),
            serverKey.getPrivateKey().nativeHandle()));
  }
}
