package org.whispersystems.libsignal;

import junit.framework.TestCase;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class CurveTest extends TestCase {

  public void testLargeSignatures() throws InvalidKeyException {
    ECKeyPair keys      = Curve.generateKeyPair();
    byte[]    message   = new byte[1024 * 1024];
    byte[]    signature = Curve.calculateSignature(keys.getPrivateKey(), message);

    assertTrue(Curve.verifySignature(keys.getPublicKey(), message, signature));

    message[0] ^= 0x01;

    assertFalse(Curve.verifySignature(keys.getPublicKey(), message, signature));
  }

}
