package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.util.KeyHelper;

public class TestInMemoryIdentityKeyStore
    extends org.whispersystems.libsignal.state.impl.InMemoryIdentityKeyStore {
  public TestInMemoryIdentityKeyStore() {
    super(generateIdentityKeyPair(), generateRegistrationId());
  }

  private static IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

    return new IdentityKeyPair(
        new IdentityKey(identityKeyPairKeys.getPublicKey()), identityKeyPairKeys.getPrivateKey());
  }

  private static int generateRegistrationId() {
    return KeyHelper.generateRegistrationId(false);
  }
}
