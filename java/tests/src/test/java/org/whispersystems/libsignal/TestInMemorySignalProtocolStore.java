package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

public class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
  public TestInMemorySignalProtocolStore() {
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
