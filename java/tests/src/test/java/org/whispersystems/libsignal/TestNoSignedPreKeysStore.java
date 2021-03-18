package org.whispersystems.libsignal;

import org.whispersystems.libsignal.state.SignedPreKeyRecord;

public class TestNoSignedPreKeysStore extends TestInMemorySignalProtocolStore {
  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new InvalidKeyIdException("TestNoSignedPreKeysStore rejected loading " + signedPreKeyId);
  }
}
