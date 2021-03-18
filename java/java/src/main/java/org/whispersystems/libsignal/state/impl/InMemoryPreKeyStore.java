/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;

public class InMemoryPreKeyStore implements PreKeyStore {

  private final Map<Integer, byte[]> store = new HashMap<>();

  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    try {
      if (!store.containsKey(preKeyId)) {
        throw new InvalidKeyIdException("No such prekeyrecord!");
      }

      return new PreKeyRecord(store.get(preKeyId));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    store.put(preKeyId, record.serialize());
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    return store.containsKey(preKeyId);
  }

  @Override
  public void removePreKey(int preKeyId) {
    store.remove(preKeyId);
  }
}
