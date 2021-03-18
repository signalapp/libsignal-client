/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;

public interface FingerprintGenerator {
  public Fingerprint createFor(
      int version,
      byte[] localStableIdentifier,
      IdentityKey localIdentityKey,
      byte[] remoteStableIdentifier,
      IdentityKey remoteIdentityKey);
}
