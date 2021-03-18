/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.IdentityKey;

public class NumericFingerprintGenerator implements FingerprintGenerator {
  private final int iterations;

  /**
   * Construct a fingerprint generator for 60 digit numerics.
   *
   * @param iterations The number of internal iterations to perform in the process of generating a
   *     fingerprint. This needs to be constant, and synchronized across all clients.
   *     <p>The higher the iteration count, the higher the security level:
   *     <p>- 1024 ~ 109.7 bits - 1400 > 110 bits - 5200 > 112 bits
   */
  public NumericFingerprintGenerator(int iterations) {
    this.iterations = iterations;
  }

  /**
   * Generate a scannable and displayable fingerprint.
   *
   * @param version The version of fingerprint you are generating.
   * @param localStableIdentifier The client's "stable" identifier.
   * @param localIdentityKey The client's identity key.
   * @param remoteStableIdentifier The remote party's "stable" identifier.
   * @param remoteIdentityKey The remote party's identity key.
   * @return A unique fingerprint for this conversation.
   */
  @Override
  public Fingerprint createFor(
      int version,
      byte[] localStableIdentifier,
      final IdentityKey localIdentityKey,
      byte[] remoteStableIdentifier,
      final IdentityKey remoteIdentityKey) {

    long handle =
        Native.NumericFingerprintGenerator_New(
            this.iterations,
            version,
            localStableIdentifier,
            localIdentityKey.serialize(),
            remoteStableIdentifier,
            remoteIdentityKey.serialize());

    DisplayableFingerprint displayableFingerprint =
        new DisplayableFingerprint(Native.NumericFingerprintGenerator_GetDisplayString(handle));

    ScannableFingerprint scannableFingerprint =
        new ScannableFingerprint(Native.NumericFingerprintGenerator_GetScannableEncoding(handle));

    Native.NumericFingerprintGenerator_Destroy(handle);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }
}
