/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class SenderKeyDistributionMessage implements CiphertextMessage {

  private final long handle;

  @Override
  protected void finalize() {
    Native.SenderKeyDistributionMessage_Destroy(this.handle);
  }

  public SenderKeyDistributionMessage(long handle) {
    this.handle = handle;
  }

  public SenderKeyDistributionMessage(
      int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
    handle =
        Native.SenderKeyDistributionMessage_New(
            id, iteration, chainKey, signatureKey.nativeHandle());
  }

  public SenderKeyDistributionMessage(byte[] serialized)
      throws LegacyMessageException, InvalidMessageException {
    handle = Native.SenderKeyDistributionMessage_Deserialize(serialized);
  }

  @Override
  public byte[] serialize() {
    return Native.SenderKeyDistributionMessage_GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return SENDERKEY_DISTRIBUTION_TYPE;
  }

  public int getIteration() {
    return Native.SenderKeyDistributionMessage_GetIteration(this.handle);
  }

  public byte[] getChainKey() {
    return Native.SenderKeyDistributionMessage_GetChainKey(this.handle);
  }

  public ECPublicKey getSignatureKey() {
    return new ECPublicKey(Native.SenderKeyDistributionMessage_GetSignatureKey(this.handle));
  }

  public int getId() {
    return Native.SenderKeyDistributionMessage_GetId(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
