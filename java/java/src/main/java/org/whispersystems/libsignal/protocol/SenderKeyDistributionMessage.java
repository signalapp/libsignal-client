/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.UUID;

public class SenderKeyDistributionMessage {

  private final long handle;

  @Override
  protected void finalize() {
     Native.SenderKeyDistributionMessage_Destroy(this.handle);
  }

  public SenderKeyDistributionMessage(long handle) {
    this.handle = handle;
  }

  public SenderKeyDistributionMessage(byte[] serialized) throws LegacyMessageException, InvalidMessageException {
    handle = Native.SenderKeyDistributionMessage_Deserialize(serialized);
  }

  public byte[] serialize() {
    return Native.SenderKeyDistributionMessage_GetSerialized(this.handle);
  }

  public UUID getDistributionId() {
    return Native.SenderKeyMessage_GetDistributionId(this.handle);
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

  public int getChainId() {
    return Native.SenderKeyDistributionMessage_GetChainId(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
