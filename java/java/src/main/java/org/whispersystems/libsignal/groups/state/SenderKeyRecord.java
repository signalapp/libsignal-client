/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups.state;

import org.signal.client.internal.Native;

import java.io.IOException;

/**
 * A durable representation of a set of SenderKeyStates for a specific
 * (senderName, deviceId, distributionId) tuple.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyRecord {
  private long handle;

  @Override
  protected void finalize() {
    Native.SenderKeyRecord_Destroy(this.handle);
  }

  public SenderKeyRecord() {
    handle = Native.SenderKeyRecord_New();
  }

  public SenderKeyRecord(long handle) {
    this.handle = handle;
  }

  public SenderKeyRecord(byte[] serialized) throws IOException {
    handle = Native.SenderKeyRecord_Deserialize(serialized);
  }

  public byte[] serialize() {
    return Native.SenderKeyRecord_GetSerialized(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
