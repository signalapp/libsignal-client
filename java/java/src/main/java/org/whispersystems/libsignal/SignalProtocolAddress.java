/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.signal.client.internal.Native;

public class SignalProtocolAddress {
  private final long handle;

  public SignalProtocolAddress(String name, int deviceId) {
    this.handle = Native.ProtocolAddress_New(name, deviceId);
  }

  public SignalProtocolAddress(long handle) {
    this.handle = handle;
  }

  @Override
  protected void finalize() {
    Native.ProtocolAddress_Destroy(this.handle);
  }

  public String getName() {
    return Native.ProtocolAddress_Name(this.handle);
  }

  public int getDeviceId() {
    return Native.ProtocolAddress_DeviceId(this.handle);
  }

  @Override
  public String toString() {
    return getName() + ":" + getDeviceId();
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) return false;
    if (!(other instanceof SignalProtocolAddress)) return false;

    SignalProtocolAddress that = (SignalProtocolAddress) other;
    return this.getName().equals(that.getName()) && this.getDeviceId() == that.getDeviceId();
  }

  @Override
  public int hashCode() {
    return this.getName().hashCode() ^ this.getDeviceId();
  }

  public long nativeHandle() {
    return this.handle;
  }
}
