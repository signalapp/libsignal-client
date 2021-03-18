/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.kdf;

public class HKDFv2 extends HKDF {
  @Override
  protected int getVersion() {
    return 2;
  }
}
