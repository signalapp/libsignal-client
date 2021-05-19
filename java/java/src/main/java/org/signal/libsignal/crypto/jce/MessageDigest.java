//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto.jce;

import org.signal.libsignal.crypto.CryptographicHash;

import java.security.NoSuchAlgorithmException;

public class MessageDigest {
  CryptographicHash hash;

  public static MessageDigest getInstance(String algoName) throws NoSuchAlgorithmException {
    return new MessageDigest(algoName);
  }

  private MessageDigest(String algoName) throws NoSuchAlgorithmException {
    this.hash = new CryptographicHash(algoName);
  }

  public void update(byte[] input, int offset, int len) {
    this.hash.update(input, offset, len);
  }

  public void update(byte[] input) {
    update(input, 0, input.length);
  }

  public byte[] doFinal() {
    return this.hash.finish();
  }

  public byte[] doFinal(byte[] last) {
    update(last);
    return doFinal();
  }

  public byte[] doFinal(byte[] last, int offset, int len) {
    update(last, offset, len);
    return doFinal();
  }
}
