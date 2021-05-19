//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto.jce;

import org.signal.libsignal.crypto.CryptographicMac;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Mac {

  String algoName;
  CryptographicMac hmac;

  public static Mac getInstance(String algoName) throws NoSuchAlgorithmException {
    return new Mac(algoName);
  }

  private Mac(String algoName) throws NoSuchAlgorithmException {
    if (!algoName.equals("HMACSha256") && !algoName.equals("HMACSha1")) {
      throw new NoSuchAlgorithmException(algoName);
    }

    this.algoName = algoName;
  }

  public void init(SecretKeySpec key) throws InvalidKeyException, IllegalStateException {
    this.hmac = new CryptographicMac(this.algoName, key.getEncoded());
  }

  public void update(byte[] input, int offset, int len) throws IllegalStateException {
    if (this.hmac == null) {
      throw new IllegalStateException("Mac instance was never keyed");
    }

    this.hmac.update(input, offset, len);
  }

  public void update(byte[] input) throws IllegalStateException {
    update(input, 0, input.length);
  }

  public byte[] doFinal() throws IllegalStateException {
    if (this.hmac == null) {
      throw new IllegalStateException("Mac instance was never keyed");
    }

    return this.hmac.finish();
  }

  public byte[] doFinal(byte[] last) throws IllegalStateException {
    update(last);
    return doFinal();
  }

  public byte[] doFinal(byte[] last, int offset, int len) throws IllegalStateException {
    update(last, offset, len);
    return doFinal();
  }
}
