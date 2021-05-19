//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto.jce;

import org.signal.libsignal.crypto.Aes256GcmDecryption;
import org.signal.libsignal.crypto.Aes256GcmEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/*
This is a rough compatability layer with Java JCE interface. It diverges from
the behavior of actual JCE in (at least) the following ways

- JCE allows encrypting multiple messages without setting a new nonce. Quoting
  the docs "Upon finishing, this method [doFinal] resets this cipher object to
  the state it was in when previously initialized via a call to init."  If you
  do that with GCM you immediately cause a huge vulnerability. You must call
  init again to set a new nonce.

- JCE allows you to not provide parameters (eg a nonce) and then it will
  randomly generate them for you. This is not implementned.

- JCE allows incremental update of the associated data. This is not supported.
  You may call updateAAD at most 1 time, and it must be before any calls to
  update have been made.

- JCE allows you to not provide the tag to doFinal. As a result, when decrypting
  the JCE implementation must unavoidably buffer 16 bytes to ensure that it does
  not attempt to process the tag as ciphertext. We don't do this. Instead the
  caller must provide the tag to doFinal

- Many irrelevant APIs (ie ones not used by Signal Android app) are not
  implemented at all.

- Only precisely 128-bit tags, 96-bit nonces, and 256-bit keys are supported.

*/
class Cipher {

  static int ENCRYPT_MODE = 0;
  static int DECRYPT_MODE = 1;

  Aes256GcmEncryption gcmEnc;
  Aes256GcmDecryption gcmDec;
  int mode;
  byte[] key;
  byte[] nonce;
  byte[] aad;
  byte[] tagBuf;

  public static Cipher getInstance(String algoName) throws NoSuchAlgorithmException {
    if (algoName != "AES/GCM/NoPadding") {
      throw new NoSuchAlgorithmException(algoName);
    }

    return new Cipher(algoName);
  }

  private Cipher(String algoName) {
    this.mode = -1;
    this.gcmEnc = null;
    this.gcmDec = null;
  }

  public void init(int mode, SecretKeySpec key, IvParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

    this.mode = mode;
    this.key = key.getEncoded();
    this.nonce = params.getIV();
    this.aad = null;
    this.tagBuf = null;

    this.gcmEnc = null;
    this.gcmDec = null;

    if (this.key.length != 32) {
      throw new InvalidKeyException("GCM implementation only supports 256 bit keys");
    }

    if (this.nonce.length != 12) {
      throw new InvalidAlgorithmParameterException("GCM implementation only supports 96 bit nonce");
    }
  }

  public void init(int mode, SecretKeySpec key, GCMParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

    if (params.getTLen() != 128) {
      throw new InvalidAlgorithmParameterException(
          "This GCM implementation supports only 128 bit tags");
    }

    this.mode = mode;
    this.key = key.getEncoded();
    this.nonce = params.getIV();
    this.aad = null;

    gcmEnc = null;
    gcmDec = null;

    if (this.key.length != 32) {
      throw new InvalidKeyException("GCM implementation only supports 256 bit keys");
    }

    if (this.nonce.length != 12) {
      throw new InvalidAlgorithmParameterException("GCM implementation only supports 96 bit nonce");
    }
  }

  public void updateAAD(byte[] aad) throws IllegalStateException {
    if (this.aad != null) {
      throw new IllegalStateException("This API does not support incremental AAD update");
    }
    if (this.gcmEnc != null || this.gcmDec != null) {
      throw new IllegalStateException(
          "This API does not support setting AAD after processing ciphertext");
    }

    this.aad = aad;
  }

  public void update(byte[] input, int offset, int len) throws IllegalStateException {
    if (this.gcmEnc == null && this.gcmDec == null) {

      try {
        if (this.mode == ENCRYPT_MODE) {
          this.gcmEnc = new Aes256GcmEncryption(this.key, this.nonce, this.aad);
        } else {
          this.gcmDec = new Aes256GcmDecryption(this.key, this.nonce, this.aad);
        }
      } catch (org.whispersystems.libsignal.InvalidKeyException e) {
        // We already checked the length so this should never happen
        throw new AssertionError(e);
      }

      this.key = null;
      this.nonce = null;
      this.mode = -1;
    }

    if (this.gcmEnc != null) {
      this.gcmEnc.encrypt(input, offset, len);
    } else {
      this.gcmDec.decrypt(input, offset, len);
    }
  }

  public void update(byte[] input) throws IllegalStateException {
    update(input, 0, input.length);
  }

  public byte[] doFinal() throws IllegalStateException {
    if (this.gcmEnc != null) {
      byte[] tag = this.gcmEnc.computeTag();
      this.gcmEnc = null;
      return tag;
    } else {
      throw new IllegalStateException("Must provide tag to doFinal for GCM decryption");
    }
  }

  public byte[] doFinal(byte[] last) throws IllegalStateException, BadPaddingException {

    if (this.gcmEnc != null) {
      update(last);
      byte[] tag = this.gcmEnc.computeTag();
      this.gcmEnc = null;
      return tag;
    } else {
      if (last.length < 16) {
        throw new IllegalStateException("Must provide tag to doFinal for GCM decryption");
      }

      update(last, 0, last.length - 16);
      byte[] tag = new byte[16];
      System.arraycopy(last, last.length - 16, tag, 0, 16);
      if (!this.gcmDec.verifyTag(tag)) {
        throw new BadPaddingException();
      }
      return null;
    }
  }
}
