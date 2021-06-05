/**
 * Copyright (C) 2013-2021 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;
import org.whispersystems.libsignal.InvalidKeyException;

public class Curve {
  public static final int CURVE_25519_TYPE   = 0x05;

  public static ECKeyPair generateKeyPair() {
    ECPrivateKey privateKey = ECPrivateKey.generate();
    ECPublicKey publicKey = privateKey.publicKey();
    return new ECKeyPair(publicKey, privateKey);
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset)
      throws InvalidKeyException
  {
    if (bytes == null || bytes.length - offset < 1) {
      throw new InvalidKeyException("No key type identifier");
    }

    return new ECPublicKey(bytes, offset);
  }

  public static ECPrivateKey decodePrivatePoint(byte[] bytes) {
    return new ECPrivateKey(bytes);
  }

  public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws InvalidKeyException
  {
    if (publicKey == null) {
      throw new InvalidKeyException("public value is null");
    }

    if (privateKey == null) {
      throw new InvalidKeyException("private value is null");
    }

    return privateKey.calculateAgreement(publicKey);
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null || signature == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return signingKey.verifySignature(message, signature);
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey == null || message == null) {
      throw new InvalidKeyException("Values must not be null");
    }

    return signingKey.calculateSignature(message);
  }

}
