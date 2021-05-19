//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import junit.framework.TestCase;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.util.Hex;

import java.io.IOException;

public class Aes256GcmSivTests extends TestCase {

  public void testAesGcmSivInvalidInputs() throws Exception {
    try {
      byte[] invalid_key = new byte[16];
      Aes256GcmSiv gcm_siv = new Aes256GcmSiv(invalid_key);
      throw new AssertionError("Invalid key length accepted");
    } catch (InvalidKeyException e) {
      /* good */
    }

    byte[] key = new byte[32];
    Aes256GcmSiv gcm_siv = new Aes256GcmSiv(key);

    try {
      byte[] ptext = new byte[5];
      byte[] ad = new byte[5];
      byte[] invalid_nonce = new byte[16];
      gcm_siv.encrypt(ptext, invalid_nonce, ad);
      throw new AssertionError("Invalid nonce accepted");
    } catch (IllegalArgumentException e) {
      /* good */
    }
  }

  public void testAesGcmSivKats() throws Exception {
    testAesGcmSivKat(
        "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
        "671fdd4fbdc66f146545fc880c94a95198",
        "9209cfae7372e0a3ec2e5d072d5e26b7b9f3acb73908e54cddf7be1864914e13cf",
        "e4b47801afc0577e34699b9e",
        "874296d5cc1fd16132");
  }

  private static void testAesGcmSivKat(
      String hex_key,
      String hex_plaintext,
      String hex_ciphertext,
      String hex_nonce,
      String hex_associated_data) {

    try {
      byte[] key = Hex.fromStringCondensed(hex_key);
      byte[] plaintext = Hex.fromStringCondensed(hex_plaintext);
      byte[] nonce = Hex.fromStringCondensed(hex_nonce);
      byte[] ad = Hex.fromStringCondensed(hex_associated_data);

      Aes256GcmSiv gcm_siv = new Aes256GcmSiv(key);

      byte[] ciphertext = gcm_siv.encrypt(plaintext, nonce, ad);
      assertEquals(Hex.toHexString(ciphertext), hex_ciphertext);

      byte[] recovered = gcm_siv.decrypt(ciphertext, nonce, ad);
      assertEquals(Hex.toHexString(recovered), hex_plaintext);

      try {
        ciphertext[0] ^= 1;
        gcm_siv.decrypt(ciphertext, nonce, ad);
        throw new AssertionError("Should not have decrypted");
      } catch (InvalidMessageException e) {
        /* good */
      }

      try {
        ciphertext[0] ^= 1; // restore ciphertext
        nonce[0] ^= 1;
        gcm_siv.decrypt(ciphertext, nonce, ad);
        throw new AssertionError("Should not have decrypted");
      } catch (InvalidMessageException e) {
        /* good */
      }

      try {
        nonce[0] ^= 1; // restore nonce
        ad[0] ^= 1;
        gcm_siv.decrypt(ciphertext, nonce, ad);
        throw new AssertionError("Should not have decrypted");
      } catch (InvalidMessageException e) {
        /* good */
      }

    } catch (IOException e) {
      throw new AssertionError(e);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }
}
