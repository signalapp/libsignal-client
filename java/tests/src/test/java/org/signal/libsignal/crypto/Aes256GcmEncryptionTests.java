//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import junit.framework.TestCase;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.Hex;

import java.io.IOException;

public class Aes256GcmEncryptionTests extends TestCase {

  public void testAesGcmKats() throws Exception {
    testAesGcmKat(
       "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
       "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
       "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
       "76fc6ece0f4e1768cddf8853bb2d551b",
       "cafebabefacedbaddecaf888",
       "feedfacedeadbeeffeedfacedeadbeefabaddad2");
  }

  private static void testAesGcmKat(
      String hex_key,
      String hex_plaintext,
      String hex_ciphertext,
      String hex_tag,
      String hex_nonce,
      String hex_associated_data) throws IOException, InvalidKeyException {

   byte[] key = Hex.fromStringCondensed(hex_key);
   byte[] plaintext = Hex.fromStringCondensed(hex_plaintext);
   byte[] nonce = Hex.fromStringCondensed(hex_nonce);
   byte[] ad = Hex.fromStringCondensed(hex_associated_data);

   Aes256GcmEncryption gcmEnc = new Aes256GcmEncryption(key, nonce, ad);
   byte[] ciphertext = plaintext.clone();
   gcmEnc.encrypt(ciphertext);
   byte[] tag = gcmEnc.computeTag();
   assertEquals(Hex.toHexString(ciphertext), hex_ciphertext);
   assertEquals(Hex.toHexString(tag), hex_tag);

   Aes256GcmDecryption gcmDec = new Aes256GcmDecryption(key, nonce, ad);
   byte[] decrypted = ciphertext.clone();
   gcmDec.decrypt(decrypted);
   assertEquals(Hex.toHexString(decrypted), hex_plaintext);
   assertEquals(gcmDec.verifyTag(tag), true);

   Aes256GcmEncryption gcmEnc2 = new Aes256GcmEncryption(key, nonce, ad);
   byte[] ciphertextSplit = plaintext.clone();
   gcmEnc2.encrypt(ciphertextSplit, 0, 1);
   gcmEnc2.encrypt(ciphertextSplit, 1, plaintext.length - 1);
   byte[] tag2 = gcmEnc2.computeTag();
   assertEquals(Hex.toHexString(ciphertextSplit), hex_ciphertext);
   assertEquals(Hex.toHexString(tag2), hex_tag);

   Aes256GcmDecryption gcmDec2 = new Aes256GcmDecryption(key, nonce, ad);
   byte[] decryptedSplit = ciphertext.clone();
   gcmDec2.decrypt(decryptedSplit, 0, 1);
   gcmDec2.decrypt(decryptedSplit, 1, ciphertext.length - 1);
   assertEquals(Hex.toHexString(decryptedSplit), hex_plaintext);
   assertEquals(gcmDec2.verifyTag(tag), true);
  }
}
