//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import junit.framework.TestCase;
import org.whispersystems.libsignal.util.Hex;

public class CryptographicHashTests extends TestCase {

   void hashKat(String algo, String hexInput, String hexExpectedOutput) throws Exception {
     CryptographicHash hash = new CryptographicHash(algo);

     byte[] input = Hex.fromStringCondensed(hexInput);

     hash.update(input);
     byte[] digestAllInOne = hash.finish();

     assertEquals(Hex.toHexString(digestAllInOne), hexExpectedOutput);

     if(input.length > 1) {
       hash.update(input, 0, 1);
       hash.update(input, 1, input.length - 1);
       byte[] digestSplit = hash.finish();
       assertEquals(Hex.toHexString(digestSplit), hexExpectedOutput);

       hash.update(input, 0, input.length - 1);
       hash.update(input, input.length - 1, 1);
       byte[] digestSplit2 = hash.finish();
       assertEquals(Hex.toHexString(digestSplit2), hexExpectedOutput);
     }
   }

   public void testSha1() throws Exception {
     hashKat("Sha1", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
     hashKat("Sha1", "616263", "a9993e364706816aba3e25717850c26c9cd0d89d");
     hashKat("Sha1", "f1ea1c9b787bad", "b234020692659c3dee19f7e75390984dd7e7ebbb");
   }

   public void testSha256() throws Exception {
     hashKat("Sha256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
     hashKat("Sha256", "616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
     hashKat("Sha256", "6d65737361676520646967657374",
             "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
   }

   public void testSha512() throws Exception {
     hashKat("Sha512", "",
             "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
     hashKat("Sha512", "616263",
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
     hashKat("Sha512", "6d65737361676520646967657374",
             "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
   }
}
