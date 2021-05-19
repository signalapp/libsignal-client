//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import junit.framework.TestCase;
import org.whispersystems.libsignal.util.Hex;

public class CryptographicMacTests extends TestCase {

   void hmacKat(String algo, String hexKey, String hexInput, String hexExpectedOutput) throws Exception {
     CryptographicMac hmac = new CryptographicMac(algo, Hex.fromStringCondensed(hexKey));

     byte[] input = Hex.fromStringCondensed(hexInput);

     hmac.update(input);
     byte[] macAllInOne = hmac.finish();
     assertEquals(Hex.toHexString(macAllInOne), hexExpectedOutput);

     if(input.length > 1) {
       hmac.update(input, 0, 1);
       hmac.update(input, 1, input.length - 1);
       byte[] macSplit = hmac.finish();
       assertEquals(Hex.toHexString(macSplit), hexExpectedOutput);

       hmac.update(input, 0, input.length - 1);
       hmac.update(input, input.length - 1, 1);
       byte[] macSplit2 = hmac.finish();
       assertEquals(Hex.toHexString(macSplit2), hexExpectedOutput);
     }
   }

   public void testHmacSha1() throws Exception {
     // RFC 2202
     hmacKat("HmacSha1",
             "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
             "4869205468657265",
             "b617318655057264e28bc0b6fb378c8ef146be00");

     hmacKat("HmacSha1",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
             "125d7342b9ac11cd91a39af48aa17b4f63f175d3");
   }

   public void testHmacSha256() throws Exception {
     // RFC 4231
     hmacKat("HmacSha256",
             "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
             "4869205468657265",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

     hmacKat("HmacSha256",
             "4a656665",
             "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
   }

}
