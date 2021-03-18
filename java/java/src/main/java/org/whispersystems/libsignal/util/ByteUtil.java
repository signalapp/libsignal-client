/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;

public class ByteUtil {

  public static byte[] combine(byte[]... elements) {
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      for (byte[] element : elements) {
        baos.write(element);
      }

      return baos.toByteArray();
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  public static byte[][] split(byte[] input, int firstLength, int secondLength) {
    byte[][] parts = new byte[2][];

    parts[0] = new byte[firstLength];
    System.arraycopy(input, 0, parts[0], 0, firstLength);

    parts[1] = new byte[secondLength];
    System.arraycopy(input, firstLength, parts[1], 0, secondLength);

    return parts;
  }

  public static byte[][] split(byte[] input, int firstLength, int secondLength, int thirdLength)
      throws ParseException {
    if (input == null
        || firstLength < 0
        || secondLength < 0
        || thirdLength < 0
        || input.length < firstLength + secondLength + thirdLength) {
      throw new ParseException(
          "Input too small: " + (input == null ? null : Hex.toString(input)), 0);
    }

    byte[][] parts = new byte[3][];

    parts[0] = new byte[firstLength];
    System.arraycopy(input, 0, parts[0], 0, firstLength);

    parts[1] = new byte[secondLength];
    System.arraycopy(input, firstLength, parts[1], 0, secondLength);

    parts[2] = new byte[thirdLength];
    System.arraycopy(input, firstLength + secondLength, parts[2], 0, thirdLength);

    return parts;
  }

  public static byte[] trim(byte[] input, int length) {
    byte[] result = new byte[length];
    System.arraycopy(input, 0, result, 0, result.length);

    return result;
  }

  public static byte intsToByteHighAndLow(int highValue, int lowValue) {
    return (byte) ((highValue << 4 | lowValue) & 0xFF);
  }

  public static int highBitsToInt(byte value) {
    return (value & 0xFF) >> 4;
  }

  public static byte[] longToByteArray(long value) {
    byte[] bytes = new byte[8];
    bytes[7] = (byte) value;
    bytes[6] = (byte) (value >> 8);
    bytes[5] = (byte) (value >> 16);
    bytes[4] = (byte) (value >> 24);
    bytes[3] = (byte) (value >> 32);
    bytes[2] = (byte) (value >> 40);
    bytes[1] = (byte) (value >> 48);
    bytes[0] = (byte) (value >> 56);
    return bytes;
  }

  public static long byteArray5ToLong(byte[] bytes, int offset) {
    return ((bytes[offset] & 0xffL) << 32)
        | ((bytes[offset + 1] & 0xffL) << 24)
        | ((bytes[offset + 2] & 0xffL) << 16)
        | ((bytes[offset + 3] & 0xffL) << 8)
        | ((bytes[offset + 4] & 0xffL));
  }
}
