/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;

/**
 * The main entry point for Signal Protocol group encrypt/decrypt operations.
 *
 * <p>Once a session has been established with {@link
 * org.whispersystems.libsignal.groups.GroupSessionBuilder} and a {@link
 * org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage} has been distributed to each
 * member of the group, this class can be used for all subsequent encrypt/decrypt operations within
 * that session (ie: until group membership changes).
 *
 * @author Moxie Marlinspike
 */
public class GroupCipher {

  static final Object LOCK = new Object();

  private final SenderKeyStore senderKeyStore;
  private final SenderKeyName senderKeyId;

  public GroupCipher(SenderKeyStore senderKeyStore, SenderKeyName senderKeyId) {
    this.senderKeyStore = senderKeyStore;
    this.senderKeyId = senderKeyId;
  }

  /**
   * Encrypt a message.
   *
   * @param paddedPlaintext The plaintext message bytes, optionally padded.
   * @return Ciphertext.
   * @throws NoSessionException
   */
  public byte[] encrypt(byte[] paddedPlaintext) throws NoSessionException {
    synchronized (LOCK) {
      try {
        return Native.GroupCipher_EncryptMessage(
            this.senderKeyId.nativeHandle(), paddedPlaintext, this.senderKeyStore, null);
      } catch (IllegalStateException e) {
        throw new NoSessionException(e);
      }
    }
  }

  /**
   * Decrypt a SenderKey group message.
   *
   * @param senderKeyMessageBytes The received ciphertext.
   * @return Plaintext
   * @throws LegacyMessageException
   * @throws InvalidMessageException
   * @throws DuplicateMessageException
   */
  public byte[] decrypt(byte[] senderKeyMessageBytes)
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException,
          NoSessionException {
    synchronized (LOCK) {
      try {
        return Native.GroupCipher_DecryptMessage(
            this.senderKeyId.nativeHandle(), senderKeyMessageBytes, this.senderKeyStore, null);
      } catch (IllegalStateException e) {
        throw new NoSessionException(e);
      }
    }
  }
}
