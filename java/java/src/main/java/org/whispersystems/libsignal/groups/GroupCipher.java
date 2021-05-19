/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.CiphertextMessage;

import java.util.UUID;

/**
 * The main entry point for Signal Protocol group encrypt/decrypt operations.
 *
 * Once a session has been established with {@link org.whispersystems.libsignal.groups.GroupSessionBuilder}
 * and a {@link org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage} has been
 * distributed to each member of the group, this class can be used for all subsequent encrypt/decrypt
 * operations within that session (ie: until group membership changes).
 *
 * This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class GroupCipher {

  private final SenderKeyStore senderKeyStore;
  private final SignalProtocolAddress sender;

  public GroupCipher(SenderKeyStore senderKeyStore, SignalProtocolAddress sender) {
    this.senderKeyStore = senderKeyStore;
    this.sender         = sender;
  }

  /**
   * Encrypt a message.
   *
   * @param paddedPlaintext The plaintext message bytes, optionally padded.
   * @return Ciphertext.
   * @throws NoSessionException
   */
  public CiphertextMessage encrypt(UUID distributionId, byte[] paddedPlaintext) throws NoSessionException {
    try {
      return Native.GroupCipher_EncryptMessage(this.sender.nativeHandle(), distributionId, paddedPlaintext, this.senderKeyStore, null);
    } catch (IllegalStateException e) {
      throw new NoSessionException(e);
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
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
  {
    try {
      return Native.GroupCipher_DecryptMessage(this.sender.nativeHandle(), senderKeyMessageBytes, this.senderKeyStore, null);
    } catch (IllegalStateException e) {
      throw new NoSessionException(e);
    }
  }
}
