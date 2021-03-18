/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;

/**
 * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
 *
 * <p>Once a session has been established, {@link org.whispersystems.libsignal.groups.GroupCipher}
 * can be used to encrypt/decrypt messages in that session.
 *
 * <p>The built sessions are unidirectional: they can be used either for sending or for receiving,
 * but not both.
 *
 * <p>Sessions are constructed per (groupId + senderId + deviceId) tuple. Remote logical users are
 * identified by their senderId, and each logical recipientId can have multiple physical devices.
 *
 * @author Moxie Marlinspike
 */
public class GroupSessionBuilder {
  private final SenderKeyStore senderKeyStore;

  public GroupSessionBuilder(SenderKeyStore senderKeyStore) {
    this.senderKeyStore = senderKeyStore;
  }

  /**
   * Construct a group session for receiving messages from senderKeyName.
   *
   * @param senderKeyName The (groupId, senderId, deviceId) tuple associated with the
   *     SenderKeyDistributionMessage.
   * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
   */
  public void process(
      SenderKeyName senderKeyName, SenderKeyDistributionMessage senderKeyDistributionMessage) {
    synchronized (GroupCipher.LOCK) {
      Native.GroupSessionBuilder_ProcessSenderKeyDistributionMessage(
          senderKeyName.nativeHandle(),
          senderKeyDistributionMessage.nativeHandle(),
          senderKeyStore,
          null);
    }
  }

  /**
   * Construct a group session for sending messages.
   *
   * @param senderKeyName The (groupId, senderId, deviceId) tuple. In this case, 'senderId' should
   *     be the caller.
   * @return A SenderKeyDistributionMessage that is individually distributed to each member of the
   *     group.
   */
  public SenderKeyDistributionMessage create(SenderKeyName senderKeyName) {
    synchronized (GroupCipher.LOCK) {
      return new SenderKeyDistributionMessage(
          Native.GroupSessionBuilder_CreateSenderKeyDistributionMessage(
              senderKeyName.nativeHandle(), senderKeyStore, null));
    }
  }
}
