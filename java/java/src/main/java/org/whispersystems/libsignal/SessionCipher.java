/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

/**
 * The main entry point for Signal Protocol encrypt/decrypt operations.
 *
 * <p>Once a session has been established with {@link SessionBuilder}, this class can be used for
 * all encrypt/decrypt operations within that session.
 *
 * <p>This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class SessionCipher {

  private final SessionStore sessionStore;
  private final IdentityKeyStore identityKeyStore;
  private final PreKeyStore preKeyStore;
  private final SignedPreKeyStore signedPreKeyStore;
  private final SignalProtocolAddress remoteAddress;

  /**
   * Construct a SessionCipher for encrypt/decrypt operations on a session. In order to use
   * SessionCipher, a session must have already been created and stored using {@link
   * SessionBuilder}.
   *
   * @param sessionStore The {@link SessionStore} that contains a session for this recipient.
   * @param remoteAddress The remote address that messages will be encrypted to or decrypted from.
   */
  public SessionCipher(
      SessionStore sessionStore,
      PreKeyStore preKeyStore,
      SignedPreKeyStore signedPreKeyStore,
      IdentityKeyStore identityKeyStore,
      SignalProtocolAddress remoteAddress) {
    this.sessionStore = sessionStore;
    this.preKeyStore = preKeyStore;
    this.identityKeyStore = identityKeyStore;
    this.remoteAddress = remoteAddress;
    this.signedPreKeyStore = signedPreKeyStore;
  }

  public SessionCipher(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
    this(store, store, store, store, remoteAddress);
  }

  /**
   * Encrypt a message.
   *
   * @param paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   */
  public CiphertextMessage encrypt(byte[] paddedMessage) throws UntrustedIdentityException {
    return Native.SessionCipher_EncryptMessage(
        paddedMessage, this.remoteAddress.nativeHandle(), sessionStore, identityKeyStore);
  }

  /**
   * Decrypt a message.
   *
   * @param ciphertext The {@link PreKeySignalMessage} to decrypt.
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *     is no longer supported.
   * @throws InvalidKeyIdException when there is no local {@link
   *     org.whispersystems.libsignal.state.PreKeyRecord} that corresponds to the PreKey ID in the
   *     message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  public byte[] decrypt(PreKeySignalMessage ciphertext)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException,
          InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException {
    return Native.SessionCipher_DecryptPreKeySignalMessage(
        ciphertext.nativeHandle(),
        remoteAddress.nativeHandle(),
        sessionStore,
        identityKeyStore,
        preKeyStore,
        signedPreKeyStore,
        null);
  }

  /**
   * Decrypt a message.
   *
   * @param ciphertext The {@link SignalMessage} to decrypt.
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *     is no longer supported.
   * @throws NoSessionException if there is no established session for this contact.
   */
  public byte[] decrypt(SignalMessage ciphertext)
      throws InvalidMessageException, DuplicateMessageException, LegacyMessageException,
          NoSessionException, UntrustedIdentityException {
    return Native.SessionCipher_DecryptSignalMessage(
        ciphertext.nativeHandle(),
        remoteAddress.nativeHandle(),
        sessionStore,
        identityKeyStore,
        null);
  }

  public int getRemoteRegistrationId() {
    if (!sessionStore.containsSession(remoteAddress)) {
      throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
    }

    SessionRecord record = sessionStore.loadSession(remoteAddress);
    return record.getRemoteRegistrationId();
  }

  public int getSessionVersion() {
    if (!sessionStore.containsSession(remoteAddress)) {
      throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
    }

    SessionRecord record = sessionStore.loadSession(remoteAddress);
    return record.getSessionVersion();
  }
}
