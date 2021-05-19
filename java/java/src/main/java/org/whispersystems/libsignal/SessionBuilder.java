/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

/**
 * SessionBuilder is responsible for setting up encrypted sessions.
 * Once a session has been established, {@link org.whispersystems.libsignal.SessionCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * Sessions are built from one of three different possible vectors:
 * <ol>
 *   <li>A {@link org.whispersystems.libsignal.state.PreKeyBundle} retrieved from a server.</li>
 *   <li>A {@link PreKeySignalMessage} received from a client.</li>
 * </ol>
 *
 * Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class SessionBuilder {
  private static final String TAG = SessionBuilder.class.getSimpleName();

  private final SessionStore      sessionStore;
  private final PreKeyStore       preKeyStore;
  private final SignedPreKeyStore signedPreKeyStore;
  private final IdentityKeyStore  identityKeyStore;
  private final SignalProtocolAddress remoteAddress;

  /**
   * Constructs a SessionBuilder.
   *
   * @param sessionStore The {@link org.whispersystems.libsignal.state.SessionStore} to store the constructed session in.
   * @param preKeyStore The {@link  org.whispersystems.libsignal.state.PreKeyStore} where the client's local {@link org.whispersystems.libsignal.state.PreKeyRecord}s are stored.
   * @param identityKeyStore The {@link org.whispersystems.libsignal.state.IdentityKeyStore} containing the client's identity key information.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  public SessionBuilder(SessionStore sessionStore,
                        PreKeyStore preKeyStore,
                        SignedPreKeyStore signedPreKeyStore,
                        IdentityKeyStore identityKeyStore,
                        SignalProtocolAddress remoteAddress)
  {
    this.sessionStore      = sessionStore;
    this.preKeyStore       = preKeyStore;
    this.signedPreKeyStore = signedPreKeyStore;
    this.identityKeyStore  = identityKeyStore;
    this.remoteAddress     = remoteAddress;
  }

  /**
   * Constructs a SessionBuilder
   * @param store The {@link SignalProtocolStore} to store all state information in.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  public SessionBuilder(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
    this(store, store, store, store, remoteAddress);
  }

  /**
   * Build a new session from a {@link org.whispersystems.libsignal.state.PreKeyBundle} retrieved from
   * a server.
   *
   * @param preKey A PreKey for the destination recipient, retrieved from a server.
   * @throws InvalidKeyException when the {@link org.whispersystems.libsignal.state.PreKeyBundle} is
   *                             badly formatted.
   * @throws org.whispersystems.libsignal.UntrustedIdentityException when the sender's
   *                                                                  {@link IdentityKey} is not
   *                                                                  trusted.
   */
  public void process(PreKeyBundle preKey) throws InvalidKeyException, UntrustedIdentityException {
    Native.SessionBuilder_ProcessPreKeyBundle(preKey.nativeHandle(),
                                              remoteAddress.nativeHandle(),
                                              sessionStore,
                                              identityKeyStore,
                                              null);
  }
}
