/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * <p>Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import java.io.IOException;
import org.signal.client.internal.Native;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
public class SessionRecord {

  long handle;

  @Override
  protected void finalize() {
    Native.SessionRecord_Destroy(this.handle);
  }

  public SessionRecord() {
    this.handle = Native.SessionRecord_NewFresh();
  }

  private SessionRecord(long handle) {
    this.handle = handle;
  }

  public static SessionRecord fromSingleSessionState(byte[] sessionStateBytes) throws IOException {
    return new SessionRecord(Native.SessionRecord_FromSingleSessionState(sessionStateBytes));
  }

  public SessionRecord(byte[] serialized) throws IOException {
    this.handle = Native.SessionRecord_Deserialize(serialized);
  }

  /**
   * Move the current SessionState into the list of "previous" session states, and replace the
   * current SessionState with a fresh reset instance.
   */
  public void archiveCurrentState() {
    Native.SessionRecord_ArchiveCurrentState(this.handle);
  }

  public int getSessionVersion() {
    return Native.SessionRecord_GetSessionVersion(this.handle);
  }

  public int getRemoteRegistrationId() {
    return Native.SessionRecord_GetRemoteRegistrationId(this.handle);
  }

  public int getLocalRegistrationId() {
    return Native.SessionRecord_GetLocalRegistrationId(this.handle);
  }

  public IdentityKey getRemoteIdentityKey() {
    byte[] keyBytes = Native.SessionRecord_GetRemoteIdentityKeyPublic(this.handle);

    if (keyBytes == null) {
      return null;
    }

    try {
      return new IdentityKey(keyBytes);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public IdentityKey getLocalIdentityKey() {
    byte[] keyBytes = Native.SessionRecord_GetLocalIdentityKeyPublic(this.handle);
    try {
      return new IdentityKey(keyBytes);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public boolean hasSenderChain() {
    return Native.SessionRecord_HasSenderChain(this.handle);
  }

  /** @return a serialized version of the current SessionRecord. */
  public byte[] serialize() {
    return Native.SessionRecord_Serialize(this.handle);
  }

  // Following functions are for internal or testing use and may be removed in the future:

  public byte[] getReceiverChainKeyValue(ECPublicKey senderEphemeral) {
    return Native.SessionRecord_GetReceiverChainKeyValue(
        this.handle, senderEphemeral.nativeHandle());
  }

  public byte[] getSenderChainKeyValue() {
    return Native.SessionRecord_GetSenderChainKeyValue(this.handle);
  }

  public byte[] getAliceBaseKey() {
    return Native.SessionRecord_GetAliceBaseKey(this.handle);
  }

  public static SessionRecord initializeAliceSession(
      IdentityKeyPair identityKey,
      ECKeyPair baseKey,
      IdentityKey theirIdentityKey,
      ECPublicKey theirSignedPreKey,
      ECPublicKey theirRatchetKey) {
    return new SessionRecord(
        Native.SessionRecord_InitializeAliceSession(
            identityKey.getPrivateKey().nativeHandle(),
            identityKey.getPublicKey().getPublicKey().nativeHandle(),
            baseKey.getPrivateKey().nativeHandle(),
            baseKey.getPublicKey().nativeHandle(),
            theirIdentityKey.getPublicKey().nativeHandle(),
            theirSignedPreKey.nativeHandle(),
            theirRatchetKey.nativeHandle()));
  }

  public static SessionRecord initializeBobSession(
      IdentityKeyPair identityKey,
      ECKeyPair signedPreKey,
      ECKeyPair ephemeralKey,
      IdentityKey theirIdentityKey,
      ECPublicKey theirBaseKey) {
    return new SessionRecord(
        Native.SessionRecord_InitializeBobSession(
            identityKey.getPrivateKey().nativeHandle(),
            identityKey.getPublicKey().getPublicKey().nativeHandle(),
            signedPreKey.getPrivateKey().nativeHandle(),
            signedPreKey.getPublicKey().nativeHandle(),
            ephemeralKey.getPrivateKey().nativeHandle(),
            ephemeralKey.getPublicKey().nativeHandle(),
            theirIdentityKey.getPublicKey().nativeHandle(),
            theirBaseKey.nativeHandle()));
  }

  long nativeHandle() {
    return this.handle;
  }
}
