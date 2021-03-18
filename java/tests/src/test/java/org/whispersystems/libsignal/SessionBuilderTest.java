package org.whispersystems.libsignal;

import java.util.HashSet;
import java.util.Set;
import junit.framework.TestCase;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Pair;

public class SessionBuilderTest extends TestCase {

  private static final SignalProtocolAddress ALICE_ADDRESS =
      new SignalProtocolAddress("+14151111111", 1);
  private static final SignalProtocolAddress BOB_ADDRESS =
      new SignalProtocolAddress("+14152222222", 1);

  public void testBasicPreKeyV3()
      throws InvalidKeyException, InvalidVersionException, InvalidMessageException,
          InvalidKeyIdException, DuplicateMessageException, LegacyMessageException,
          UntrustedIdentityException, NoSessionException {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    final SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();
    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31337,
            bobPreKeyPair.getPublicKey(),
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    aliceSessionBuilder.process(bobPreKey);

    assertTrue(aliceStore.containsSession(BOB_ADDRESS));
    assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionVersion() == 3);

    String originalMessage = "Good, fast, cheap: pick two";
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(
        22,
        new SignedPreKeyRecord(
            22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
    byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

    assertTrue(bobStore.containsSession(ALICE_ADDRESS));
    assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionVersion() == 3);
    assertTrue(bobStore.loadSession(ALICE_ADDRESS).getAliceBaseKey() != null);
    assertTrue(originalMessage.equals(new String(plaintext)));

    CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
    assertTrue(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

    byte[] alicePlaintext =
        aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
    assertTrue(new String(alicePlaintext).equals(originalMessage));

    runInteraction(aliceStore, bobStore);

    aliceStore = new TestInMemorySignalProtocolStore();
    aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
    aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);

    bobPreKeyPair = Curve.generateKeyPair();
    bobSignedPreKeyPair = Curve.generateKeyPair();
    bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());
    bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31338,
            bobPreKeyPair.getPublicKey(),
            23,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(
        23,
        new SignedPreKeyRecord(
            23, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
    aliceSessionBuilder.process(bobPreKey);

    outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

    try {
      plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
      throw new AssertionError("shouldn't be trusted!");
    } catch (UntrustedIdentityException uie) {
      bobStore.saveIdentity(
          ALICE_ADDRESS, new PreKeySignalMessage(outgoingMessage.serialize()).getIdentityKey());
    }

    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31337,
            Curve.generateKeyPair().getPublicKey(),
            23,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            aliceStore.getIdentityKeyPair().getPublicKey());

    try {
      aliceSessionBuilder.process(bobPreKey);
      throw new AssertionError("shoulnd't be trusted!");
    } catch (UntrustedIdentityException uie) {
      // good
    }
  }

  public void testBadSignedPreKeySignature()
      throws InvalidKeyException, UntrustedIdentityException {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobIdentityKeyStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    for (int i = 0; i < bobSignedPreKeySignature.length * 8; i++) {
      byte[] modifiedSignature = new byte[bobSignedPreKeySignature.length];
      System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

      modifiedSignature[i / 8] ^= (0x01 << (i % 8));

      PreKeyBundle bobPreKey =
          new PreKeyBundle(
              bobIdentityKeyStore.getLocalRegistrationId(),
              1,
              31337,
              bobPreKeyPair.getPublicKey(),
              22,
              bobSignedPreKeyPair.getPublicKey(),
              modifiedSignature,
              bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

      try {
        aliceSessionBuilder.process(bobPreKey);
        throw new AssertionError("Accepted modified device key signature!");
      } catch (InvalidKeyException ike) {
        // good
      }
    }

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobIdentityKeyStore.getLocalRegistrationId(),
            1,
            31337,
            bobPreKeyPair.getPublicKey(),
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

    aliceSessionBuilder.process(bobPreKey);
  }

  public void testRepeatBundleMessageV3()
      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
          InvalidMessageException, InvalidKeyIdException, DuplicateMessageException,
          LegacyMessageException, NoSessionException {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31337,
            bobPreKeyPair.getPublicKey(),
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(
        22,
        new SignedPreKeyRecord(
            22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    aliceSessionBuilder.process(bobPreKey);

    String originalMessage = "Good, fast, cheap: pick two";
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
    CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);
    assertTrue(outgoingMessageTwo.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

    byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);
    assertTrue(originalMessage.equals(new String(plaintext)));

    CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

    byte[] alicePlaintext =
        aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
    assertTrue(originalMessage.equals(new String(alicePlaintext)));

    // The test

    PreKeySignalMessage incomingMessageTwo =
        new PreKeySignalMessage(outgoingMessageTwo.serialize());

    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(incomingMessageTwo.serialize()));
    assertTrue(originalMessage.equals(new String(plaintext)));

    bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
    alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
    assertTrue(originalMessage.equals(new String(alicePlaintext)));
  }

  public void testBadMessageBundle()
      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
          InvalidMessageException, DuplicateMessageException, LegacyMessageException,
          InvalidKeyIdException {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31337,
            bobPreKeyPair.getPublicKey(),
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(
        22,
        new SignedPreKeyRecord(
            22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    aliceSessionBuilder.process(bobPreKey);

    String originalMessage = "Good, fast, cheap: pick two";
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

    byte[] goodMessage = outgoingMessageOne.serialize();
    byte[] badMessage = new byte[goodMessage.length];
    System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

    badMessage[badMessage.length - 10] ^= 0x01;

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(badMessage);
    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

    byte[] plaintext = new byte[0];

    try {
      plaintext = bobSessionCipher.decrypt(incomingMessage);
      throw new AssertionError("Decrypt should have failed!");
    } catch (InvalidMessageException e) {
      // good.
    }

    assertTrue(bobStore.containsPreKey(31337));

    plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(goodMessage));

    assertTrue(originalMessage.equals(new String(plaintext)));
    assertTrue(!bobStore.containsPreKey(31337));
  }

  public void testBadSignedPreKeyStore()
      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
          InvalidMessageException, DuplicateMessageException, LegacyMessageException {
    SignalProtocolStore aliceStore = new TestNoSignedPreKeysStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    SignalProtocolStore bobStore = new TestNoSignedPreKeysStore();

    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31337,
            bobPreKeyPair.getPublicKey(),
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(
        22,
        new SignedPreKeyRecord(
            22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    aliceSessionBuilder.process(bobPreKey);

    String originalMessage = "Good, fast, cheap: pick two";
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());
    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

    byte[] plaintext = null;

    try {
      plaintext = bobSessionCipher.decrypt(incomingMessage);
      throw new AssertionError("Decrypt should have failed!");
    } catch (InvalidKeyIdException e) {
      assertEquals("TestNoSignedPreKeysStore rejected loading 22", e.getMessage());
    }
  }

  public void testBadSignedPreKeyStoreError()
      throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException,
          InvalidMessageException, DuplicateMessageException, LegacyMessageException {
    SignalProtocolStore aliceStore = new TestBadSignedPreKeysStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    SignalProtocolStore bobStore = new TestBadSignedPreKeysStore();

    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            31337,
            bobPreKeyPair.getPublicKey(),
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(
        22,
        new SignedPreKeyRecord(
            22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    aliceSessionBuilder.process(bobPreKey);

    String originalMessage = "Good, fast, cheap: pick two";
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());
    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

    byte[] plaintext = null;

    try {
      plaintext = bobSessionCipher.decrypt(incomingMessage);
      throw new AssertionError("Decrypt should have failed!");
    } catch (InvalidKeyIdException e) {
      throw new AssertionError("libsignal-client swallowed the exception");
    } catch (TestBadSignedPreKeysStore.CustomException e) {
      // success!
    }
  }

  public void testOptionalOneTimePreKey() throws Exception {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
    ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
    byte[] bobSignedPreKeySignature =
        Curve.calculateSignature(
            bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());

    PreKeyBundle bobPreKey =
        new PreKeyBundle(
            bobStore.getLocalRegistrationId(),
            1,
            -1,
            null,
            22,
            bobSignedPreKeyPair.getPublicKey(),
            bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());

    aliceSessionBuilder.process(bobPreKey);

    assertTrue(aliceStore.containsSession(BOB_ADDRESS));
    assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionVersion() == 3);

    String originalMessage = "Good, fast, cheap: pick two";
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
    assertTrue(!incomingMessage.getPreKeyId().isPresent());

    bobStore.storeSignedPreKey(
        22,
        new SignedPreKeyRecord(
            22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
    byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

    assertTrue(bobStore.containsSession(ALICE_ADDRESS));
    assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionVersion() == 3);
    assertTrue(bobStore.loadSession(ALICE_ADDRESS).getAliceBaseKey() != null);
    assertTrue(originalMessage.equals(new String(plaintext)));
  }

  private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException,
          NoSessionException, UntrustedIdentityException {
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

    String originalMessage = "smert ze smert";
    CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(aliceMessage.getType() == CiphertextMessage.WHISPER_TYPE);

    byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(bobMessage.getType() == CiphertextMessage.WHISPER_TYPE);

    plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    for (int i = 0; i < 10; i++) {
      String loopingMessage =
          ("What do we mean by saying that existence precedes essence? "
              + "We mean that man first of all exists, encounters himself, "
              + "surges up in the world--and defines himself aftward. "
              + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext =
          bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (int i = 0; i < 10; i++) {
      String loopingMessage =
          ("What do we mean by saying that existence precedes essence? "
              + "We mean that man first of all exists, encounters himself, "
              + "surges up in the world--and defines himself aftward. "
              + i);
      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext =
          aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    Set<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

    for (int i = 0; i < 10; i++) {
      String loopingMessage =
          ("What do we mean by saying that existence precedes essence? "
              + "We mean that man first of all exists, encounters himself, "
              + "surges up in the world--and defines himself aftward. "
              + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
    }

    for (int i = 0; i < 10; i++) {
      String loopingMessage =
          ("What do we mean by saying that existence precedes essence? "
              + "We mean that man first of all exists, encounters himself, "
              + "surges up in the world--and defines himself aftward. "
              + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext =
          bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (int i = 0; i < 10; i++) {
      String loopingMessage = ("You can only desire based on what you know: " + i);
      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext =
          aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
      byte[] outOfOrderPlaintext =
          bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
      assertTrue(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
    }
  }
}
