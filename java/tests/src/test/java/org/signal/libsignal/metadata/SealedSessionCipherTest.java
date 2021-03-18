package org.signal.libsignal.metadata;

import java.util.UUID;
import junit.framework.TestCase;
import org.signal.client.internal.Native;
import org.signal.libsignal.metadata.SealedSessionCipher.DecryptionResult;
import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.metadata.certificate.ServerCertificate;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

public class SealedSessionCipherTest extends TestCase {

  private static SignedPreKeyRecord generateSignedPreKey(
      IdentityKeyPair identityKeyPair, int signedPreKeyId) throws InvalidKeyException {
    ECKeyPair keyPair = Curve.generateKeyPair();
    byte[] signature =
        Curve.calculateSignature(
            identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());

    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }

  public void testEncryptDecrypt()
      throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException,
          InvalidMetadataMessageException, ProtocolDuplicateMessageException,
          ProtocolUntrustedIdentityException, ProtocolLegacyMessageException,
          ProtocolInvalidKeyException, InvalidMetadataVersionException,
          ProtocolInvalidVersionException, ProtocolInvalidMessageException,
          ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair trustRoot = Curve.generateKeyPair();
    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            1,
            aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(),
            31337);
    SealedSessionCipher aliceCipher =
        new SealedSessionCipher(
            aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext =
        aliceCipher.encrypt(
            new SignalProtocolAddress("+14152222222", 1),
            senderCertificate,
            "smert za smert".getBytes());

    SealedSessionCipher bobCipher =
        new SealedSessionCipher(
            bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    DecryptionResult plaintext =
        bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);

    assertEquals(new String(plaintext.getPaddedMessage()), "smert za smert");
    assertEquals(plaintext.getSenderUuid(), "9d0652a3-dcc3-4d11-975f-74d61598733f");
    assertEquals(plaintext.getSenderE164().get(), "+14151111111");
    assertEquals(plaintext.getDeviceId(), 1);
  }

  public void testEncryptDecryptUntrusted() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair falseTrustRoot = Curve.generateKeyPair();
    SenderCertificate senderCertificate =
        createCertificateFor(
            falseTrustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            1,
            aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(),
            31337);
    SealedSessionCipher aliceCipher =
        new SealedSessionCipher(
            aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext =
        aliceCipher.encrypt(
            new SignalProtocolAddress("+14152222222", 1),
            senderCertificate,
            "\u0438 \u0432\u043E\u0442 \u044F".getBytes());

    SealedSessionCipher bobCipher =
        new SealedSessionCipher(
            bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptDecryptExpired() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair trustRoot = Curve.generateKeyPair();
    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            1,
            aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(),
            31337);
    SealedSessionCipher aliceCipher =
        new SealedSessionCipher(
            aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext =
        aliceCipher.encrypt(
            new SignalProtocolAddress("+14152222222", 1),
            senderCertificate,
            "\u0438 \u0432\u043E\u0442 \u044F".getBytes());

    SealedSessionCipher bobCipher =
        new SealedSessionCipher(
            bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31338);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptFromWrongIdentity() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair randomKeyPair = Curve.generateKeyPair();
    SenderCertificate senderCertificate =
        createCertificateFor(
            trustRoot,
            UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"),
            "+14151111111",
            1,
            randomKeyPair.getPublicKey(),
            31337);
    SealedSessionCipher aliceCipher =
        new SealedSessionCipher(
            aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext =
        aliceCipher.encrypt(
            new SignalProtocolAddress("+14152222222", 1),
            senderCertificate,
            "smert za smert".getBytes());

    SealedSessionCipher bobCipher =
        new SealedSessionCipher(
            bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  private SenderCertificate createCertificateFor(
      ECKeyPair trustRoot,
      UUID uuid,
      String e164,
      int deviceId,
      ECPublicKey identityKey,
      long expires)
      throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair serverKey = Curve.generateKeyPair();

    ServerCertificate serverCertificate =
        new ServerCertificate(
            Native.ServerCertificate_New(
                1,
                serverKey.getPublicKey().nativeHandle(),
                trustRoot.getPrivateKey().nativeHandle()));

    return new SenderCertificate(
        Native.SenderCertificate_New(
            uuid.toString(),
            e164,
            deviceId,
            identityKey.nativeHandle(),
            expires,
            serverCertificate.nativeHandle(),
            serverKey.getPrivateKey().nativeHandle()));
  }

  private void initializeSessions(
      TestInMemorySignalProtocolStore aliceStore, TestInMemorySignalProtocolStore bobStore)
      throws InvalidKeyException, UntrustedIdentityException {
    ECKeyPair bobPreKey = Curve.generateKeyPair();
    IdentityKeyPair bobIdentityKey = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = generateSignedPreKey(bobIdentityKey, 2);

    PreKeyBundle bobBundle =
        new PreKeyBundle(
            1,
            1,
            1,
            bobPreKey.getPublicKey(),
            2,
            bobSignedPreKey.getKeyPair().getPublicKey(),
            bobSignedPreKey.getSignature(),
            bobIdentityKey.getPublicKey());
    SessionBuilder aliceSessionBuilder =
        new SessionBuilder(aliceStore, new SignalProtocolAddress("+14152222222", 1));
    aliceSessionBuilder.process(bobBundle);

    bobStore.storeSignedPreKey(2, bobSignedPreKey);
    bobStore.storePreKey(1, new PreKeyRecord(1, bobPreKey));
  }
}
