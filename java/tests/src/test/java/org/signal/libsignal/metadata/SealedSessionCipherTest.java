package org.signal.libsignal.metadata;

import junit.framework.TestCase;
import org.signal.client.internal.Native;
import org.signal.libsignal.metadata.SealedSessionCipher.DecryptionResult;
import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.metadata.certificate.ServerCertificate;
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Hex;
import org.whispersystems.libsignal.util.guava.Optional;

import java.util.Arrays;
import java.util.UUID;

public class SealedSessionCipherTest extends TestCase {

  private static SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, int signedPreKeyId)
      throws InvalidKeyException
  {
    ECKeyPair keyPair   = Curve.generateKeyPair();
    byte[]    signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());

    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }

  public void testEncryptDecrypt() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMetadataMessageException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "smert za smert".getBytes());


    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    DecryptionResult plaintext = bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);

    assertEquals(new String(plaintext.getPaddedMessage()), "smert za smert");
    assertEquals(plaintext.getSenderUuid(), "9d0652a3-dcc3-4d11-975f-74d61598733f");
    assertEquals(plaintext.getSenderE164().get(), "+14151111111");
    assertEquals(plaintext.getDeviceId(), 1);
  }

  public void testEncryptDecryptUntrusted() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    ECKeyPair           falseTrustRoot    = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(falseTrustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "\u0438 \u0432\u043E\u0442 \u044F".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptDecryptExpired() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "\u0438 \u0432\u043E\u0442 \u044F".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31338);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptFromWrongIdentity() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    ECKeyPair           randomKeyPair     = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, randomKeyPair.getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "smert za smert".getBytes());


    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptDecryptGroup() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidMetadataMessageException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, senderAddress);

    SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(senderAddress, distributionId);
    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
    bobSessionBuilder.process(senderAddress, receivedAliceDistributionMessage);

    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_SUPPLEMENTARY, Optional.of(new byte[]{42}));

    byte[] aliceMessage = aliceCipher.multiRecipientEncrypt(Arrays.asList(bobAddress), usmcFromAlice);
    byte[] bobMessage = SealedSessionCipher.multiRecipientMessageForSingleRecipient(aliceMessage);

    DecryptionResult plaintext = bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), bobMessage, 31335);

    assertEquals(new String(plaintext.getPaddedMessage()), "smert ze smert");
    assertEquals(plaintext.getSenderUuid(), "9d0652a3-dcc3-4d11-975f-74d61598733f");
    assertEquals(plaintext.getSenderE164().get(), "+14151111111");
    assertEquals(plaintext.getDeviceId(), 1);
  }

  public void testProtocolException() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidMetadataMessageException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, senderAddress);

    // Send a group message without sending the distribution ID first.
    aliceSessionBuilder.create(senderAddress, distributionId);
    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_SUPPLEMENTARY, Optional.of(new byte[]{42, 1}));

    byte[] aliceMessage = aliceCipher.multiRecipientEncrypt(Arrays.asList(bobAddress), usmcFromAlice);
    byte[] bobMessage = SealedSessionCipher.multiRecipientMessageForSingleRecipient(aliceMessage);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), bobMessage, 31335);
    } catch (ProtocolNoSessionException e) {
      assertEquals(e.getSender(), "+14151111111");
      assertEquals(e.getSenderDevice(), 1);
      assertEquals(e.getContentHint(), UnidentifiedSenderMessageContent.CONTENT_HINT_SUPPLEMENTARY);
      assertEquals(Hex.toHexString(e.getGroupId().get()), Hex.toHexString(new byte[]{42, 1}));
    }
  }

  private SenderCertificate createCertificateFor(ECKeyPair trustRoot, UUID uuid, String e164, int deviceId, ECPublicKey identityKey, long expires)
      throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair serverKey = Curve.generateKeyPair();

    ServerCertificate serverCertificate = new ServerCertificate(Native.ServerCertificate_New(1, serverKey.getPublicKey().nativeHandle(), trustRoot.getPrivateKey().nativeHandle()));

    return new SenderCertificate(Native.SenderCertificate_New(uuid.toString(), e164, deviceId, identityKey.nativeHandle(), expires,
                                                              serverCertificate.nativeHandle(), serverKey.getPrivateKey().nativeHandle()));
  }

  private void initializeSessions(TestInMemorySignalProtocolStore aliceStore, TestInMemorySignalProtocolStore bobStore, SignalProtocolAddress bobAddress)
      throws InvalidKeyException, UntrustedIdentityException
  {
    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = generateSignedPreKey(bobIdentityKey, 2);

    PreKeyBundle bobBundle             = new PreKeyBundle(1, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey());
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);
    aliceSessionBuilder.process(bobBundle);

    bobStore.storeSignedPreKey(2, bobSignedPreKey);
    bobStore.storePreKey(1, new PreKeyRecord(1, bobPreKey));

  }
}
