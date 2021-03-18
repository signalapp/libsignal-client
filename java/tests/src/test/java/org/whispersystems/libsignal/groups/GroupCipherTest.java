package org.whispersystems.libsignal.groups;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import junit.framework.TestCase;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;

public class GroupCipherTest extends TestCase {

  private static final SignalProtocolAddress SENDER_ADDRESS =
      new SignalProtocolAddress("+14150001111", 1);
  private static final SenderKeyName GROUP_SENDER =
      new SenderKeyName("nihilist history reading group", SENDER_ADDRESS);

  public void testNoSession()
      throws InvalidMessageException, LegacyMessageException, NoSessionException,
          DuplicateMessageException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

    SenderKeyDistributionMessage sentAliceDistributionMessage =
        aliceSessionBuilder.create(GROUP_SENDER);
    SenderKeyDistributionMessage receivedAliceDistributionMessage =
        new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

    //    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

    byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert".getBytes());
    try {
      byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);
      throw new AssertionError("Should be no session!");
    } catch (NoSessionException e) {
      // good
    }
  }

  public void testBasicEncryptDecrypt()
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException,
          NoSessionException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

    SenderKeyDistributionMessage sentAliceDistributionMessage =
        aliceSessionBuilder.create(GROUP_SENDER);
    SenderKeyDistributionMessage receivedAliceDistributionMessage =
        new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

    byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert".getBytes());
    byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

    assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
  }

  public void testLargeMessages()
      throws InvalidMessageException, LegacyMessageException, NoSessionException,
          DuplicateMessageException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

    SenderKeyDistributionMessage sentAliceDistributionMessage =
        aliceSessionBuilder.create(GROUP_SENDER);
    SenderKeyDistributionMessage receivedAliceDistributionMessage =
        new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

    byte[] plaintext = new byte[1024 * 1024];
    new Random().nextBytes(plaintext);

    byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(plaintext);
    byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

    assertTrue(Arrays.equals(plaintext, plaintextFromAlice));
  }

  public void testBasicRatchet()
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException,
          NoSessionException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    SenderKeyName aliceName = GROUP_SENDER;

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

    SenderKeyDistributionMessage sentAliceDistributionMessage =
        aliceSessionBuilder.create(aliceName);
    SenderKeyDistributionMessage receivedAliceDistributionMessage =
        new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

    bobSessionBuilder.process(aliceName, receivedAliceDistributionMessage);

    byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert".getBytes());
    byte[] ciphertextFromAlice2 = aliceGroupCipher.encrypt("smert ze smert2".getBytes());
    byte[] ciphertextFromAlice3 = aliceGroupCipher.encrypt("smert ze smert3".getBytes());

    byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

    try {
      bobGroupCipher.decrypt(ciphertextFromAlice);
      throw new AssertionError("Should have ratcheted forward!");
    } catch (DuplicateMessageException dme) {
      // good
    }

    byte[] plaintextFromAlice2 = bobGroupCipher.decrypt(ciphertextFromAlice2);
    byte[] plaintextFromAlice3 = bobGroupCipher.decrypt(ciphertextFromAlice3);

    assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
    assertTrue(new String(plaintextFromAlice2).equals("smert ze smert2"));
    assertTrue(new String(plaintextFromAlice3).equals("smert ze smert3"));
  }

  public void testLateJoin()
      throws NoSessionException, InvalidMessageException, LegacyMessageException,
          DuplicateMessageException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);

    SenderKeyName aliceName = GROUP_SENDER;

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);
    // Send off to some people.

    for (int i = 0; i < 100; i++) {
      aliceGroupCipher.encrypt("up the punks up the punks up the punks".getBytes());
    }

    // Now Bob Joins.
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

    SenderKeyDistributionMessage distributionMessageToBob = aliceSessionBuilder.create(aliceName);
    bobSessionBuilder.process(
        aliceName, new SenderKeyDistributionMessage(distributionMessageToBob.serialize()));

    byte[] ciphertext = aliceGroupCipher.encrypt("welcome to the group".getBytes());
    byte[] plaintext = bobGroupCipher.decrypt(ciphertext);

    assertEquals(new String(plaintext), "welcome to the group");
  }

  public void testOutOfOrder()
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException,
          NoSessionException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    SenderKeyName aliceName = GROUP_SENDER;

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

    bobSessionBuilder.process(aliceName, aliceDistributionMessage);

    ArrayList<byte[]> ciphertexts = new ArrayList<>(100);

    for (int i = 0; i < 100; i++) {
      ciphertexts.add(aliceGroupCipher.encrypt("up the punks".getBytes()));
    }

    while (ciphertexts.size() > 0) {
      int index = randomInt() % ciphertexts.size();
      byte[] ciphertext = ciphertexts.remove(index);
      byte[] plaintext = bobGroupCipher.decrypt(ciphertext);

      assertTrue(new String(plaintext).equals("up the punks"));
    }
  }

  public void testEncryptNoSession() {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    GroupCipher aliceGroupCipher =
        new GroupCipher(
            aliceStore,
            new SenderKeyName("coolio groupio", new SignalProtocolAddress("+10002223333", 1)));
    try {
      aliceGroupCipher.encrypt("up the punks".getBytes());
      throw new AssertionError("Should have failed!");
    } catch (NoSessionException nse) {
      // good
    }
  }

  public void testTooFarInFuture()
      throws DuplicateMessageException, InvalidMessageException, LegacyMessageException,
          NoSessionException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    SenderKeyName aliceName = GROUP_SENDER;

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

    bobSessionBuilder.process(aliceName, aliceDistributionMessage);

    for (int i = 0; i < 25001; i++) {
      aliceGroupCipher.encrypt("up the punks".getBytes());
    }

    byte[] tooFarCiphertext = aliceGroupCipher.encrypt("notta gonna worka".getBytes());
    try {
      bobGroupCipher.decrypt(tooFarCiphertext);
      throw new AssertionError("Should have failed!");
    } catch (InvalidMessageException e) {
      // good
    }
  }

  public void testMessageKeyLimit() throws Exception {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

    SenderKeyName aliceName = GROUP_SENDER;

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
    GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

    bobSessionBuilder.process(aliceName, aliceDistributionMessage);

    List<byte[]> inflight = new LinkedList<>();

    for (int i = 0; i < 2010; i++) {
      inflight.add(aliceGroupCipher.encrypt("up the punks".getBytes()));
    }

    bobGroupCipher.decrypt(inflight.get(1000));
    bobGroupCipher.decrypt(inflight.get(inflight.size() - 1));

    try {
      bobGroupCipher.decrypt(inflight.get(0));
      throw new AssertionError("Should have failed!");
    } catch (DuplicateMessageException e) {
      // good
    }
  }

  private int randomInt() {
    try {
      return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }
}
