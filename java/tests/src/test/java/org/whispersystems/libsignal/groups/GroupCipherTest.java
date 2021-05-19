package org.whispersystems.libsignal.groups;

import junit.framework.TestCase;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.groups.state.InMemorySenderKeyStore;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

public class GroupCipherTest extends TestCase {

  private static final SignalProtocolAddress SENDER_ADDRESS = new SignalProtocolAddress("+14150001111", 1);
  private static final UUID DISTRIBUTION_ID = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

  public void testNoSession() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);
    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

//    bobSessionBuilder.process(SENDER_ADDRESS, DISTRIBUTION_ID, receivedAliceDistributionMessage);

    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "smert ze smert".getBytes());
    try {
      byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice.serialize());
      throw new AssertionError("Should be no session!");
    } catch (NoSessionException e) {
      // good
    }
  }

  public void testBasicEncryptDecrypt()
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
  {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);
    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
    bobSessionBuilder.process(SENDER_ADDRESS, receivedAliceDistributionMessage);

    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "smert ze smert".getBytes());
    byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice.serialize());

    assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
  }

  public void testLargeMessages() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);
    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
    bobSessionBuilder.process(SENDER_ADDRESS, receivedAliceDistributionMessage);

    byte[] plaintext = new byte[1024 * 1024];
    new Random().nextBytes(plaintext);

    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(DISTRIBUTION_ID, plaintext);
    byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice.serialize());

    assertTrue(Arrays.equals(plaintext, plaintextFromAlice));
  }

  public void testBasicRatchet()
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
  {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage sentAliceDistributionMessage =
        aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);
    SenderKeyDistributionMessage receivedAliceDistributionMessage =
        new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

    bobSessionBuilder.process(SENDER_ADDRESS, receivedAliceDistributionMessage);

    byte[] ciphertextFromAlice  = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "smert ze smert".getBytes()).serialize();
    byte[] ciphertextFromAlice2 = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "smert ze smert2".getBytes()).serialize();
    byte[] ciphertextFromAlice3 = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "smert ze smert3".getBytes()).serialize();

    byte[] plaintextFromAlice   = bobGroupCipher.decrypt(ciphertextFromAlice);

    try {
      bobGroupCipher.decrypt(ciphertextFromAlice);
      throw new AssertionError("Should have ratcheted forward!");
    } catch (DuplicateMessageException dme) {
      // good
    }

    byte[] plaintextFromAlice2  = bobGroupCipher.decrypt(ciphertextFromAlice2);
    byte[] plaintextFromAlice3  = bobGroupCipher.decrypt(ciphertextFromAlice3);

    assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
    assertTrue(new String(plaintextFromAlice2).equals("smert ze smert2"));
    assertTrue(new String(plaintextFromAlice3).equals("smert ze smert3"));
  }

  public void testLateJoin() throws NoSessionException, InvalidMessageException, LegacyMessageException, DuplicateMessageException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);
    // Send off to some people.

    for (int i=0;i<100;i++) {
      aliceGroupCipher.encrypt(DISTRIBUTION_ID, "up the punks up the punks up the punks".getBytes());
    }

    // Now Bob Joins.
    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
    GroupCipher         bobGroupCipher    = new GroupCipher(bobStore, SENDER_ADDRESS);


    SenderKeyDistributionMessage distributionMessageToBob = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);
    bobSessionBuilder.process(SENDER_ADDRESS, new SenderKeyDistributionMessage(distributionMessageToBob.serialize()));

    CiphertextMessage ciphertext = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "welcome to the group".getBytes());
    byte[] plaintext  = bobGroupCipher.decrypt(ciphertext.serialize());

    assertEquals(new String(plaintext), "welcome to the group");
  }


  public void testOutOfOrder()
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
  {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage aliceDistributionMessage =
        aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);

    bobSessionBuilder.process(SENDER_ADDRESS, aliceDistributionMessage);

    ArrayList<byte[]> ciphertexts = new ArrayList<>(100);

    for (int i=0;i<100;i++) {
      ciphertexts.add(aliceGroupCipher.encrypt(DISTRIBUTION_ID, "up the punks".getBytes()).serialize());
    }

    while (ciphertexts.size() > 0) {
      int    index      = randomInt() % ciphertexts.size();
      byte[] ciphertext = ciphertexts.remove(index);
      byte[] plaintext  = bobGroupCipher.decrypt(ciphertext);

      assertTrue(new String(plaintext).equals("up the punks"));
    }
  }

  public void testEncryptNoSession() {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, new SignalProtocolAddress("+10002223333", 1));
    try {
      aliceGroupCipher.encrypt(DISTRIBUTION_ID, "up the punks".getBytes());
      throw new AssertionError("Should have failed!");
    } catch (NoSessionException nse) {
      // good
    }
  }


  public void testTooFarInFuture() throws DuplicateMessageException, InvalidMessageException, LegacyMessageException, NoSessionException {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);

    bobSessionBuilder.process(SENDER_ADDRESS, aliceDistributionMessage);

    for (int i=0;i<25001;i++) {
      aliceGroupCipher.encrypt(DISTRIBUTION_ID, "up the punks".getBytes());
    }

    byte[] tooFarCiphertext = aliceGroupCipher.encrypt(DISTRIBUTION_ID, "notta gonna worka".getBytes()).serialize();
    try {
      bobGroupCipher.decrypt(tooFarCiphertext);
      throw new AssertionError("Should have failed!");
    } catch (InvalidMessageException e) {
      // good
    }
  }

  public void testMessageKeyLimit() throws Exception {
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_ADDRESS);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, SENDER_ADDRESS);

    SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(SENDER_ADDRESS, DISTRIBUTION_ID);

    bobSessionBuilder.process(SENDER_ADDRESS, aliceDistributionMessage);

    List<byte[]> inflight = new LinkedList<>();

    for (int i=0;i<2010;i++) {
      inflight.add(aliceGroupCipher.encrypt(DISTRIBUTION_ID, "up the punks".getBytes()).serialize());
    }

    bobGroupCipher.decrypt(inflight.get(1000));
    bobGroupCipher.decrypt(inflight.get(inflight.size()-1));

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
