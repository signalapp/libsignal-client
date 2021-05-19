//
// Copyright (C) 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

package org.signal.client.internal;

import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.logging.SignalProtocolLogger;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.UUID;

public final class Native {
  private static void copyToTempFileAndLoad(InputStream in, String extension) throws IOException {
    File tempFile = Files.createTempFile("resource", extension).toFile();
    tempFile.deleteOnExit();

    try (OutputStream out = new FileOutputStream(tempFile)) {
      byte[] buffer = new byte[4096];
      int read;

      while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
      }
    }
    System.load(tempFile.getAbsolutePath());
  }

  /*
  If a .so and/or .dylib is embedded within this jar as a resource file, attempt
  to copy it to a temporary file and then load it. This allows the jar to be
  used even without a libsignal_jni shared library existing on the filesystem.
  */
  private static void loadLibrary() {
    try {
      String  osName    = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT);
      boolean isMacOs   = osName.startsWith("mac os");
      String  extension = isMacOs ? ".dylib" : ".so";

      try (InputStream in = Native.class.getResourceAsStream("/libsignal_jni" + extension)) {
        if (in != null) {
          copyToTempFileAndLoad(in, extension);
        } else {
          System.loadLibrary("signal_jni");
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static {
    loadLibrary();
    Logger_Initialize(SignalProtocolLogger.INFO, Log.class);
  }

  private Native() {}

  public static native void Aes256Ctr32_Destroy(long handle);
  public static native long Aes256Ctr32_New(byte[] key, byte[] nonce, int initialCtr);
  public static native void Aes256Ctr32_Process(long ctr, byte[] data, int offset, int length);

  public static native void Aes256GcmDecryption_Destroy(long handle);
  public static native long Aes256GcmDecryption_New(byte[] key, byte[] nonce, byte[] associatedData);
  public static native void Aes256GcmDecryption_Update(long gcm, byte[] data, int offset, int length);
  public static native boolean Aes256GcmDecryption_VerifyTag(long gcm, byte[] tag);

  public static native byte[] Aes256GcmEncryption_ComputeTag(long gcm);
  public static native void Aes256GcmEncryption_Destroy(long handle);
  public static native long Aes256GcmEncryption_New(byte[] key, byte[] nonce, byte[] associatedData);
  public static native void Aes256GcmEncryption_Update(long gcm, byte[] data, int offset, int length);

  public static native byte[] Aes256GcmSiv_Decrypt(long aesGcmSiv, byte[] ctext, byte[] nonce, byte[] associatedData);
  public static native void Aes256GcmSiv_Destroy(long handle);
  public static native byte[] Aes256GcmSiv_Encrypt(long aesGcmSiv, byte[] ptext, byte[] nonce, byte[] associatedData);
  public static native long Aes256GcmSiv_New(byte[] key);

  public static native void CryptographicHash_Destroy(long handle);
  public static native byte[] CryptographicHash_Finalize(long hash);
  public static native long CryptographicHash_New(String algo);
  public static native void CryptographicHash_Update(long hash, byte[] input);
  public static native void CryptographicHash_UpdateWithOffset(long hash, byte[] input, int offset, int len);

  public static native void CryptographicMac_Destroy(long handle);
  public static native byte[] CryptographicMac_Finalize(long mac);
  public static native long CryptographicMac_New(String algo, byte[] key);
  public static native void CryptographicMac_Update(long mac, byte[] input);
  public static native void CryptographicMac_UpdateWithOffset(long mac, byte[] input, int offset, int len);

  public static native byte[] DeviceTransfer_GenerateCertificate(byte[] privateKey, String name, int daysToExpire);
  public static native byte[] DeviceTransfer_GeneratePrivateKey();

  public static native byte[] ECPrivateKey_Agree(long privateKey, long publicKey);
  public static native long ECPrivateKey_Deserialize(byte[] data);
  public static native void ECPrivateKey_Destroy(long handle);
  public static native long ECPrivateKey_Generate();
  public static native long ECPrivateKey_GetPublicKey(long k);
  public static native byte[] ECPrivateKey_Serialize(long obj);
  public static native byte[] ECPrivateKey_Sign(long key, byte[] message);

  public static native int ECPublicKey_Compare(long key1, long key2);
  public static native long ECPublicKey_Deserialize(byte[] data, int offset);
  public static native void ECPublicKey_Destroy(long handle);
  public static native byte[] ECPublicKey_GetPublicKeyBytes(long obj);
  public static native byte[] ECPublicKey_Serialize(long obj);
  public static native boolean ECPublicKey_Verify(long key, byte[] message, byte[] signature);

  public static native byte[] GroupCipher_DecryptMessage(long sender, byte[] message, SenderKeyStore store, Object ctx);
  public static native CiphertextMessage GroupCipher_EncryptMessage(long sender, UUID distributionId, byte[] message, SenderKeyStore store, Object ctx);

  public static native long GroupSessionBuilder_CreateSenderKeyDistributionMessage(long sender, UUID distributionId, SenderKeyStore store, Object ctx);
  public static native void GroupSessionBuilder_ProcessSenderKeyDistributionMessage(long sender, long senderKeyDistributionMessage, SenderKeyStore store, Object ctx);

  public static native byte[] HKDF_DeriveSecrets(int outputLength, int version, byte[] ikm, byte[] label, byte[] salt);

  public static native long[] IdentityKeyPair_Deserialize(byte[] data);
  public static native byte[] IdentityKeyPair_Serialize(long publicKey, long privateKey);

  public static native void Logger_Initialize(int maxLevel, Class loggerClass);
  public static native void Logger_SetMaxLevel(int maxLevel);

  public static native void NumericFingerprintGenerator_Destroy(long handle);
  public static native String NumericFingerprintGenerator_GetDisplayString(long obj);
  public static native byte[] NumericFingerprintGenerator_GetScannableEncoding(long obj);
  public static native long NumericFingerprintGenerator_New(int iterations, int version, byte[] localIdentifier, byte[] localKey, byte[] remoteIdentifier, byte[] remoteKey);

  public static native void PreKeyBundle_Destroy(long handle);
  public static native int PreKeyBundle_GetDeviceId(long obj);
  public static native long PreKeyBundle_GetIdentityKey(long p);
  public static native int PreKeyBundle_GetPreKeyId(long obj);
  public static native long PreKeyBundle_GetPreKeyPublic(long obj);
  public static native int PreKeyBundle_GetRegistrationId(long obj);
  public static native int PreKeyBundle_GetSignedPreKeyId(long obj);
  public static native long PreKeyBundle_GetSignedPreKeyPublic(long obj);
  public static native byte[] PreKeyBundle_GetSignedPreKeySignature(long obj);
  public static native long PreKeyBundle_New(int registrationId, int deviceId, int prekeyId, long prekey, int signedPrekeyId, long signedPrekey, byte[] signedPrekeySignature, long identityKey);

  public static native long PreKeyRecord_Deserialize(byte[] data);
  public static native void PreKeyRecord_Destroy(long handle);
  public static native int PreKeyRecord_GetId(long obj);
  public static native long PreKeyRecord_GetPrivateKey(long obj);
  public static native long PreKeyRecord_GetPublicKey(long obj);
  public static native byte[] PreKeyRecord_GetSerialized(long obj);
  public static native long PreKeyRecord_New(int id, long pubKey, long privKey);

  public static native long PreKeySignalMessage_Deserialize(byte[] data);
  public static native void PreKeySignalMessage_Destroy(long handle);
  public static native byte[] PreKeySignalMessage_GetBaseKey(long m);
  public static native byte[] PreKeySignalMessage_GetIdentityKey(long m);
  public static native int PreKeySignalMessage_GetPreKeyId(long obj);
  public static native int PreKeySignalMessage_GetRegistrationId(long obj);
  public static native byte[] PreKeySignalMessage_GetSerialized(long obj);
  public static native byte[] PreKeySignalMessage_GetSignalMessage(long m);
  public static native int PreKeySignalMessage_GetSignedPreKeyId(long obj);
  public static native int PreKeySignalMessage_GetVersion(long obj);
  public static native long PreKeySignalMessage_New(int messageVersion, int registrationId, int preKeyId, int signedPreKeyId, long baseKey, long identityKey, long signalMessage);

  public static native void ProtocolAddress_Destroy(long handle);
  public static native int ProtocolAddress_DeviceId(long obj);
  public static native String ProtocolAddress_Name(long obj);
  public static native long ProtocolAddress_New(String name, int deviceId);

  public static native boolean ScannableFingerprint_Compare(byte[] fprint1, byte[] fprint2);

  public static native long SealedSessionCipher_DecryptToUsmc(byte[] ctext, IdentityKeyStore identityStore, Object ctx);
  public static native byte[] SealedSessionCipher_Encrypt(long destination, long content, IdentityKeyStore identityKeyStore, Object ctx);
  public static native byte[] SealedSessionCipher_MultiRecipientEncrypt(long[] recipients, long content, IdentityKeyStore identityKeyStore, Object ctx);
  public static native byte[] SealedSessionCipher_MultiRecipientMessageForSingleRecipient(byte[] encodedMultiRecipientMessage);

  public static native long SenderCertificate_Deserialize(byte[] data);
  public static native void SenderCertificate_Destroy(long handle);
  public static native byte[] SenderCertificate_GetCertificate(long obj);
  public static native int SenderCertificate_GetDeviceId(long obj);
  public static native long SenderCertificate_GetExpiration(long obj);
  public static native long SenderCertificate_GetKey(long obj);
  public static native String SenderCertificate_GetSenderE164(long obj);
  public static native String SenderCertificate_GetSenderUuid(long obj);
  public static native byte[] SenderCertificate_GetSerialized(long obj);
  public static native long SenderCertificate_GetServerCertificate(long cert);
  public static native byte[] SenderCertificate_GetSignature(long obj);
  public static native long SenderCertificate_New(String senderUuid, String senderE164, int senderDeviceId, long senderKey, long expiration, long signerCert, long signerKey);
  public static native boolean SenderCertificate_Validate(long cert, long key, long time);

  public static native long SenderKeyDistributionMessage_Deserialize(byte[] data);
  public static native void SenderKeyDistributionMessage_Destroy(long handle);
  public static native int SenderKeyDistributionMessage_GetChainId(long obj);
  public static native byte[] SenderKeyDistributionMessage_GetChainKey(long obj);
  public static native UUID SenderKeyDistributionMessage_GetDistributionId(long obj);
  public static native int SenderKeyDistributionMessage_GetIteration(long obj);
  public static native byte[] SenderKeyDistributionMessage_GetSerialized(long obj);
  public static native byte[] SenderKeyDistributionMessage_GetSignatureKey(long m);
  public static native long SenderKeyDistributionMessage_New(int messageVersion, UUID distributionId, int chainId, int iteration, byte[] chainkey, long pk);

  public static native long SenderKeyMessage_Deserialize(byte[] data);
  public static native void SenderKeyMessage_Destroy(long handle);
  public static native int SenderKeyMessage_GetChainId(long obj);
  public static native byte[] SenderKeyMessage_GetCipherText(long obj);
  public static native UUID SenderKeyMessage_GetDistributionId(long obj);
  public static native int SenderKeyMessage_GetIteration(long obj);
  public static native byte[] SenderKeyMessage_GetSerialized(long obj);
  public static native long SenderKeyMessage_New(int messageVersion, UUID distributionId, int chainId, int iteration, byte[] ciphertext, long pk);
  public static native boolean SenderKeyMessage_VerifySignature(long skm, long pubkey);

  public static native long SenderKeyRecord_Deserialize(byte[] data);
  public static native void SenderKeyRecord_Destroy(long handle);
  public static native byte[] SenderKeyRecord_GetSerialized(long obj);
  public static native long SenderKeyRecord_New();

  public static native long ServerCertificate_Deserialize(byte[] data);
  public static native void ServerCertificate_Destroy(long handle);
  public static native byte[] ServerCertificate_GetCertificate(long obj);
  public static native long ServerCertificate_GetKey(long obj);
  public static native int ServerCertificate_GetKeyId(long obj);
  public static native byte[] ServerCertificate_GetSerialized(long obj);
  public static native byte[] ServerCertificate_GetSignature(long obj);
  public static native long ServerCertificate_New(int keyId, long serverKey, long trustRoot);

  public static native void SessionBuilder_ProcessPreKeyBundle(long bundle, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, Object ctx);

  public static native byte[] SessionCipher_DecryptPreKeySignalMessage(long message, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, PreKeyStore prekeyStore, SignedPreKeyStore signedPrekeyStore, Object ctx);
  public static native byte[] SessionCipher_DecryptSignalMessage(long message, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, Object ctx);
  public static native CiphertextMessage SessionCipher_EncryptMessage(byte[] ptext, long protocolAddress, SessionStore sessionStore, IdentityKeyStore identityKeyStore, Object ctx);

  public static native void SessionRecord_ArchiveCurrentState(long sessionRecord);
  public static native long SessionRecord_Deserialize(byte[] data);
  public static native void SessionRecord_Destroy(long handle);
  public static native long SessionRecord_FromSingleSessionState(byte[] sessionState);
  public static native byte[] SessionRecord_GetAliceBaseKey(long obj);
  public static native byte[] SessionRecord_GetLocalIdentityKeyPublic(long obj);
  public static native int SessionRecord_GetLocalRegistrationId(long obj);
  public static native byte[] SessionRecord_GetReceiverChainKeyValue(long sessionState, long key);
  public static native byte[] SessionRecord_GetRemoteIdentityKeyPublic(long obj);
  public static native int SessionRecord_GetRemoteRegistrationId(long obj);
  public static native byte[] SessionRecord_GetSenderChainKeyValue(long obj);
  public static native int SessionRecord_GetSessionVersion(long s);
  public static native boolean SessionRecord_HasSenderChain(long obj);
  public static native long SessionRecord_InitializeAliceSession(long identityKeyPrivate, long identityKeyPublic, long basePrivate, long basePublic, long theirIdentityKey, long theirSignedPrekey, long theirRatchetKey);
  public static native long SessionRecord_InitializeBobSession(long identityKeyPrivate, long identityKeyPublic, long signedPrekeyPrivate, long signedPrekeyPublic, long ephPrivate, long ephPublic, long theirIdentityKey, long theirBaseKey);
  public static native long SessionRecord_NewFresh();
  public static native byte[] SessionRecord_Serialize(long obj);

  public static native long SignalMessage_Deserialize(byte[] data);
  public static native void SignalMessage_Destroy(long handle);
  public static native byte[] SignalMessage_GetBody(long obj);
  public static native int SignalMessage_GetCounter(long obj);
  public static native int SignalMessage_GetMessageVersion(long obj);
  public static native byte[] SignalMessage_GetSenderRatchetKey(long m);
  public static native byte[] SignalMessage_GetSerialized(long obj);
  public static native long SignalMessage_New(int messageVersion, byte[] macKey, long senderRatchetKey, int counter, int previousCounter, byte[] ciphertext, long senderIdentityKey, long receiverIdentityKey);
  public static native boolean SignalMessage_VerifyMac(long msg, long senderIdentityKey, long receiverIdentityKey, byte[] macKey);

  public static native long SignedPreKeyRecord_Deserialize(byte[] data);
  public static native void SignedPreKeyRecord_Destroy(long handle);
  public static native int SignedPreKeyRecord_GetId(long obj);
  public static native long SignedPreKeyRecord_GetPrivateKey(long obj);
  public static native long SignedPreKeyRecord_GetPublicKey(long obj);
  public static native byte[] SignedPreKeyRecord_GetSerialized(long obj);
  public static native byte[] SignedPreKeyRecord_GetSignature(long obj);
  public static native long SignedPreKeyRecord_GetTimestamp(long obj);
  public static native long SignedPreKeyRecord_New(int id, long timestamp, long pubKey, long privKey, byte[] signature);

  public static native long UnidentifiedSenderMessageContent_Deserialize(byte[] data);
  public static native void UnidentifiedSenderMessageContent_Destroy(long handle);
  public static native int UnidentifiedSenderMessageContent_GetContentHint(long m);
  public static native byte[] UnidentifiedSenderMessageContent_GetContents(long obj);
  public static native byte[] UnidentifiedSenderMessageContent_GetGroupId(long m);
  public static native int UnidentifiedSenderMessageContent_GetMsgType(long m);
  public static native long UnidentifiedSenderMessageContent_GetSenderCert(long m);
  public static native byte[] UnidentifiedSenderMessageContent_GetSerialized(long obj);
  public static native long UnidentifiedSenderMessageContent_New(CiphertextMessage message, long sender, int contentHint, byte[] groupId);
}
