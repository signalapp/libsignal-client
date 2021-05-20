//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

type Uuid = Buffer;

export abstract class IdentityKeyStore {
  _getIdentityKey(): Promise<PrivateKey>;
  _getLocalRegistrationId(): Promise<number>;
  _saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<boolean>;
  _isTrustedIdentity(name: ProtocolAddress, key: PublicKey, sending: boolean): Promise<boolean>;
  _getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}

export abstract class SessionStore {
  _saveSession(addr: ProtocolAddress, record: SessionRecord): Promise<void>;
  _getSession(addr: ProtocolAddress): Promise<SessionRecord | null>;
}

export abstract class PreKeyStore {
  _savePreKey(preKeyId: number, record: PreKeyRecord): Promise<void>;
  _getPreKey(preKeyId: number): Promise<PreKeyRecord>;
  _removePreKey(preKeyId: number): Promise<void>;
}

export abstract class SignedPreKeyStore {
  _saveSignedPreKey(signedPreKeyId: number, record: SignedPreKeyRecord): Promise<void>;
  _getSignedPreKey(signedPreKeyId: number): Promise<SignedPreKeyRecord>;
}

export abstract class SenderKeyStore {
  _saveSenderKey(sender: ProtocolAddress, distributionId: Uuid, record: SenderKeyRecord): Promise<void>;
  _getSenderKey(sender: ProtocolAddress, distributionId: Uuid): Promise<SenderKeyRecord | null>;
}

interface Wrapper<T> {
  readonly _nativeHandle: T
}

export function registerErrors(errorsModule: Record<string, unknown>): void;

export const enum LogLevel { Error = 1, Warn, Info, Debug, Trace }
export function Aes256GcmSiv_Decrypt(aesGcmSiv: Wrapper<Aes256GcmSiv>, ctext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_Encrypt(aesGcmSiv: Wrapper<Aes256GcmSiv>, ptext: Buffer, nonce: Buffer, associatedData: Buffer): Buffer;
export function Aes256GcmSiv_New(key: Buffer): Aes256GcmSiv;
export function CiphertextMessage_Serialize(obj: Wrapper<CiphertextMessage>): Buffer;
export function CiphertextMessage_Type(msg: Wrapper<CiphertextMessage>): number;
export function Fingerprint_DisplayString(obj: Wrapper<Fingerprint>): string;
export function Fingerprint_New(iterations: number, version: number, localIdentifier: Buffer, localKey: Wrapper<PublicKey>, remoteIdentifier: Buffer, remoteKey: Wrapper<PublicKey>): Fingerprint;
export function Fingerprint_ScannableEncoding(obj: Wrapper<Fingerprint>): Buffer;
export function GroupCipher_DecryptMessage(sender: Wrapper<ProtocolAddress>, message: Buffer, store: SenderKeyStore, ctx: null): Promise<Buffer>;
export function GroupCipher_EncryptMessage(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, message: Buffer, store: SenderKeyStore, ctx: null): Promise<CiphertextMessage>;
export function HKDF_DeriveSecrets(outputLength: number, version: number, ikm: Buffer, label: Buffer | null, salt: Buffer | null): Buffer;
export function IdentityKeyPair_Serialize(publicKey: Wrapper<PublicKey>, privateKey: Wrapper<PrivateKey>): Buffer;
export function PreKeyBundle_GetDeviceId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetIdentityKey(p: Wrapper<PreKeyBundle>): PublicKey;
export function PreKeyBundle_GetPreKeyId(obj: Wrapper<PreKeyBundle>): number | null;
export function PreKeyBundle_GetPreKeyPublic(obj: Wrapper<PreKeyBundle>): PublicKey | null;
export function PreKeyBundle_GetRegistrationId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetSignedPreKeyId(obj: Wrapper<PreKeyBundle>): number;
export function PreKeyBundle_GetSignedPreKeyPublic(obj: Wrapper<PreKeyBundle>): PublicKey;
export function PreKeyBundle_GetSignedPreKeySignature(obj: Wrapper<PreKeyBundle>): Buffer;
export function PreKeyBundle_New(registrationId: number, deviceId: number, prekeyId: number | null, prekey: Wrapper<PublicKey> | null, signedPrekeyId: number, signedPrekey: Wrapper<PublicKey>, signedPrekeySignature: Buffer, identityKey: Wrapper<PublicKey>): PreKeyBundle;
export function PreKeyRecord_Deserialize(buffer: Buffer): PreKeyRecord;
export function PreKeyRecord_GetId(obj: Wrapper<PreKeyRecord>): number;
export function PreKeyRecord_GetPrivateKey(obj: Wrapper<PreKeyRecord>): PrivateKey;
export function PreKeyRecord_GetPublicKey(obj: Wrapper<PreKeyRecord>): PublicKey;
export function PreKeyRecord_New(id: number, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>): PreKeyRecord;
export function PreKeyRecord_Serialize(obj: Wrapper<PreKeyRecord>): Buffer;
export function PreKeySignalMessage_Deserialize(buffer: Buffer): PreKeySignalMessage;
export function PreKeySignalMessage_GetPreKeyId(obj: Wrapper<PreKeySignalMessage>): number | null;
export function PreKeySignalMessage_GetRegistrationId(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_GetSignedPreKeyId(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_GetVersion(obj: Wrapper<PreKeySignalMessage>): number;
export function PreKeySignalMessage_New(messageVersion: number, registrationId: number, preKeyId: number | null, signedPreKeyId: number, baseKey: Wrapper<PublicKey>, identityKey: Wrapper<PublicKey>, signalMessage: Wrapper<SignalMessage>): PreKeySignalMessage;
export function PreKeySignalMessage_Serialize(obj: Wrapper<PreKeySignalMessage>): Buffer;
export function PrivateKey_Agree(privateKey: Wrapper<PrivateKey>, publicKey: Wrapper<PublicKey>): Buffer;
export function PrivateKey_Deserialize(buffer: Buffer): PrivateKey;
export function PrivateKey_Generate(): PrivateKey;
export function PrivateKey_GetPublicKey(k: Wrapper<PrivateKey>): PublicKey;
export function PrivateKey_Serialize(obj: Wrapper<PrivateKey>): Buffer;
export function PrivateKey_Sign(key: Wrapper<PrivateKey>, message: Buffer): Buffer;
export function ProtocolAddress_DeviceId(obj: Wrapper<ProtocolAddress>): number;
export function ProtocolAddress_Name(obj: Wrapper<ProtocolAddress>): string;
export function ProtocolAddress_New(name: string, deviceId: number): ProtocolAddress;
export function PublicKey_Compare(key1: Wrapper<PublicKey>, key2: Wrapper<PublicKey>): number;
export function PublicKey_Deserialize(buffer: Buffer): PublicKey;
export function PublicKey_GetPublicKeyBytes(obj: Wrapper<PublicKey>): Buffer;
export function PublicKey_Serialize(obj: Wrapper<PublicKey>): Buffer;
export function PublicKey_Verify(key: Wrapper<PublicKey>, message: Buffer, signature: Buffer): boolean;
export function ScannableFingerprint_Compare(fprint1: Buffer, fprint2: Buffer): boolean;
export function SealedSenderDecryptionResult_GetDeviceId(obj: Wrapper<SealedSenderDecryptionResult>): number;
export function SealedSenderDecryptionResult_GetSenderE164(obj: Wrapper<SealedSenderDecryptionResult>): string | null;
export function SealedSenderDecryptionResult_GetSenderUuid(obj: Wrapper<SealedSenderDecryptionResult>): string;
export function SealedSenderDecryptionResult_Message(obj: Wrapper<SealedSenderDecryptionResult>): Buffer;
export function SealedSender_DecryptMessage(message: Buffer, trustRoot: Wrapper<PublicKey>, timestamp: number, localE164: string | null, localUuid: string, localDeviceId: number, sessionStore: SessionStore, identityStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore): Promise<SealedSenderDecryptionResult>;
export function SealedSender_DecryptToUsmc(ctext: Buffer, identityPrivate: Wrapper<PrivateKey>, identityPublic: Wrapper<PublicKey>): UnidentifiedSenderMessageContent;
export function SealedSender_Encrypt(destination: Wrapper<ProtocolAddress>, content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore, ctx: null): Promise<Buffer>;
export function SealedSender_MultiRecipientEncrypt(recipients: Wrapper<ProtocolAddress>[], content: Wrapper<UnidentifiedSenderMessageContent>, identityKeyStore: IdentityKeyStore, ctx: null): Promise<Buffer>;
export function SealedSender_MultiRecipientMessageForSingleRecipient(encodedMultiRecipientMessage: Buffer): Buffer;
export function SenderCertificate_Deserialize(buffer: Buffer): SenderCertificate;
export function SenderCertificate_GetCertificate(obj: Wrapper<SenderCertificate>): Buffer;
export function SenderCertificate_GetDeviceId(obj: Wrapper<SenderCertificate>): number;
export function SenderCertificate_GetExpiration(obj: Wrapper<SenderCertificate>): number;
export function SenderCertificate_GetKey(obj: Wrapper<SenderCertificate>): PublicKey;
export function SenderCertificate_GetSenderE164(obj: Wrapper<SenderCertificate>): string | null;
export function SenderCertificate_GetSenderUuid(obj: Wrapper<SenderCertificate>): string;
export function SenderCertificate_GetSerialized(obj: Wrapper<SenderCertificate>): Buffer;
export function SenderCertificate_GetServerCertificate(cert: Wrapper<SenderCertificate>): ServerCertificate;
export function SenderCertificate_GetSignature(obj: Wrapper<SenderCertificate>): Buffer;
export function SenderCertificate_New(senderUuid: string, senderE164: string | null, senderDeviceId: number, senderKey: Wrapper<PublicKey>, expiration: number, signerCert: Wrapper<ServerCertificate>, signerKey: Wrapper<PrivateKey>): SenderCertificate;
export function SenderCertificate_Validate(cert: Wrapper<SenderCertificate>, key: Wrapper<PublicKey>, time: number): boolean;
export function SenderKeyDistributionMessage_Create(sender: Wrapper<ProtocolAddress>, distributionId: Uuid, store: SenderKeyStore, ctx: null): Promise<SenderKeyDistributionMessage>;
export function SenderKeyDistributionMessage_Deserialize(buffer: Buffer): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_GetChainId(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_GetChainKey(obj: Wrapper<SenderKeyDistributionMessage>): Buffer;
export function SenderKeyDistributionMessage_GetDistributionId(obj: Wrapper<SenderKeyDistributionMessage>): Uuid;
export function SenderKeyDistributionMessage_GetIteration(obj: Wrapper<SenderKeyDistributionMessage>): number;
export function SenderKeyDistributionMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, chainkey: Buffer, pk: Wrapper<PublicKey>): SenderKeyDistributionMessage;
export function SenderKeyDistributionMessage_Process(sender: Wrapper<ProtocolAddress>, senderKeyDistributionMessage: Wrapper<SenderKeyDistributionMessage>, store: SenderKeyStore, ctx: null): Promise<void>;
export function SenderKeyDistributionMessage_Serialize(obj: Wrapper<SenderKeyDistributionMessage>): Buffer;
export function SenderKeyMessage_Deserialize(buffer: Buffer): SenderKeyMessage;
export function SenderKeyMessage_GetChainId(obj: Wrapper<SenderKeyMessage>): number;
export function SenderKeyMessage_GetCipherText(obj: Wrapper<SenderKeyMessage>): Buffer;
export function SenderKeyMessage_GetDistributionId(obj: Wrapper<SenderKeyMessage>): Uuid;
export function SenderKeyMessage_GetIteration(obj: Wrapper<SenderKeyMessage>): number;
export function SenderKeyMessage_New(messageVersion: number, distributionId: Uuid, chainId: number, iteration: number, ciphertext: Buffer, pk: Wrapper<PrivateKey>): SenderKeyMessage;
export function SenderKeyMessage_Serialize(obj: Wrapper<SenderKeyMessage>): Buffer;
export function SenderKeyMessage_VerifySignature(skm: Wrapper<SenderKeyMessage>, pubkey: Wrapper<PublicKey>): boolean;
export function SenderKeyRecord_Deserialize(buffer: Buffer): SenderKeyRecord;
export function SenderKeyRecord_New(): SenderKeyRecord;
export function SenderKeyRecord_Serialize(obj: Wrapper<SenderKeyRecord>): Buffer;
export function ServerCertificate_Deserialize(buffer: Buffer): ServerCertificate;
export function ServerCertificate_GetCertificate(obj: Wrapper<ServerCertificate>): Buffer;
export function ServerCertificate_GetKey(obj: Wrapper<ServerCertificate>): PublicKey;
export function ServerCertificate_GetKeyId(obj: Wrapper<ServerCertificate>): number;
export function ServerCertificate_GetSerialized(obj: Wrapper<ServerCertificate>): Buffer;
export function ServerCertificate_GetSignature(obj: Wrapper<ServerCertificate>): Buffer;
export function ServerCertificate_New(keyId: number, serverKey: Wrapper<PublicKey>, trustRoot: Wrapper<PrivateKey>): ServerCertificate;
export function SessionBuilder_ProcessPreKeyBundle(bundle: Wrapper<PreKeyBundle>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, ctx: null): Promise<void>;
export function SessionCipher_DecryptPreKeySignalMessage(message: Wrapper<PreKeySignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, prekeyStore: PreKeyStore, signedPrekeyStore: SignedPreKeyStore, ctx: null): Promise<Buffer>;
export function SessionCipher_DecryptSignalMessage(message: Wrapper<SignalMessage>, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, ctx: null): Promise<Buffer>;
export function SessionCipher_EncryptMessage(ptext: Buffer, protocolAddress: Wrapper<ProtocolAddress>, sessionStore: SessionStore, identityKeyStore: IdentityKeyStore, ctx: null): Promise<CiphertextMessage>;
export function SessionRecord_ArchiveCurrentState(sessionRecord: Wrapper<SessionRecord>): void;
export function SessionRecord_Deserialize(buffer: Buffer): SessionRecord;
export function SessionRecord_GetLocalRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_GetRemoteRegistrationId(obj: Wrapper<SessionRecord>): number;
export function SessionRecord_HasCurrentState(obj: Wrapper<SessionRecord>): boolean;
export function SessionRecord_Serialize(obj: Wrapper<SessionRecord>): Buffer;
export function SignalMessage_Deserialize(buffer: Buffer): SignalMessage;
export function SignalMessage_GetBody(obj: Wrapper<SignalMessage>): Buffer;
export function SignalMessage_GetCounter(obj: Wrapper<SignalMessage>): number;
export function SignalMessage_GetMessageVersion(obj: Wrapper<SignalMessage>): number;
export function SignalMessage_GetSerialized(obj: Wrapper<SignalMessage>): Buffer;
export function SignalMessage_New(messageVersion: number, macKey: Buffer, senderRatchetKey: Wrapper<PublicKey>, counter: number, previousCounter: number, ciphertext: Buffer, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>): SignalMessage;
export function SignalMessage_VerifyMac(msg: Wrapper<SignalMessage>, senderIdentityKey: Wrapper<PublicKey>, receiverIdentityKey: Wrapper<PublicKey>, macKey: Buffer): boolean;
export function SignedPreKeyRecord_Deserialize(buffer: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_GetId(obj: Wrapper<SignedPreKeyRecord>): number;
export function SignedPreKeyRecord_GetPrivateKey(obj: Wrapper<SignedPreKeyRecord>): PrivateKey;
export function SignedPreKeyRecord_GetPublicKey(obj: Wrapper<SignedPreKeyRecord>): PublicKey;
export function SignedPreKeyRecord_GetSignature(obj: Wrapper<SignedPreKeyRecord>): Buffer;
export function SignedPreKeyRecord_GetTimestamp(obj: Wrapper<SignedPreKeyRecord>): number;
export function SignedPreKeyRecord_New(id: number, timestamp: number, pubKey: Wrapper<PublicKey>, privKey: Wrapper<PrivateKey>, signature: Buffer): SignedPreKeyRecord;
export function SignedPreKeyRecord_Serialize(obj: Wrapper<SignedPreKeyRecord>): Buffer;
export function UnidentifiedSenderMessageContent_Deserialize(buffer: Buffer): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_GetContentHint(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetContents(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function UnidentifiedSenderMessageContent_GetGroupId(m: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function UnidentifiedSenderMessageContent_GetMsgType(m: Wrapper<UnidentifiedSenderMessageContent>): number;
export function UnidentifiedSenderMessageContent_GetSenderCert(m: Wrapper<UnidentifiedSenderMessageContent>): SenderCertificate;
export function UnidentifiedSenderMessageContent_New(message: Wrapper<CiphertextMessage>, sender: Wrapper<SenderCertificate>, contentHint: number, groupId: Buffer | null): UnidentifiedSenderMessageContent;
export function UnidentifiedSenderMessageContent_Serialize(obj: Wrapper<UnidentifiedSenderMessageContent>): Buffer;
export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
interface Aes256GcmSiv { readonly __type: unique symbol; }
interface CiphertextMessage { readonly __type: unique symbol; }
interface Fingerprint { readonly __type: unique symbol; }
interface PreKeyBundle { readonly __type: unique symbol; }
interface PreKeyRecord { readonly __type: unique symbol; }
interface PreKeySignalMessage { readonly __type: unique symbol; }
interface PrivateKey { readonly __type: unique symbol; }
interface ProtocolAddress { readonly __type: unique symbol; }
interface PublicKey { readonly __type: unique symbol; }
interface SealedSenderDecryptionResult { readonly __type: unique symbol; }
interface SenderCertificate { readonly __type: unique symbol; }
interface SenderKeyDistributionMessage { readonly __type: unique symbol; }
interface SenderKeyMessage { readonly __type: unique symbol; }
interface SenderKeyRecord { readonly __type: unique symbol; }
interface ServerCertificate { readonly __type: unique symbol; }
interface SessionRecord { readonly __type: unique symbol; }
interface SignalMessage { readonly __type: unique symbol; }
interface SignedPreKeyRecord { readonly __type: unique symbol; }
interface UnidentifiedSenderMessageContent { readonly __type: unique symbol; }
