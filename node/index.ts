//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';

import * as Errors from './Errors';
export * from './Errors';

import * as Native from './Native';
// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
const NativeImpl = require('node-gyp-build')(
  __dirname + '/../..'
) as typeof Native;

export const { initLogger, LogLevel } = NativeImpl;

NativeImpl.registerErrors(Errors);

// These enums must be kept in sync with their Rust counterparts.

export const enum CiphertextMessageType {
  Whisper = 2,
  PreKey = 3,
  SenderKey = 7,
}

export const enum Direction {
  Sending,
  Receiving,
}

// This enum must be kept in sync with sealed_sender.proto.
export const enum ContentHint {
  Default = 0,
  Supplementary = 1,
  Retry = 2,
}

export type Uuid = string;

export class HKDF {
  private readonly version: number;

  private constructor(version: number) {
    this.version = version;
  }

  static new(version: number): HKDF {
    return new HKDF(version);
  }

  deriveSecrets(
    outputLength: number,
    keyMaterial: Buffer,
    label: Buffer,
    salt: Buffer | null
  ): Buffer {
    return NativeImpl.HKDF_DeriveSecrets(
      outputLength,
      this.version,
      keyMaterial,
      label,
      salt
    );
  }
}

export class ScannableFingerprint {
  private readonly scannable: Buffer;

  private constructor(scannable: Buffer) {
    this.scannable = scannable;
  }

  static _fromBuffer(scannable: Buffer): ScannableFingerprint {
    return new ScannableFingerprint(scannable);
  }

  compare(other: ScannableFingerprint): boolean {
    return NativeImpl.ScannableFingerprint_Compare(
      this.scannable,
      other.scannable
    );
  }

  toBuffer(): Buffer {
    return this.scannable;
  }
}

export class DisplayableFingerprint {
  private readonly display: string;

  private constructor(display: string) {
    this.display = display;
  }

  static _fromString(display: string): DisplayableFingerprint {
    return new DisplayableFingerprint(display);
  }

  toString(): string {
    return this.display;
  }
}

export class Fingerprint {
  readonly _nativeHandle: Native.Fingerprint;

  private constructor(nativeHandle: Native.Fingerprint) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    iterations: number,
    version: number,
    localIdentifier: Buffer,
    localKey: PublicKey,
    remoteIdentifier: Buffer,
    remoteKey: PublicKey
  ): Fingerprint {
    return new Fingerprint(
      NativeImpl.Fingerprint_New(
        iterations,
        version,
        localIdentifier,
        localKey,
        remoteIdentifier,
        remoteKey
      )
    );
  }

  public displayableFingerprint(): DisplayableFingerprint {
    return DisplayableFingerprint._fromString(
      NativeImpl.Fingerprint_DisplayString(this)
    );
  }

  public scannableFingerprint(): ScannableFingerprint {
    return ScannableFingerprint._fromBuffer(
      NativeImpl.Fingerprint_ScannableEncoding(this)
    );
  }
}

export class Aes256GcmSiv {
  readonly _nativeHandle: Native.Aes256GcmSiv;

  private constructor(key: Buffer) {
    this._nativeHandle = NativeImpl.Aes256GcmSiv_New(key);
  }

  static new(key: Buffer): Aes256GcmSiv {
    return new Aes256GcmSiv(key);
  }

  encrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer {
    return NativeImpl.Aes256GcmSiv_Encrypt(
      this,
      message,
      nonce,
      associated_data
    );
  }

  decrypt(message: Buffer, nonce: Buffer, associated_data: Buffer): Buffer {
    return NativeImpl.Aes256GcmSiv_Decrypt(
      this,
      message,
      nonce,
      associated_data
    );
  }
}

export class ProtocolAddress {
  readonly _nativeHandle: Native.ProtocolAddress;

  private constructor(handle: Native.ProtocolAddress) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress {
    return new ProtocolAddress(handle);
  }

  static new(name: string, deviceId: number): ProtocolAddress {
    return new ProtocolAddress(NativeImpl.ProtocolAddress_New(name, deviceId));
  }

  name(): string {
    return NativeImpl.ProtocolAddress_Name(this);
  }

  deviceId(): number {
    return NativeImpl.ProtocolAddress_DeviceId(this);
  }
}

export class PublicKey {
  readonly _nativeHandle: Native.PublicKey;

  private constructor(handle: Native.PublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Buffer): PublicKey {
    return new PublicKey(NativeImpl.PublicKey_Deserialize(buf));
  }

  /// Returns -1, 0, or 1
  compare(other: PublicKey): number {
    return NativeImpl.PublicKey_Compare(this, other);
  }

  serialize(): Buffer {
    return NativeImpl.PublicKey_Serialize(this);
  }

  getPublicKeyBytes(): Buffer {
    return NativeImpl.PublicKey_GetPublicKeyBytes(this);
  }

  verify(msg: Buffer, sig: Buffer): boolean {
    return NativeImpl.PublicKey_Verify(this, msg, sig);
  }
}

export class PrivateKey {
  readonly _nativeHandle: Native.PrivateKey;

  private constructor(handle: Native.PrivateKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PrivateKey): PrivateKey {
    return new PrivateKey(handle);
  }

  static generate(): PrivateKey {
    return new PrivateKey(NativeImpl.PrivateKey_Generate());
  }

  static deserialize(buf: Buffer): PrivateKey {
    return new PrivateKey(NativeImpl.PrivateKey_Deserialize(buf));
  }

  serialize(): Buffer {
    return NativeImpl.PrivateKey_Serialize(this);
  }

  sign(msg: Buffer): Buffer {
    return NativeImpl.PrivateKey_Sign(this, msg);
  }

  agree(other_key: PublicKey): Buffer {
    return NativeImpl.PrivateKey_Agree(this, other_key);
  }

  getPublicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.PrivateKey_GetPublicKey(this)
    );
  }
}

export class IdentityKeyPair {
  private readonly publicKey: PublicKey;
  private readonly privateKey: PrivateKey;

  constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  static new(publicKey: PublicKey, privateKey: PrivateKey): IdentityKeyPair {
    return new IdentityKeyPair(publicKey, privateKey);
  }

  serialize(): Buffer {
    return NativeImpl.IdentityKeyPair_Serialize(
      this.publicKey,
      this.privateKey
    );
  }
}

export class PreKeyBundle {
  readonly _nativeHandle: Native.PreKeyBundle;

  private constructor(handle: Native.PreKeyBundle) {
    this._nativeHandle = handle;
  }

  static new(
    registration_id: number,
    device_id: number,
    prekey_id: number | null,
    prekey: PublicKey | null,
    signed_prekey_id: number,
    signed_prekey: PublicKey,
    signed_prekey_signature: Buffer,
    identity_key: PublicKey
  ): PreKeyBundle {
    return new PreKeyBundle(
      NativeImpl.PreKeyBundle_New(
        registration_id,
        device_id,
        prekey_id,
        prekey != null ? prekey : null,
        //prekey?,
        signed_prekey_id,
        signed_prekey,
        signed_prekey_signature,
        identity_key
      )
    );
  }

  deviceId(): number {
    return NativeImpl.PreKeyBundle_GetDeviceId(this);
  }
  identityKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.PreKeyBundle_GetIdentityKey(this)
    );
  }
  preKeyId(): number | null {
    return NativeImpl.PreKeyBundle_GetPreKeyId(this);
  }
  preKeyPublic(): PublicKey | null {
    const handle = NativeImpl.PreKeyBundle_GetPreKeyPublic(this);

    if (handle == null) {
      return null;
    } else {
      return PublicKey._fromNativeHandle(handle);
    }
  }
  registrationId(): number {
    return NativeImpl.PreKeyBundle_GetRegistrationId(this);
  }
  signedPreKeyId(): number {
    return NativeImpl.PreKeyBundle_GetSignedPreKeyId(this);
  }
  signedPreKeyPublic(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.PreKeyBundle_GetSignedPreKeyPublic(this)
    );
  }
  signedPreKeySignature(): Buffer {
    return NativeImpl.PreKeyBundle_GetSignedPreKeySignature(this);
  }
}

export class PreKeyRecord {
  readonly _nativeHandle: Native.PreKeyRecord;

  private constructor(handle: Native.PreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(nativeHandle: Native.PreKeyRecord): PreKeyRecord {
    return new PreKeyRecord(nativeHandle);
  }

  static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord {
    return new PreKeyRecord(NativeImpl.PreKeyRecord_New(id, pubKey, privKey));
  }

  static deserialize(buffer: Buffer): PreKeyRecord {
    return new PreKeyRecord(NativeImpl.PreKeyRecord_Deserialize(buffer));
  }

  id(): number {
    return NativeImpl.PreKeyRecord_GetId(this);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(
      NativeImpl.PreKeyRecord_GetPrivateKey(this)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.PreKeyRecord_GetPublicKey(this)
    );
  }

  serialize(): Buffer {
    return NativeImpl.PreKeyRecord_Serialize(this);
  }
}

export class SignedPreKeyRecord {
  readonly _nativeHandle: Native.SignedPreKeyRecord;

  private constructor(handle: Native.SignedPreKeyRecord) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.SignedPreKeyRecord
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(nativeHandle);
  }

  static new(
    id: number,
    timestamp: number,
    pubKey: PublicKey,
    privKey: PrivateKey,
    signature: Buffer
  ): SignedPreKeyRecord {
    return new SignedPreKeyRecord(
      NativeImpl.SignedPreKeyRecord_New(
        id,
        timestamp,
        pubKey,
        privKey,
        signature
      )
    );
  }

  static deserialize(buffer: Buffer): SignedPreKeyRecord {
    return new SignedPreKeyRecord(
      NativeImpl.SignedPreKeyRecord_Deserialize(buffer)
    );
  }

  id(): number {
    return NativeImpl.SignedPreKeyRecord_GetId(this);
  }

  privateKey(): PrivateKey {
    return PrivateKey._fromNativeHandle(
      NativeImpl.SignedPreKeyRecord_GetPrivateKey(this)
    );
  }

  publicKey(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.SignedPreKeyRecord_GetPublicKey(this)
    );
  }

  serialize(): Buffer {
    return NativeImpl.SignedPreKeyRecord_Serialize(this);
  }

  signature(): Buffer {
    return NativeImpl.SignedPreKeyRecord_GetSignature(this);
  }

  timestamp(): number {
    return NativeImpl.SignedPreKeyRecord_GetTimestamp(this);
  }
}

export class SignalMessage {
  readonly _nativeHandle: Native.SignalMessage;

  private constructor(handle: Native.SignalMessage) {
    this._nativeHandle = handle;
  }

  static _new(
    messageVersion: number,
    macKey: Buffer,
    senderRatchetKey: PublicKey,
    counter: number,
    previousCounter: number,
    ciphertext: Buffer,
    senderIdentityKey: PublicKey,
    receiverIdentityKey: PublicKey
  ): SignalMessage {
    return new SignalMessage(
      NativeImpl.SignalMessage_New(
        messageVersion,
        macKey,
        senderRatchetKey,
        counter,
        previousCounter,
        ciphertext,
        senderIdentityKey,
        receiverIdentityKey
      )
    );
  }

  static deserialize(buffer: Buffer): SignalMessage {
    return new SignalMessage(NativeImpl.SignalMessage_Deserialize(buffer));
  }

  body(): Buffer {
    return NativeImpl.SignalMessage_GetBody(this);
  }

  counter(): number {
    return NativeImpl.SignalMessage_GetCounter(this);
  }

  messageVersion(): number {
    return NativeImpl.SignalMessage_GetMessageVersion(this);
  }

  serialize(): Buffer {
    return NativeImpl.SignalMessage_GetSerialized(this);
  }

  verifyMac(
    senderIdentityKey: PublicKey,
    recevierIdentityKey: PublicKey,
    macKey: Buffer
  ): boolean {
    return NativeImpl.SignalMessage_VerifyMac(
      this,
      senderIdentityKey,
      recevierIdentityKey,
      macKey
    );
  }
}

export class PreKeySignalMessage {
  readonly _nativeHandle: Native.PreKeySignalMessage;

  private constructor(handle: Native.PreKeySignalMessage) {
    this._nativeHandle = handle;
  }

  static _new(
    messageVersion: number,
    registrationId: number,
    preKeyId: number | null,
    signedPreKeyId: number,
    baseKey: PublicKey,
    identityKey: PublicKey,
    signalMessage: SignalMessage
  ): PreKeySignalMessage {
    return new PreKeySignalMessage(
      NativeImpl.PreKeySignalMessage_New(
        messageVersion,
        registrationId,
        preKeyId,
        signedPreKeyId,
        baseKey,
        identityKey,
        signalMessage
      )
    );
  }

  static deserialize(buffer: Buffer): PreKeySignalMessage {
    return new PreKeySignalMessage(
      NativeImpl.PreKeySignalMessage_Deserialize(buffer)
    );
  }

  preKeyId(): number | null {
    return NativeImpl.PreKeySignalMessage_GetPreKeyId(this);
  }

  registrationId(): number {
    return NativeImpl.PreKeySignalMessage_GetRegistrationId(this);
  }

  signedPreKeyId(): number {
    return NativeImpl.PreKeySignalMessage_GetSignedPreKeyId(this);
  }

  version(): number {
    return NativeImpl.PreKeySignalMessage_GetVersion(this);
  }

  serialize(): Buffer {
    return NativeImpl.PreKeySignalMessage_Serialize(this);
  }
}

export class SessionRecord {
  readonly _nativeHandle: Native.SessionRecord;

  private constructor(nativeHandle: Native.SessionRecord) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(nativeHandle: Native.SessionRecord): SessionRecord {
    return new SessionRecord(nativeHandle);
  }

  static deserialize(buffer: Buffer): SessionRecord {
    return new SessionRecord(NativeImpl.SessionRecord_Deserialize(buffer));
  }

  serialize(): Buffer {
    return NativeImpl.SessionRecord_Serialize(this);
  }

  archiveCurrentState(): void {
    NativeImpl.SessionRecord_ArchiveCurrentState(this);
  }

  localRegistrationId(): number {
    return NativeImpl.SessionRecord_GetLocalRegistrationId(this);
  }

  remoteRegistrationId(): number {
    return NativeImpl.SessionRecord_GetRemoteRegistrationId(this);
  }

  hasCurrentState(): boolean {
    return NativeImpl.SessionRecord_HasCurrentState(this);
  }
}

export class ServerCertificate {
  readonly _nativeHandle: Native.ServerCertificate;

  static _fromNativeHandle(
    nativeHandle: Native.ServerCertificate
  ): ServerCertificate {
    return new ServerCertificate(nativeHandle);
  }

  private constructor(nativeHandle: Native.ServerCertificate) {
    this._nativeHandle = nativeHandle;
  }

  static new(
    keyId: number,
    serverKey: PublicKey,
    trustRoot: PrivateKey
  ): ServerCertificate {
    return new ServerCertificate(
      NativeImpl.ServerCertificate_New(keyId, serverKey, trustRoot)
    );
  }

  static deserialize(buffer: Buffer): ServerCertificate {
    return new ServerCertificate(
      NativeImpl.ServerCertificate_Deserialize(buffer)
    );
  }

  certificateData(): Buffer {
    return NativeImpl.ServerCertificate_GetCertificate(this);
  }

  key(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.ServerCertificate_GetKey(this)
    );
  }

  keyId(): number {
    return NativeImpl.ServerCertificate_GetKeyId(this);
  }

  serialize(): Buffer {
    return NativeImpl.ServerCertificate_GetSerialized(this);
  }

  signature(): Buffer {
    return NativeImpl.ServerCertificate_GetSignature(this);
  }
}

export class SenderKeyRecord {
  readonly _nativeHandle: Native.SenderKeyRecord;

  static _fromNativeHandle(
    nativeHandle: Native.SenderKeyRecord
  ): SenderKeyRecord {
    return new SenderKeyRecord(nativeHandle);
  }

  private constructor(nativeHandle: Native.SenderKeyRecord) {
    this._nativeHandle = nativeHandle;
  }

  static new(): SenderKeyRecord {
    return new SenderKeyRecord(NativeImpl.SenderKeyRecord_New());
  }

  static deserialize(buffer: Buffer): SenderKeyRecord {
    return new SenderKeyRecord(NativeImpl.SenderKeyRecord_Deserialize(buffer));
  }

  serialize(): Buffer {
    return NativeImpl.SenderKeyRecord_Serialize(this);
  }
}

export class SenderCertificate {
  readonly _nativeHandle: Native.SenderCertificate;

  private constructor(nativeHandle: Native.SenderCertificate) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.SenderCertificate
  ): SenderCertificate {
    return new SenderCertificate(nativeHandle);
  }

  static new(
    senderUuid: string,
    senderE164: string | null,
    senderDeviceId: number,
    senderKey: PublicKey,
    expiration: number,
    signerCert: ServerCertificate,
    signerKey: PrivateKey
  ): SenderCertificate {
    return new SenderCertificate(
      NativeImpl.SenderCertificate_New(
        senderUuid,
        senderE164,
        senderDeviceId,
        senderKey,
        expiration,
        signerCert,
        signerKey
      )
    );
  }

  static deserialize(buffer: Buffer): SenderCertificate {
    return new SenderCertificate(
      NativeImpl.SenderCertificate_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return NativeImpl.SenderCertificate_GetSerialized(this);
  }

  certificate(): Buffer {
    return NativeImpl.SenderCertificate_GetCertificate(this);
  }
  expiration(): number {
    return NativeImpl.SenderCertificate_GetExpiration(this);
  }
  key(): PublicKey {
    return PublicKey._fromNativeHandle(
      NativeImpl.SenderCertificate_GetKey(this)
    );
  }
  senderE164(): string | null {
    return NativeImpl.SenderCertificate_GetSenderE164(this);
  }
  senderUuid(): string {
    return NativeImpl.SenderCertificate_GetSenderUuid(this);
  }
  senderDeviceId(): number {
    return NativeImpl.SenderCertificate_GetDeviceId(this);
  }
  serverCertificate(): ServerCertificate {
    return ServerCertificate._fromNativeHandle(
      NativeImpl.SenderCertificate_GetServerCertificate(this)
    );
  }
  signature(): Buffer {
    return NativeImpl.SenderCertificate_GetSignature(this);
  }
  validate(trustRoot: PublicKey, time: number): boolean {
    return NativeImpl.SenderCertificate_Validate(this, trustRoot, time);
  }
}

export class SenderKeyDistributionMessage {
  readonly _nativeHandle: Native.SenderKeyDistributionMessage;

  private constructor(nativeHandle: Native.SenderKeyDistributionMessage) {
    this._nativeHandle = nativeHandle;
  }

  static async create(
    sender: ProtocolAddress,
    distributionId: Uuid,
    store: SenderKeyStore
  ): Promise<SenderKeyDistributionMessage> {
    const handle = await NativeImpl.SenderKeyDistributionMessage_Create(
      sender,
      Buffer.from(uuid.parse(distributionId) as Uint8Array),
      store,
      null
    );
    return new SenderKeyDistributionMessage(handle);
  }

  static _new(
    messageVersion: number,
    distributionId: Uuid,
    chainId: number,
    iteration: number,
    chainKey: Buffer,
    pk: PublicKey
  ): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      NativeImpl.SenderKeyDistributionMessage_New(
        messageVersion,
        Buffer.from(uuid.parse(distributionId) as Uint8Array),
        chainId,
        iteration,
        chainKey,
        pk
      )
    );
  }

  static deserialize(buffer: Buffer): SenderKeyDistributionMessage {
    return new SenderKeyDistributionMessage(
      NativeImpl.SenderKeyDistributionMessage_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return NativeImpl.SenderKeyDistributionMessage_Serialize(this);
  }

  chainKey(): Buffer {
    return NativeImpl.SenderKeyDistributionMessage_GetChainKey(this);
  }

  iteration(): number {
    return NativeImpl.SenderKeyDistributionMessage_GetIteration(this);
  }

  chainId(): number {
    return NativeImpl.SenderKeyDistributionMessage_GetChainId(this);
  }

  distributionId(): Uuid {
    return uuid.stringify(
      NativeImpl.SenderKeyDistributionMessage_GetDistributionId(this)
    );
  }
}

export async function processSenderKeyDistributionMessage(
  sender: ProtocolAddress,
  message: SenderKeyDistributionMessage,
  store: SenderKeyStore
): Promise<void> {
  await NativeImpl.SenderKeyDistributionMessage_Process(
    sender,
    message,
    store,
    null
  );
}

export class SenderKeyMessage {
  readonly _nativeHandle: Native.SenderKeyMessage;

  private constructor(nativeHandle: Native.SenderKeyMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _new(
    messageVersion: number,
    distributionId: Uuid,
    chainId: number,
    iteration: number,
    ciphertext: Buffer,
    pk: PrivateKey
  ): SenderKeyMessage {
    return new SenderKeyMessage(
      NativeImpl.SenderKeyMessage_New(
        messageVersion,
        Buffer.from(uuid.parse(distributionId) as Uint8Array),
        chainId,
        iteration,
        ciphertext,
        pk
      )
    );
  }

  static deserialize(buffer: Buffer): SenderKeyMessage {
    return new SenderKeyMessage(
      NativeImpl.SenderKeyMessage_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return NativeImpl.SenderKeyMessage_Serialize(this);
  }

  ciphertext(): Buffer {
    return NativeImpl.SenderKeyMessage_GetCipherText(this);
  }

  iteration(): number {
    return NativeImpl.SenderKeyMessage_GetIteration(this);
  }

  chainId(): number {
    return NativeImpl.SenderKeyMessage_GetChainId(this);
  }

  distributionId(): Uuid {
    return uuid.stringify(NativeImpl.SenderKeyMessage_GetDistributionId(this));
  }

  verifySignature(key: PublicKey): boolean {
    return NativeImpl.SenderKeyMessage_VerifySignature(this, key);
  }
}

export class UnidentifiedSenderMessageContent {
  readonly _nativeHandle: Native.UnidentifiedSenderMessageContent;

  private constructor(nativeHandle: Native.UnidentifiedSenderMessageContent) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.UnidentifiedSenderMessageContent
  ): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(nativeHandle);
  }

  static new(
    message: CiphertextMessage,
    sender: SenderCertificate,
    contentHint: number,
    groupId: Buffer | null
  ): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(
      NativeImpl.UnidentifiedSenderMessageContent_New(
        message,
        sender,
        contentHint,
        groupId
      )
    );
  }

  static deserialize(buffer: Buffer): UnidentifiedSenderMessageContent {
    return new UnidentifiedSenderMessageContent(
      NativeImpl.UnidentifiedSenderMessageContent_Deserialize(buffer)
    );
  }

  serialize(): Buffer {
    return NativeImpl.UnidentifiedSenderMessageContent_Serialize(this);
  }

  contents(): Buffer {
    return NativeImpl.UnidentifiedSenderMessageContent_GetContents(this);
  }

  msgType(): number {
    return NativeImpl.UnidentifiedSenderMessageContent_GetMsgType(this);
  }

  senderCertificate(): SenderCertificate {
    return SenderCertificate._fromNativeHandle(
      NativeImpl.UnidentifiedSenderMessageContent_GetSenderCert(this)
    );
  }

  contentHint(): number {
    return NativeImpl.UnidentifiedSenderMessageContent_GetContentHint(this);
  }

  groupId(): Buffer | null {
    return NativeImpl.UnidentifiedSenderMessageContent_GetGroupId(this);
  }
}

export abstract class SessionStore implements Native.SessionStore {
  async _saveSession(
    name: Native.ProtocolAddress,
    record: Native.SessionRecord
  ): Promise<void> {
    return this.saveSession(
      ProtocolAddress._fromNativeHandle(name),
      SessionRecord._fromNativeHandle(record)
    );
  }
  async _getSession(
    name: Native.ProtocolAddress
  ): Promise<Native.SessionRecord | null> {
    const sess = await this.getSession(ProtocolAddress._fromNativeHandle(name));
    if (sess == null) {
      return null;
    } else {
      return sess._nativeHandle;
    }
  }

  abstract saveSession(
    name: ProtocolAddress,
    record: SessionRecord
  ): Promise<void>;
  abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>;
}

export abstract class IdentityKeyStore implements Native.IdentityKeyStore {
  async _getIdentityKey(): Promise<Native.PrivateKey> {
    const key = this.getIdentityKey();
    return key._nativeHandle;
  }

  async _getLocalRegistrationId(): Promise<number> {
    return this.getLocalRegistrationId();
  }
  async _saveIdentity(
    name: Native.ProtocolAddress,
    key: Native.PublicKey
  ): Promise<boolean> {
    return this.saveIdentity(
      ProtocolAddress._fromNativeHandle(name),
      PublicKey._fromNativeHandle(key)
    );
  }
  async _isTrustedIdentity(
    name: Native.ProtocolAddress,
    key: Native.PublicKey,
    sending: boolean
  ): Promise<boolean> {
    const direction = sending ? Direction.Sending : Direction.Receiving;

    return this.isTrustedIdentity(
      ProtocolAddress._fromNativeHandle(name),
      PublicKey._fromNativeHandle(key),
      direction
    );
  }
  async _getIdentity(
    name: Native.ProtocolAddress
  ): Promise<Native.PublicKey | null> {
    const key = await this.getIdentity(ProtocolAddress._fromNativeHandle(name));
    if (key == null) {
      return Promise.resolve(null);
    } else {
      return key._nativeHandle;
    }
  }

  abstract getIdentityKey(): PrivateKey;
  abstract getLocalRegistrationId(): number;
  abstract saveIdentity(
    name: ProtocolAddress,
    key: PublicKey
  ): Promise<boolean>;
  abstract isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    direction: Direction
  ): Promise<boolean>;
  abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>;
}

export abstract class PreKeyStore implements Native.PreKeyStore {
  async _savePreKey(id: number, record: Native.PreKeyRecord): Promise<void> {
    return this.savePreKey(id, PreKeyRecord._fromNativeHandle(record));
  }
  async _getPreKey(id: number): Promise<Native.PreKeyRecord> {
    const pk = await this.getPreKey(id);
    return pk._nativeHandle;
  }
  async _removePreKey(id: number): Promise<void> {
    return this.removePreKey(id);
  }

  abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>;
  abstract getPreKey(id: number): Promise<PreKeyRecord>;
  abstract removePreKey(id: number): Promise<void>;
}

export abstract class SignedPreKeyStore implements Native.SignedPreKeyStore {
  async _saveSignedPreKey(
    id: number,
    record: Native.SignedPreKeyRecord
  ): Promise<void> {
    return this.saveSignedPreKey(
      id,
      SignedPreKeyRecord._fromNativeHandle(record)
    );
  }
  async _getSignedPreKey(id: number): Promise<Native.SignedPreKeyRecord> {
    const pk = await this.getSignedPreKey(id);
    return pk._nativeHandle;
  }

  abstract saveSignedPreKey(
    id: number,
    record: SignedPreKeyRecord
  ): Promise<void>;
  abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>;
}

export abstract class SenderKeyStore implements Native.SenderKeyStore {
  async _saveSenderKey(
    sender: Native.ProtocolAddress,
    distributionId: Native.Uuid,
    record: Native.SenderKeyRecord
  ): Promise<void> {
    return this.saveSenderKey(
      ProtocolAddress._fromNativeHandle(sender),
      uuid.stringify(distributionId),
      SenderKeyRecord._fromNativeHandle(record)
    );
  }
  async _getSenderKey(
    sender: Native.ProtocolAddress,
    distributionId: Native.Uuid
  ): Promise<Native.SenderKeyRecord | null> {
    const skr = await this.getSenderKey(
      ProtocolAddress._fromNativeHandle(sender),
      uuid.stringify(distributionId)
    );
    if (skr == null) {
      return null;
    } else {
      return skr._nativeHandle;
    }
  }

  abstract saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord
  ): Promise<void>;
  abstract getSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid
  ): Promise<SenderKeyRecord | null>;
}

export async function groupEncrypt(
  sender: ProtocolAddress,
  distributionId: Uuid,
  store: SenderKeyStore,
  message: Buffer
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await NativeImpl.GroupCipher_EncryptMessage(
      sender,
      Buffer.from(uuid.parse(distributionId) as Uint8Array),
      message,
      store,
      null
    )
  );
}

export async function groupDecrypt(
  sender: ProtocolAddress,
  store: SenderKeyStore,
  message: Buffer
): Promise<Buffer> {
  return NativeImpl.GroupCipher_DecryptMessage(sender, message, store, null);
}

export class SealedSenderDecryptionResult {
  readonly _nativeHandle: Native.SealedSenderDecryptionResult;

  private constructor(nativeHandle: Native.SealedSenderDecryptionResult) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.SealedSenderDecryptionResult
  ): SealedSenderDecryptionResult {
    return new SealedSenderDecryptionResult(nativeHandle);
  }

  message(): Buffer {
    return NativeImpl.SealedSenderDecryptionResult_Message(this);
  }

  senderE164(): string | null {
    return NativeImpl.SealedSenderDecryptionResult_GetSenderE164(this);
  }

  senderUuid(): string {
    return NativeImpl.SealedSenderDecryptionResult_GetSenderUuid(this);
  }

  deviceId(): number {
    return NativeImpl.SealedSenderDecryptionResult_GetDeviceId(this);
  }
}

export class CiphertextMessage {
  readonly _nativeHandle: Native.CiphertextMessage;

  private constructor(nativeHandle: Native.CiphertextMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.CiphertextMessage
  ): CiphertextMessage {
    return new CiphertextMessage(nativeHandle);
  }

  serialize(): Buffer {
    return NativeImpl.CiphertextMessage_Serialize(this);
  }

  type(): number {
    return NativeImpl.CiphertextMessage_Type(this);
  }
}

export function processPreKeyBundle(
  bundle: PreKeyBundle,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<void> {
  return NativeImpl.SessionBuilder_ProcessPreKeyBundle(
    bundle,
    address,
    sessionStore,
    identityStore,
    null
  );
}

export async function signalEncrypt(
  message: Buffer,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<CiphertextMessage> {
  return CiphertextMessage._fromNativeHandle(
    await NativeImpl.SessionCipher_EncryptMessage(
      message,
      address,
      sessionStore,
      identityStore,
      null
    )
  );
}

export function signalDecrypt(
  message: SignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Buffer> {
  return NativeImpl.SessionCipher_DecryptSignalMessage(
    message,
    address,
    sessionStore,
    identityStore,
    null
  );
}

export function signalDecryptPreKey(
  message: PreKeySignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore
): Promise<Buffer> {
  return NativeImpl.SessionCipher_DecryptPreKeySignalMessage(
    message,
    address,
    sessionStore,
    identityStore,
    prekeyStore,
    signedPrekeyStore,
    null
  );
}

export async function sealedSenderEncryptMessage(
  message: Buffer,
  address: ProtocolAddress,
  senderCert: SenderCertificate,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<Buffer> {
  const ciphertext = await signalEncrypt(
    message,
    address,
    sessionStore,
    identityStore
  );
  const usmc = UnidentifiedSenderMessageContent.new(
    ciphertext,
    senderCert,
    ContentHint.Default,
    null
  );
  return await sealedSenderEncrypt(usmc, address, identityStore);
}

export function sealedSenderEncrypt(
  content: UnidentifiedSenderMessageContent,
  address: ProtocolAddress,
  identityStore: IdentityKeyStore
): Promise<Buffer> {
  return NativeImpl.SealedSender_Encrypt(address, content, identityStore, null);
}

export function sealedSenderMultiRecipientEncrypt(
  content: UnidentifiedSenderMessageContent,
  recipients: ProtocolAddress[],
  identityStore: IdentityKeyStore
): Promise<Buffer> {
  return NativeImpl.SealedSender_MultiRecipientEncrypt(
    recipients,
    content,
    identityStore,
    null
  );
}

// For testing only
export function sealedSenderMultiRecipientMessageForSingleRecipient(
  message: Buffer
): Buffer {
  return NativeImpl.SealedSender_MultiRecipientMessageForSingleRecipient(
    message
  );
}

export async function sealedSenderDecryptMessage(
  message: Buffer,
  trustRoot: PublicKey,
  timestamp: number,
  localE164: string | null,
  localUuid: string,
  localDeviceId: number,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore
): Promise<SealedSenderDecryptionResult> {
  const ssdr = await NativeImpl.SealedSender_DecryptMessage(
    message,
    trustRoot,
    timestamp,
    localE164,
    localUuid,
    localDeviceId,
    sessionStore,
    identityStore,
    prekeyStore,
    signedPrekeyStore
  );
  return SealedSenderDecryptionResult._fromNativeHandle(ssdr);
}

export function sealedSenderDecryptToUsmc(
  message: Buffer,
  identityStore: IdentityKeyStore
): UnidentifiedSenderMessageContent {
  const identity = identityStore.getIdentityKey();
  const usmc = NativeImpl.SealedSender_DecryptToUsmc(
    message,
    identity,
    identity.getPublicKey()
  );
  return UnidentifiedSenderMessageContent._fromNativeHandle(usmc);
}
