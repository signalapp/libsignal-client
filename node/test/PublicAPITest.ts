//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as SignalClient from '../index';

use(chaiAsPromised);

SignalClient.initLogger(
  SignalClient.LogLevel.Trace,
  (level, target, fileOrNull, lineOrNull, message) => {
    const targetPrefix = target ? '[' + target + '] ' : '';
    const file = fileOrNull ?? '<unknown>';
    const line = lineOrNull ?? 0;
    // eslint-disable-next-line no-console
    console.log(targetPrefix + file + ':' + line + ': ' + message);
  }
);

class InMemorySessionStore extends SignalClient.SessionStore {
  private state = new Map<string, Buffer>();
  async saveSession(
    name: SignalClient.ProtocolAddress,
    record: SignalClient.SessionRecord
  ): Promise<void> {
    const idx = name.name() + '::' + name.deviceId();
    Promise.resolve(this.state.set(idx, record.serialize()));
  }
  async getSession(
    name: SignalClient.ProtocolAddress
  ): Promise<SignalClient.SessionRecord | null> {
    const idx = name.name() + '::' + name.deviceId();
    const serialized = this.state.get(idx);
    if (serialized) {
      return Promise.resolve(
        SignalClient.SessionRecord.deserialize(serialized)
      );
    } else {
      return Promise.resolve(null);
    }
  }
  async getExistingSessions(
    addresses: SignalClient.ProtocolAddress[]
  ): Promise<SignalClient.SessionRecord[]> {
    return addresses.map(address => {
      const idx = address.name() + '::' + address.deviceId();
      const serialized = this.state.get(idx);
      if (!serialized) {
        throw 'no session for ' + idx;
      }
      return SignalClient.SessionRecord.deserialize(serialized);
    });
  }
}

class InMemoryIdentityKeyStore extends SignalClient.IdentityKeyStore {
  private idKeys = new Map();
  private localRegistrationId: number;
  private identityKey: SignalClient.PrivateKey;

  constructor() {
    super();
    this.identityKey = SignalClient.PrivateKey.generate();
    this.localRegistrationId = 5;
  }

  async getIdentityKey(): Promise<SignalClient.PrivateKey> {
    return Promise.resolve(this.identityKey);
  }
  async getLocalRegistrationId(): Promise<number> {
    return Promise.resolve(this.localRegistrationId);
  }

  async isTrustedIdentity(
    name: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey,
    _direction: SignalClient.Direction
  ): Promise<boolean> {
    const idx = name.name() + '::' + name.deviceId();
    if (this.idKeys.has(idx)) {
      const currentKey = this.idKeys.get(idx);
      return Promise.resolve(currentKey.compare(key) == 0);
    } else {
      return Promise.resolve(true);
    }
  }

  async saveIdentity(
    name: SignalClient.ProtocolAddress,
    key: SignalClient.PublicKey
  ): Promise<boolean> {
    const idx = name.name() + '::' + name.deviceId();
    const seen = this.idKeys.has(idx);
    if (seen) {
      const currentKey = this.idKeys.get(idx);
      const changed = currentKey.compare(key) != 0;
      this.idKeys.set(idx, key);
      return Promise.resolve(changed);
    }

    this.idKeys.set(idx, key);
    return Promise.resolve(false);
  }
  async getIdentity(
    name: SignalClient.ProtocolAddress
  ): Promise<SignalClient.PublicKey | null> {
    const idx = name.name() + '::' + name.deviceId();
    if (this.idKeys.has(idx)) {
      return Promise.resolve(this.idKeys.get(idx));
    } else {
      return Promise.resolve(null);
    }
  }
}

class InMemoryPreKeyStore extends SignalClient.PreKeyStore {
  private state = new Map();
  async savePreKey(
    id: number,
    record: SignalClient.PreKeyRecord
  ): Promise<void> {
    Promise.resolve(this.state.set(id, record.serialize()));
  }
  async getPreKey(id: number): Promise<SignalClient.PreKeyRecord> {
    return Promise.resolve(
      SignalClient.PreKeyRecord.deserialize(this.state.get(id))
    );
  }
  async removePreKey(id: number): Promise<void> {
    this.state.delete(id);
    return Promise.resolve();
  }
}

class InMemorySignedPreKeyStore extends SignalClient.SignedPreKeyStore {
  private state = new Map();
  async saveSignedPreKey(
    id: number,
    record: SignalClient.SignedPreKeyRecord
  ): Promise<void> {
    Promise.resolve(this.state.set(id, record.serialize()));
  }
  async getSignedPreKey(id: number): Promise<SignalClient.SignedPreKeyRecord> {
    return Promise.resolve(
      SignalClient.SignedPreKeyRecord.deserialize(this.state.get(id))
    );
  }
}

class InMemorySenderKeyStore extends SignalClient.SenderKeyStore {
  private state = new Map();
  async saveSenderKey(
    sender: SignalClient.ProtocolAddress,
    distributionId: SignalClient.Uuid,
    record: SignalClient.SenderKeyRecord
  ): Promise<void> {
    const idx =
      distributionId + '::' + sender.name() + '::' + sender.deviceId();
    Promise.resolve(this.state.set(idx, record));
  }
  async getSenderKey(
    sender: SignalClient.ProtocolAddress,
    distributionId: SignalClient.Uuid
  ): Promise<SignalClient.SenderKeyRecord | null> {
    const idx =
      distributionId + '::' + sender.name() + '::' + sender.deviceId();
    if (this.state.has(idx)) {
      return Promise.resolve(this.state.get(idx));
    } else {
      return Promise.resolve(null);
    }
  }
}

describe('SignalClient', () => {
  it('HKDF test vector', () => {
    const hkdf = SignalClient.HKDF.new(3);

    const secret = Buffer.from(
      '0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B',
      'hex'
    );
    const empty = Buffer.from('', 'hex');

    assert.deepEqual(
      hkdf.deriveSecrets(42, secret, empty, empty).toString('hex'),
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    );

    assert.deepEqual(
      hkdf.deriveSecrets(42, secret, empty, null).toString('hex'),
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    );

    const salt = Buffer.from('000102030405060708090A0B0C', 'hex');
    const label = Buffer.from('F0F1F2F3F4F5F6F7F8F9', 'hex');

    assert.deepEqual(
      hkdf.deriveSecrets(42, secret, label, salt).toString('hex'),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    );
  });
  it('ProtocolAddress', () => {
    const addr = SignalClient.ProtocolAddress.new('name', 42);
    assert.deepEqual(addr.name(), 'name');
    assert.deepEqual(addr.deviceId(), 42);
  });
  it('Fingerprint', () => {
    const aliceKey = SignalClient.PublicKey.deserialize(
      Buffer.from(
        '0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868',
        'hex'
      )
    );
    const aliceIdentifier = Buffer.from('+14152222222', 'utf8');
    const bobKey = SignalClient.PublicKey.deserialize(
      Buffer.from(
        '05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b',
        'hex'
      )
    );
    const bobIdentifier = Buffer.from('+14153333333', 'utf8');
    const iterations = 5200;
    const aFprint1 = SignalClient.Fingerprint.new(
      iterations,
      1,
      aliceIdentifier,
      aliceKey,
      bobIdentifier,
      bobKey
    );

    assert.deepEqual(
      aFprint1
        .scannableFingerprint()
        .toBuffer()
        .toString('hex'),
      '080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d'
    );

    assert.deepEqual(
      aFprint1.displayableFingerprint().toString(),
      '300354477692869396892869876765458257569162576843440918079131'
    );

    const bFprint1 = SignalClient.Fingerprint.new(
      iterations,
      1,
      bobIdentifier,
      bobKey,
      aliceIdentifier,
      aliceKey
    );

    assert.deepEqual(
      bFprint1
        .scannableFingerprint()
        .toBuffer()
        .toString('hex'),
      '080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df'
    );
    assert.deepEqual(
      bFprint1.displayableFingerprint().toString(),
      '300354477692869396892869876765458257569162576843440918079131'
    );

    assert(
      aFprint1.scannableFingerprint().compare(bFprint1.scannableFingerprint())
    );
    assert(
      bFprint1.scannableFingerprint().compare(aFprint1.scannableFingerprint())
    );

    assert.isNotTrue(
      aFprint1.scannableFingerprint().compare(aFprint1.scannableFingerprint())
    );
    assert.isNotTrue(
      bFprint1.scannableFingerprint().compare(bFprint1.scannableFingerprint())
    );
  });
  it('SenderCertificate', () => {
    const trustRoot = SignalClient.PrivateKey.generate();
    const serverKey = SignalClient.PrivateKey.generate();

    const keyId = 23;

    const serverCert = SignalClient.ServerCertificate.new(
      keyId,
      serverKey.getPublicKey(),
      trustRoot
    );
    assert.deepEqual(serverCert.keyId(), keyId);
    assert.deepEqual(serverCert.key(), serverKey.getPublicKey());

    const serverCertFromBytes = SignalClient.ServerCertificate.deserialize(
      serverCert.serialize()
    );
    assert.deepEqual(serverCert, serverCertFromBytes);

    const senderUuid = 'fedfe51e-2b91-4156-8710-7cc1bdd57cd8';
    const senderE164 = '555-123-4567';
    const senderDeviceId = 9;
    const senderKey = SignalClient.PrivateKey.generate();
    const expiration = 2114398800; // Jan 1, 2037

    const senderCert = SignalClient.SenderCertificate.new(
      senderUuid,
      senderE164,
      senderDeviceId,
      senderKey.getPublicKey(),
      expiration,
      serverCert,
      serverKey
    );

    assert.deepEqual(senderCert.serverCertificate(), serverCert);
    assert.deepEqual(senderCert.senderUuid(), senderUuid);
    assert.deepEqual(senderCert.senderE164(), senderE164);
    assert.deepEqual(senderCert.senderDeviceId(), senderDeviceId);

    const senderCertFromBytes = SignalClient.SenderCertificate.deserialize(
      senderCert.serialize()
    );
    assert.deepEqual(senderCert, senderCertFromBytes);

    assert(senderCert.validate(trustRoot.getPublicKey(), expiration - 1000));
    assert(!senderCert.validate(trustRoot.getPublicKey(), expiration + 10)); // expired
  });
  it('SenderKeyMessage', () => {
    const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
    const chainId = 9;
    const iteration = 101;
    const ciphertext = Buffer.alloc(32, 0xfe);
    const pk = SignalClient.PrivateKey.generate();

    const skm = SignalClient.SenderKeyMessage._new(
      3,
      distributionId,
      chainId,
      iteration,
      ciphertext,
      pk
    );
    assert.deepEqual(skm.distributionId(), distributionId);
    assert.deepEqual(skm.chainId(), chainId);
    assert.deepEqual(skm.iteration(), iteration);
    assert.deepEqual(skm.ciphertext(), ciphertext);

    assert(skm.verifySignature(pk.getPublicKey()));

    const skmFromBytes = SignalClient.SenderKeyMessage.deserialize(
      skm.serialize()
    );
    assert.deepEqual(skm, skmFromBytes);
  });
  it('SenderKeyDistributionMessage', () => {
    const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
    const chainId = 9;
    const iteration = 101;
    const chainKey = Buffer.alloc(32, 0xfe);
    const pk = SignalClient.PrivateKey.generate();

    const skdm = SignalClient.SenderKeyDistributionMessage._new(
      3,
      distributionId,
      chainId,
      iteration,
      chainKey,
      pk.getPublicKey()
    );
    assert.deepEqual(skdm.distributionId(), distributionId);
    assert.deepEqual(skdm.chainId(), chainId);
    assert.deepEqual(skdm.iteration(), iteration);
    assert.deepEqual(skdm.chainKey(), chainKey);

    const skdmFromBytes = SignalClient.SenderKeyDistributionMessage.deserialize(
      skdm.serialize()
    );
    assert.deepEqual(skdm, skdmFromBytes);
  });
  describe('SenderKeyDistributionMessage Store API', () => {
    it('can encrypt and decrypt', async () => {
      const sender = SignalClient.ProtocolAddress.new('sender', 1);
      const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
      const aSenderKeyStore = new InMemorySenderKeyStore();
      const skdm = await SignalClient.SenderKeyDistributionMessage.create(
        sender,
        distributionId,
        aSenderKeyStore
      );

      const bSenderKeyStore = new InMemorySenderKeyStore();
      await SignalClient.processSenderKeyDistributionMessage(
        sender,
        skdm,
        bSenderKeyStore
      );

      const message = Buffer.from('0a0b0c', 'hex');

      const aCtext = await SignalClient.groupEncrypt(
        sender,
        distributionId,
        aSenderKeyStore,
        message
      );

      const bPtext = await SignalClient.groupDecrypt(
        sender,
        bSenderKeyStore,
        aCtext.serialize()
      );

      assert.deepEqual(message, bPtext);
    });
    it("does not panic if there's an error", async () => {
      const sender = SignalClient.ProtocolAddress.new('sender', 1);
      const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
      const aSenderKeyStore = new InMemorySenderKeyStore();

      const messagePromise = SignalClient.SenderKeyDistributionMessage.create(
        sender,
        distributionId,
        (undefined as unknown) as SignalClient.SenderKeyStore
      );
      await assert.isRejected(messagePromise, TypeError);

      const messagePromise2 = SignalClient.SenderKeyDistributionMessage.create(
        ({} as unknown) as SignalClient.ProtocolAddress,
        distributionId,
        aSenderKeyStore
      );
      await assert.isRejected(messagePromise2, TypeError);
    });
  });
  it('PublicKeyBundle', () => {
    const registrationId = 5;
    const deviceId = 23;
    const prekeyId = 42;
    const prekey = SignalClient.PrivateKey.generate().getPublicKey();
    const signedPrekeyId = 2300;
    const signedPrekey = SignalClient.PrivateKey.generate().getPublicKey();
    const signedPrekeySignature = SignalClient.PrivateKey.generate().sign(
      Buffer.from('010203', 'hex')
    );
    const identityKey = SignalClient.PrivateKey.generate().getPublicKey();

    const pkb = SignalClient.PreKeyBundle.new(
      registrationId,
      deviceId,
      prekeyId,
      prekey,
      signedPrekeyId,
      signedPrekey,
      signedPrekeySignature,
      identityKey
    );

    assert.deepEqual(pkb.registrationId(), registrationId);
    assert.deepEqual(pkb.deviceId(), deviceId);
    assert.deepEqual(pkb.preKeyId(), prekeyId);
    assert.deepEqual(pkb.preKeyPublic(), prekey);
    assert.deepEqual(pkb.signedPreKeyId(), signedPrekeyId);
    assert.deepEqual(pkb.signedPreKeyPublic(), signedPrekey);
    assert.deepEqual(pkb.signedPreKeySignature(), signedPrekeySignature);
    assert.deepEqual(pkb.identityKey(), identityKey);

    // null handling:
    const pkb2 = SignalClient.PreKeyBundle.new(
      registrationId,
      deviceId,
      null,
      null,
      signedPrekeyId,
      signedPrekey,
      signedPrekeySignature,
      identityKey
    );

    assert.deepEqual(pkb2.registrationId(), registrationId);
    assert.deepEqual(pkb2.deviceId(), deviceId);
    assert.deepEqual(pkb2.preKeyId(), null);
    assert.deepEqual(pkb2.preKeyPublic(), null);
    assert.deepEqual(pkb2.signedPreKeyId(), signedPrekeyId);
    assert.deepEqual(pkb2.signedPreKeyPublic(), signedPrekey);
    assert.deepEqual(pkb2.signedPreKeySignature(), signedPrekeySignature);
    assert.deepEqual(pkb2.identityKey(), identityKey);
  });
  it('PreKeyRecord', () => {
    const privKey = SignalClient.PrivateKey.generate();
    const pubKey = privKey.getPublicKey();
    const pkr = SignalClient.PreKeyRecord.new(23, pubKey, privKey);

    assert.deepEqual(pkr.id(), 23);
    assert.deepEqual(pkr.publicKey(), pubKey);
    assert.deepEqual(pkr.privateKey(), privKey);

    const pkr2 = SignalClient.PreKeyRecord.deserialize(pkr.serialize());
    assert.deepEqual(pkr2.id(), 23);
    assert.deepEqual(pkr2.publicKey(), pubKey);
    assert.deepEqual(pkr2.privateKey(), privKey);
  });
  it('SignedPreKeyRecord', () => {
    const privKey = SignalClient.PrivateKey.generate();
    const pubKey = privKey.getPublicKey();
    const timestamp = 9000;
    const keyId = 23;
    const signature = Buffer.alloc(64, 64);
    const spkr = SignalClient.SignedPreKeyRecord.new(
      keyId,
      timestamp,
      pubKey,
      privKey,
      signature
    );

    assert.deepEqual(spkr.id(), keyId);
    assert.deepEqual(spkr.timestamp(), timestamp);
    assert.deepEqual(spkr.publicKey(), pubKey);
    assert.deepEqual(spkr.privateKey(), privKey);
    assert.deepEqual(spkr.signature(), signature);

    const spkrFromBytes = SignalClient.SignedPreKeyRecord.deserialize(
      spkr.serialize()
    );
    assert.deepEqual(spkrFromBytes, spkr);
  });
  it('SenderKeyRecord', () => {
    const skr = SignalClient.SenderKeyRecord.new();
    const skrFromBytes = SignalClient.SenderKeyRecord.deserialize(
      skr.serialize()
    );
    assert.deepEqual(skr, skrFromBytes);
  });
  it('SignalMessage and PreKeySignalMessage', () => {
    const messageVersion = 3;
    const macKey = Buffer.alloc(32, 0xab);
    const senderRatchetKey = SignalClient.PrivateKey.generate().getPublicKey();
    const counter = 9;
    const previousCounter = 8;
    const senderIdentityKey = SignalClient.PrivateKey.generate().getPublicKey();
    const receiverIdentityKey = SignalClient.PrivateKey.generate().getPublicKey();
    const ciphertext = Buffer.from('01020304', 'hex');

    const sm = SignalClient.SignalMessage._new(
      messageVersion,
      macKey,
      senderRatchetKey,
      counter,
      previousCounter,
      ciphertext,
      senderIdentityKey,
      receiverIdentityKey
    );

    assert.deepEqual(sm.counter(), counter);
    assert.deepEqual(sm.messageVersion(), messageVersion);

    const sm_bytes = sm.serialize();

    const sm2 = SignalClient.SignalMessage.deserialize(sm_bytes);

    assert.deepEqual(sm.body(), sm2.body());

    const registrationId = 9;
    const preKeyId = 23;
    const signedPreKeyId = 802;
    const baseKey = SignalClient.PrivateKey.generate().getPublicKey();
    const identityKey = SignalClient.PrivateKey.generate().getPublicKey();

    const pkm = SignalClient.PreKeySignalMessage._new(
      messageVersion,
      registrationId,
      preKeyId,
      signedPreKeyId,
      baseKey,
      identityKey,
      sm
    );
    assert.deepEqual(pkm.preKeyId(), preKeyId);
    assert.deepEqual(pkm.registrationId(), registrationId);
    assert.deepEqual(pkm.signedPreKeyId(), signedPreKeyId);
    assert.deepEqual(pkm.version(), messageVersion);

    const pkm_bytes = pkm.serialize();

    const pkm2 = SignalClient.PreKeySignalMessage.deserialize(pkm_bytes);

    assert.deepEqual(pkm2.serialize(), pkm_bytes);
  });
  it('BasicPreKeyMessaging', async () => {
    // basic_prekey_v3 in Rust
    const aKeys = new InMemoryIdentityKeyStore();
    const bKeys = new InMemoryIdentityKeyStore();

    const aSess = new InMemorySessionStore();
    const bSess = new InMemorySessionStore();

    const bPreK = new InMemoryPreKeyStore();
    const bSPreK = new InMemorySignedPreKeyStore();

    const bPreKey = SignalClient.PrivateKey.generate();
    const bSPreKey = SignalClient.PrivateKey.generate();

    const bIdentityKey = await bKeys.getIdentityKey();
    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialize()
    );

    const aAddress = SignalClient.ProtocolAddress.new('+14151111111', 1);
    const bAddress = SignalClient.ProtocolAddress.new('+19192222222', 1);

    const bRegistrationId = await bKeys.getLocalRegistrationId();
    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bPreKeyBundle = SignalClient.PreKeyBundle.new(
      bRegistrationId,
      bAddress.deviceId(),
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey()
    );

    const bPreKeyRecord = SignalClient.PreKeyRecord.new(
      bPreKeyId,
      bPreKey.getPublicKey(),
      bPreKey
    );
    bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

    const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
      bSignedPreKeyId,
      42, // timestamp
      bSPreKey.getPublicKey(),
      bSPreKey,
      bSignedPreKeySig
    );
    bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

    await SignalClient.processPreKeyBundle(
      bPreKeyBundle,
      bAddress,
      aSess,
      aKeys
    );
    const aMessage = Buffer.from('Greetings hoo-man', 'utf8');

    const aCiphertext = await SignalClient.signalEncrypt(
      aMessage,
      bAddress,
      aSess,
      aKeys
    );

    assert.deepEqual(
      aCiphertext.type(),
      SignalClient.CiphertextMessageType.PreKey
    );

    const aCiphertextR = SignalClient.PreKeySignalMessage.deserialize(
      aCiphertext.serialize()
    );

    const bDPlaintext = await SignalClient.signalDecryptPreKey(
      aCiphertextR,
      aAddress,
      bSess,
      bKeys,
      bPreK,
      bSPreK
    );
    assert.deepEqual(bDPlaintext, aMessage);

    const bMessage = Buffer.from(
      'Sometimes the only thing more dangerous than a question is an answer.',
      'utf8'
    );

    const bCiphertext = await SignalClient.signalEncrypt(
      bMessage,
      aAddress,
      bSess,
      bKeys
    );

    assert.deepEqual(
      bCiphertext.type(),
      SignalClient.CiphertextMessageType.Whisper
    );

    const bCiphertextR = SignalClient.SignalMessage.deserialize(
      bCiphertext.serialize()
    );

    const aDPlaintext = await SignalClient.signalDecrypt(
      bCiphertextR,
      bAddress,
      aSess,
      aKeys
    );

    assert.deepEqual(aDPlaintext, bMessage);

    const session = await bSess.getSession(aAddress);

    if (session != null) {
      assert(session.serialize().length > 0);
      assert.deepEqual(session.localRegistrationId(), 5);
      assert.deepEqual(session.remoteRegistrationId(), 5);
      assert(session.hasCurrentState());
      assert(
        !session.currentRatchetKeyMatches(
          SignalClient.PrivateKey.generate().getPublicKey()
        )
      );

      session.archiveCurrentState();
      assert(!session.hasCurrentState());
      assert(
        !session.currentRatchetKeyMatches(
          SignalClient.PrivateKey.generate().getPublicKey()
        )
      );
    } else {
      assert.fail('no session found');
    }
  });
  it('handles duplicated messages', async () => {
    const aKeys = new InMemoryIdentityKeyStore();
    const bKeys = new InMemoryIdentityKeyStore();

    const aSess = new InMemorySessionStore();
    const bSess = new InMemorySessionStore();

    const bPreK = new InMemoryPreKeyStore();
    const bSPreK = new InMemorySignedPreKeyStore();

    const bPreKey = SignalClient.PrivateKey.generate();
    const bSPreKey = SignalClient.PrivateKey.generate();

    const bIdentityKey = await bKeys.getIdentityKey();
    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialize()
    );

    const aAddress = SignalClient.ProtocolAddress.new('+14151111111', 1);
    const bAddress = SignalClient.ProtocolAddress.new('+19192222222', 1);

    const bRegistrationId = await bKeys.getLocalRegistrationId();
    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bPreKeyBundle = SignalClient.PreKeyBundle.new(
      bRegistrationId,
      bAddress.deviceId(),
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey()
    );

    const bPreKeyRecord = SignalClient.PreKeyRecord.new(
      bPreKeyId,
      bPreKey.getPublicKey(),
      bPreKey
    );
    bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

    const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
      bSignedPreKeyId,
      42, // timestamp
      bSPreKey.getPublicKey(),
      bSPreKey,
      bSignedPreKeySig
    );
    bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

    await SignalClient.processPreKeyBundle(
      bPreKeyBundle,
      bAddress,
      aSess,
      aKeys
    );
    const aMessage = Buffer.from('Greetings hoo-man', 'utf8');

    const aCiphertext = await SignalClient.signalEncrypt(
      aMessage,
      bAddress,
      aSess,
      aKeys
    );

    assert.deepEqual(
      aCiphertext.type(),
      SignalClient.CiphertextMessageType.PreKey
    );

    const aCiphertextR = SignalClient.PreKeySignalMessage.deserialize(
      aCiphertext.serialize()
    );

    const bDPlaintext = await SignalClient.signalDecryptPreKey(
      aCiphertextR,
      aAddress,
      bSess,
      bKeys,
      bPreK,
      bSPreK
    );
    assert.deepEqual(bDPlaintext, aMessage);

    try {
      await SignalClient.signalDecryptPreKey(
        aCiphertextR,
        aAddress,
        bSess,
        bKeys,
        bPreK,
        bSPreK
      );
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.SignalClientErrorBase);
      const err = e as SignalClient.SignalClientError;
      assert.equal(err.name, 'DuplicatedMessage');
      assert.equal(err.code, SignalClient.ErrorCode.DuplicatedMessage);
      assert.equal(err.operation, 'SessionCipher_DecryptPreKeySignalMessage'); // the Rust entry point
      assert.exists(err.stack); // Make sure we're still getting the benefits of Error.
    }

    const bMessage = Buffer.from(
      'Sometimes the only thing more dangerous than a question is an answer.',
      'utf8'
    );

    const bCiphertext = await SignalClient.signalEncrypt(
      bMessage,
      aAddress,
      bSess,
      bKeys
    );

    assert.deepEqual(
      bCiphertext.type(),
      SignalClient.CiphertextMessageType.Whisper
    );

    const bCiphertextR = SignalClient.SignalMessage.deserialize(
      bCiphertext.serialize()
    );

    const aDPlaintext = await SignalClient.signalDecrypt(
      bCiphertextR,
      bAddress,
      aSess,
      aKeys
    );

    assert.deepEqual(aDPlaintext, bMessage);

    try {
      await SignalClient.signalDecrypt(bCiphertextR, bAddress, aSess, aKeys);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.SignalClientErrorBase);
      const err = e as SignalClient.SignalClientError;
      assert.equal(err.name, 'DuplicatedMessage');
      assert.equal(err.code, SignalClient.ErrorCode.DuplicatedMessage);
      assert.equal(err.operation, 'SessionCipher_DecryptSignalMessage'); // the Rust entry point
      assert.exists(err.stack); // Make sure we're still getting the benefits of Error.
    }
  });
  describe('SealedSender', () => {
    it('can encrypt/decrypt 1-1 messages', async () => {
      const aKeys = new InMemoryIdentityKeyStore();
      const bKeys = new InMemoryIdentityKeyStore();

      const aSess = new InMemorySessionStore();
      const bSess = new InMemorySessionStore();

      const bPreK = new InMemoryPreKeyStore();
      const bSPreK = new InMemorySignedPreKeyStore();

      const bPreKey = SignalClient.PrivateKey.generate();
      const bSPreKey = SignalClient.PrivateKey.generate();

      const aIdentityKey = await aKeys.getIdentityKey();
      const bIdentityKey = await bKeys.getIdentityKey();

      const aE164 = '+14151111111';
      const bE164 = '+19192222222';

      const aDeviceId = 1;
      const bDeviceId = 3;

      const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
      const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

      const trustRoot = SignalClient.PrivateKey.generate();
      const serverKey = SignalClient.PrivateKey.generate();

      const serverCert = SignalClient.ServerCertificate.new(
        1,
        serverKey.getPublicKey(),
        trustRoot
      );

      const expires = 1605722925;
      const senderCert = SignalClient.SenderCertificate.new(
        aUuid,
        aE164,
        aDeviceId,
        aIdentityKey.getPublicKey(),
        expires,
        serverCert,
        serverKey
      );

      const bRegistrationId = await bKeys.getLocalRegistrationId();
      const bPreKeyId = 31337;
      const bSignedPreKeyId = 22;

      const bSignedPreKeySig = bIdentityKey.sign(
        bSPreKey.getPublicKey().serialize()
      );

      const bPreKeyBundle = SignalClient.PreKeyBundle.new(
        bRegistrationId,
        bDeviceId,
        bPreKeyId,
        bPreKey.getPublicKey(),
        bSignedPreKeyId,
        bSPreKey.getPublicKey(),
        bSignedPreKeySig,
        bIdentityKey.getPublicKey()
      );

      const bPreKeyRecord = SignalClient.PreKeyRecord.new(
        bPreKeyId,
        bPreKey.getPublicKey(),
        bPreKey
      );
      bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

      const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
        bSignedPreKeyId,
        42, // timestamp
        bSPreKey.getPublicKey(),
        bSPreKey,
        bSignedPreKeySig
      );
      bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

      const bAddress = SignalClient.ProtocolAddress.new(bUuid, bDeviceId);
      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aSess,
        aKeys
      );

      const aPlaintext = Buffer.from('hi there', 'utf8');

      const aCiphertext = await SignalClient.sealedSenderEncryptMessage(
        aPlaintext,
        bAddress,
        senderCert,
        aSess,
        aKeys
      );

      const bPlaintext = await SignalClient.sealedSenderDecryptMessage(
        aCiphertext,
        trustRoot.getPublicKey(),
        43, // timestamp,
        bE164,
        bUuid,
        bDeviceId,
        bSess,
        bKeys,
        bPreK,
        bSPreK
      );

      assert(bPlaintext != null);

      if (bPlaintext != null) {
        assert.deepEqual(bPlaintext.message(), aPlaintext);
        assert.deepEqual(bPlaintext.senderE164(), aE164);
        assert.deepEqual(bPlaintext.senderUuid(), aUuid);
        assert.deepEqual(bPlaintext.deviceId(), aDeviceId);
      }

      const innerMessage = await SignalClient.signalEncrypt(
        aPlaintext,
        bAddress,
        aSess,
        aKeys
      );

      for (const hint of [
        200,
        SignalClient.ContentHint.Default,
        SignalClient.ContentHint.Resendable,
        SignalClient.ContentHint.Implicit,
      ]) {
        const content = SignalClient.UnidentifiedSenderMessageContent.new(
          innerMessage,
          senderCert,
          hint,
          null
        );
        const ciphertext = await SignalClient.sealedSenderEncrypt(
          content,
          bAddress,
          aKeys
        );
        const decryptedContent = await SignalClient.sealedSenderDecryptToUsmc(
          ciphertext,
          bKeys
        );
        assert.deepEqual(decryptedContent.contentHint(), hint);
      }
    });

    it('rejects self-sent messages', async () => {
      const sharedKeys = new InMemoryIdentityKeyStore();

      const aSess = new InMemorySessionStore();
      const bSess = new InMemorySessionStore();

      const bPreK = new InMemoryPreKeyStore();
      const bSPreK = new InMemorySignedPreKeyStore();

      const bPreKey = SignalClient.PrivateKey.generate();
      const bSPreKey = SignalClient.PrivateKey.generate();

      const sharedIdentityKey = await sharedKeys.getIdentityKey();

      const aE164 = '+14151111111';

      const sharedDeviceId = 1;

      const sharedUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';

      const trustRoot = SignalClient.PrivateKey.generate();
      const serverKey = SignalClient.PrivateKey.generate();

      const serverCert = SignalClient.ServerCertificate.new(
        1,
        serverKey.getPublicKey(),
        trustRoot
      );

      const expires = 1605722925;
      const senderCert = SignalClient.SenderCertificate.new(
        sharedUuid,
        aE164,
        sharedDeviceId,
        sharedIdentityKey.getPublicKey(),
        expires,
        serverCert,
        serverKey
      );

      const sharedRegistrationId = await sharedKeys.getLocalRegistrationId();
      const bPreKeyId = 31337;
      const bSignedPreKeyId = 22;

      const bSignedPreKeySig = sharedIdentityKey.sign(
        bSPreKey.getPublicKey().serialize()
      );

      const bPreKeyBundle = SignalClient.PreKeyBundle.new(
        sharedRegistrationId,
        sharedDeviceId,
        bPreKeyId,
        bPreKey.getPublicKey(),
        bSignedPreKeyId,
        bSPreKey.getPublicKey(),
        bSignedPreKeySig,
        sharedIdentityKey.getPublicKey()
      );

      const bPreKeyRecord = SignalClient.PreKeyRecord.new(
        bPreKeyId,
        bPreKey.getPublicKey(),
        bPreKey
      );
      bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

      const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
        bSignedPreKeyId,
        42, // timestamp
        bSPreKey.getPublicKey(),
        bSPreKey,
        bSignedPreKeySig
      );
      bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

      const sharedAddress = SignalClient.ProtocolAddress.new(
        sharedUuid,
        sharedDeviceId
      );
      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        sharedAddress,
        aSess,
        sharedKeys
      );

      const aPlaintext = Buffer.from('hi there', 'utf8');

      const aCiphertext = await SignalClient.sealedSenderEncryptMessage(
        aPlaintext,
        sharedAddress,
        senderCert,
        aSess,
        sharedKeys
      );

      try {
        await SignalClient.sealedSenderDecryptMessage(
          aCiphertext,
          trustRoot.getPublicKey(),
          43, // timestamp,
          null,
          sharedUuid,
          sharedDeviceId,
          bSess,
          sharedKeys,
          bPreK,
          bSPreK
        );
        assert.fail();
      } catch (e) {
        assert.instanceOf(e, Error);
        assert.instanceOf(e, SignalClient.SignalClientErrorBase);
        const err = e as SignalClient.SignalClientError;
        assert.equal(err.name, 'SealedSenderSelfSend');
        assert.equal(err.code, SignalClient.ErrorCode.SealedSenderSelfSend);
        assert.equal(err.operation, 'SealedSender_DecryptMessage'); // the Rust entry point
        assert.exists(err.stack); // Make sure we're still getting the benefits of Error.
      }
    });

    it('can encrypt/decrypt group messages', async () => {
      const aKeys = new InMemoryIdentityKeyStore();
      const bKeys = new InMemoryIdentityKeyStore();

      const aSess = new InMemorySessionStore();

      const bPreK = new InMemoryPreKeyStore();
      const bSPreK = new InMemorySignedPreKeyStore();

      const bPreKey = SignalClient.PrivateKey.generate();
      const bSPreKey = SignalClient.PrivateKey.generate();

      const aIdentityKey = await aKeys.getIdentityKey();
      const bIdentityKey = await bKeys.getIdentityKey();

      const aE164 = '+14151111111';

      const aDeviceId = 1;
      const bDeviceId = 3;

      const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
      const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

      const trustRoot = SignalClient.PrivateKey.generate();
      const serverKey = SignalClient.PrivateKey.generate();

      const serverCert = SignalClient.ServerCertificate.new(
        1,
        serverKey.getPublicKey(),
        trustRoot
      );

      const expires = 1605722925;
      const senderCert = SignalClient.SenderCertificate.new(
        aUuid,
        aE164,
        aDeviceId,
        aIdentityKey.getPublicKey(),
        expires,
        serverCert,
        serverKey
      );

      const bRegistrationId = await bKeys.getLocalRegistrationId();
      const bPreKeyId = 31337;
      const bSignedPreKeyId = 22;

      const bSignedPreKeySig = bIdentityKey.sign(
        bSPreKey.getPublicKey().serialize()
      );

      const bPreKeyBundle = SignalClient.PreKeyBundle.new(
        bRegistrationId,
        bDeviceId,
        bPreKeyId,
        bPreKey.getPublicKey(),
        bSignedPreKeyId,
        bSPreKey.getPublicKey(),
        bSignedPreKeySig,
        bIdentityKey.getPublicKey()
      );

      const bPreKeyRecord = SignalClient.PreKeyRecord.new(
        bPreKeyId,
        bPreKey.getPublicKey(),
        bPreKey
      );
      bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

      const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
        bSignedPreKeyId,
        42, // timestamp
        bSPreKey.getPublicKey(),
        bSPreKey,
        bSignedPreKeySig
      );
      bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

      const bAddress = SignalClient.ProtocolAddress.new(bUuid, bDeviceId);
      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aSess,
        aKeys
      );

      const aAddress = SignalClient.ProtocolAddress.new(aUuid, aDeviceId);

      const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
      const aSenderKeyStore = new InMemorySenderKeyStore();
      const skdm = await SignalClient.SenderKeyDistributionMessage.create(
        aAddress,
        distributionId,
        aSenderKeyStore
      );

      const bSenderKeyStore = new InMemorySenderKeyStore();
      await SignalClient.processSenderKeyDistributionMessage(
        aAddress,
        skdm,
        bSenderKeyStore
      );

      const message = Buffer.from('0a0b0c', 'hex');

      const aCtext = await SignalClient.groupEncrypt(
        aAddress,
        distributionId,
        aSenderKeyStore,
        message
      );

      const aUsmc = SignalClient.UnidentifiedSenderMessageContent.new(
        aCtext,
        senderCert,
        SignalClient.ContentHint.Implicit,
        Buffer.from([42])
      );

      const aSealedSenderMessage = await SignalClient.sealedSenderMultiRecipientEncrypt(
        aUsmc,
        [bAddress],
        aKeys,
        aSess
      );

      const bSealedSenderMessage = SignalClient.sealedSenderMultiRecipientMessageForSingleRecipient(
        aSealedSenderMessage
      );

      const bUsmc = await SignalClient.sealedSenderDecryptToUsmc(
        bSealedSenderMessage,
        bKeys
      );

      assert.deepEqual(bUsmc.senderCertificate().senderE164(), aE164);
      assert.deepEqual(bUsmc.senderCertificate().senderUuid(), aUuid);
      assert.deepEqual(bUsmc.senderCertificate().senderDeviceId(), aDeviceId);
      assert.deepEqual(bUsmc.contentHint(), SignalClient.ContentHint.Implicit);
      assert.deepEqual(bUsmc.groupId(), Buffer.from([42]));

      const bPtext = await SignalClient.groupDecrypt(
        aAddress,
        bSenderKeyStore,
        bUsmc.contents()
      );

      assert.deepEqual(message, bPtext);
    });
  });

  it('DecryptionMessageError', async () => {
    const aKeys = new InMemoryIdentityKeyStore();
    const bKeys = new InMemoryIdentityKeyStore();

    const aSess = new InMemorySessionStore();
    const bSess = new InMemorySessionStore();

    const bPreK = new InMemoryPreKeyStore();
    const bSPreK = new InMemorySignedPreKeyStore();

    const bPreKey = SignalClient.PrivateKey.generate();
    const bSPreKey = SignalClient.PrivateKey.generate();

    const aIdentityKey = await aKeys.getIdentityKey();
    const bIdentityKey = await bKeys.getIdentityKey();

    const aE164 = '+14151111111';

    const aDeviceId = 1;
    const bDeviceId = 3;

    const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
    const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

    const trustRoot = SignalClient.PrivateKey.generate();
    const serverKey = SignalClient.PrivateKey.generate();

    const serverCert = SignalClient.ServerCertificate.new(
      1,
      serverKey.getPublicKey(),
      trustRoot
    );

    const expires = 1605722925;
    const senderCert = SignalClient.SenderCertificate.new(
      aUuid,
      aE164,
      aDeviceId,
      aIdentityKey.getPublicKey(),
      expires,
      serverCert,
      serverKey
    );

    const bRegistrationId = await bKeys.getLocalRegistrationId();
    const bPreKeyId = 31337;
    const bSignedPreKeyId = 22;

    const bSignedPreKeySig = bIdentityKey.sign(
      bSPreKey.getPublicKey().serialize()
    );

    const bPreKeyBundle = SignalClient.PreKeyBundle.new(
      bRegistrationId,
      bDeviceId,
      bPreKeyId,
      bPreKey.getPublicKey(),
      bSignedPreKeyId,
      bSPreKey.getPublicKey(),
      bSignedPreKeySig,
      bIdentityKey.getPublicKey()
    );

    const bPreKeyRecord = SignalClient.PreKeyRecord.new(
      bPreKeyId,
      bPreKey.getPublicKey(),
      bPreKey
    );
    bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

    const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
      bSignedPreKeyId,
      42, // timestamp
      bSPreKey.getPublicKey(),
      bSPreKey,
      bSignedPreKeySig
    );
    bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

    // Set up the session with a message from A to B.

    const bAddress = SignalClient.ProtocolAddress.new(bUuid, bDeviceId);
    await SignalClient.processPreKeyBundle(
      bPreKeyBundle,
      bAddress,
      aSess,
      aKeys
    );

    const aPlaintext = Buffer.from('hi there', 'utf8');

    const aCiphertext = await SignalClient.sealedSenderEncryptMessage(
      aPlaintext,
      bAddress,
      senderCert,
      aSess,
      aKeys
    );

    await SignalClient.sealedSenderDecryptMessage(
      aCiphertext,
      trustRoot.getPublicKey(),
      43, // timestamp,
      null,
      bUuid,
      bDeviceId,
      bSess,
      bKeys,
      bPreK,
      bSPreK
    );

    // Pretend to send a message from B back to A that "fails".
    const aAddress = SignalClient.ProtocolAddress.new(aUuid, aDeviceId);
    const bCiphertext = await SignalClient.signalEncrypt(
      Buffer.from('reply', 'utf8'),
      aAddress,
      bSess,
      bKeys
    );

    const errorMessage = SignalClient.DecryptionErrorMessage.forOriginal(
      bCiphertext.serialize(),
      bCiphertext.type(),
      45, // timestamp
      bAddress.deviceId()
    );
    const errorContent = SignalClient.PlaintextContent.from(errorMessage);
    const errorUSMC = SignalClient.UnidentifiedSenderMessageContent.new(
      SignalClient.CiphertextMessage.from(errorContent),
      senderCert,
      SignalClient.ContentHint.Implicit,
      null // group ID
    );
    const errorSealedSenderMessage = await SignalClient.sealedSenderEncrypt(
      errorUSMC,
      bAddress,
      aKeys
    );

    const bErrorUSMC = await SignalClient.sealedSenderDecryptToUsmc(
      errorSealedSenderMessage,
      bKeys
    );
    assert.equal(
      bErrorUSMC.msgType(),
      SignalClient.CiphertextMessageType.Plaintext
    );
    const bErrorContent = SignalClient.PlaintextContent.deserialize(
      bErrorUSMC.contents()
    );
    const bErrorMessage = SignalClient.DecryptionErrorMessage.extractFromSerializedBody(
      bErrorContent.body()
    );
    assert.equal(bErrorMessage.timestamp(), 45);
    assert.equal(bErrorMessage.deviceId(), bAddress.deviceId());

    const bSessionWithA = await bSess.getSession(aAddress);
    assert(
      bSessionWithA?.currentRatchetKeyMatches(
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        bErrorMessage.ratchetKey()!
      )
    );
  });

  it('AES-GCM-SIV test vector', () => {
    // RFC 8452, appendix C.2
    const key = Buffer.from(
      '0100000000000000000000000000000000000000000000000000000000000000',
      'hex'
    );

    const aes_gcm_siv = SignalClient.Aes256GcmSiv.new(key);

    const nonce = Buffer.from('030000000000000000000000', 'hex');
    const aad = Buffer.from('010000000000000000000000', 'hex');
    const ptext = Buffer.from('02000000', 'hex');

    const ctext = aes_gcm_siv.encrypt(ptext, nonce, aad);

    assert.deepEqual(
      ctext.toString('hex'),
      '22b3f4cd1835e517741dfddccfa07fa4661b74cf'
    );

    const decrypted = aes_gcm_siv.decrypt(ctext, nonce, aad);

    assert.deepEqual(decrypted.toString('hex'), '02000000');
  });
  it('ECC signatures work', () => {
    const priv_a = SignalClient.PrivateKey.generate();
    const priv_b = SignalClient.PrivateKey.generate();
    assert.lengthOf(priv_a.serialize(), 32, 'private key serialization length');
    assert.deepEqual(priv_a.serialize(), priv_a.serialize(), 'repeatable');
    assert.notDeepEqual(
      priv_a.serialize(),
      priv_b.serialize(),
      'different for different keys'
    );

    const pub_a = priv_a.getPublicKey();
    const pub_b = priv_b.getPublicKey();

    const msg = Buffer.from([1, 2, 3]);

    const sig_a = priv_a.sign(msg);
    assert.lengthOf(sig_a, 64, 'signature length');

    assert(pub_a.verify(msg, sig_a));
    assert(!pub_b.verify(msg, sig_a));

    const sig_b = priv_b.sign(msg);
    assert.lengthOf(sig_b, 64, 'signature length');

    assert(pub_b.verify(msg, sig_b));
    assert(!pub_a.verify(msg, sig_b));
  });

  it('ECC key agreement work', () => {
    const priv_a = SignalClient.PrivateKey.generate();
    const priv_b = SignalClient.PrivateKey.generate();

    const pub_a = priv_a.getPublicKey();
    const pub_b = priv_b.getPublicKey();

    const shared_a = priv_a.agree(pub_b);
    const shared_b = priv_b.agree(pub_a);

    assert.deepEqual(shared_a, shared_b, 'key agreement works');
  });

  it('ECC keys roundtrip through serialization', () => {
    const key = Buffer.alloc(32, 0x40);
    const priv = SignalClient.PrivateKey.deserialize(key);
    assert(key.equals(priv.serialize()));

    const pub = priv.getPublicKey();
    const pub_bytes = pub.serialize();
    assert.lengthOf(pub_bytes, 32 + 1);

    const pub2 = SignalClient.PublicKey.deserialize(pub_bytes);

    assert.deepEqual(pub.serialize(), pub2.serialize());

    assert.deepEqual(pub.compare(pub2), 0);
    assert.deepEqual(pub2.compare(pub), 0);

    const anotherKey = SignalClient.PrivateKey.deserialize(
      Buffer.alloc(32, 0xcd)
    ).getPublicKey();
    assert.deepEqual(pub.compare(anotherKey), 1);
    assert.deepEqual(anotherKey.compare(pub), -1);

    assert.lengthOf(pub.getPublicKeyBytes(), 32);
  });

  it('decoding invalid ECC key throws an error', () => {
    const invalid_key = Buffer.alloc(33, 0xab);

    assert.throws(() => {
      SignalClient.PrivateKey.deserialize(invalid_key);
    }, 'bad key length <33> for key with type <Curve25519>');

    assert.throws(() => {
      SignalClient.PublicKey.deserialize(invalid_key);
    }, 'bad key type <0xab>');
  });
});
