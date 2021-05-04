//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod support;

use futures::executor::block_on;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use std::convert::TryFrom;
use support::*;

#[test]
#[allow(clippy::eval_order_dependence)]
fn test_basic_prekey_v3() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let bob_pre_key_pair = KeyPair::generate(&mut csprng);
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

        let pre_key_id = 31337;
        let signed_pre_key_id = 22;

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,                                                      // device id
            Some((pre_key_id.into(), bob_pre_key_pair.public_key)), // pre key
            signed_pre_key_id.into(),                               // signed pre key id
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        assert!(alice_store
            .load_session(&bob_address, None)
            .await?
            .is_some());
        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        let original_message = "L'homme est condamné à être libre";

        let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message).await?;

        assert_eq!(
            outgoing_message.message_type(),
            CiphertextMessageType::PreKey
        );

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message.serialize())?,
        );

        bob_store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &bob_pre_key_pair),
                None,
            )
            .await?;
        bob_store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    /*timestamp*/ 42,
                    &bob_signed_pre_key_pair,
                    &bob_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message).await?;

        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        let bobs_response = "Who watches the watchers?";

        assert!(bob_store
            .load_session(&alice_address, None)
            .await?
            .is_some());
        let bobs_session_with_alice = bob_store
            .load_session(&alice_address, None)
            .await?
            .expect("session found");
        assert_eq!(bobs_session_with_alice.session_version()?, 3);
        assert_eq!(bobs_session_with_alice.alice_base_key()?.len(), 32 + 1);

        let bob_outgoing = encrypt(&mut bob_store, &alice_address, bobs_response).await?;

        assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);

        let alice_decrypts = decrypt(&mut alice_store, &bob_address, &bob_outgoing).await?;

        assert_eq!(
            String::from_utf8(alice_decrypts).expect("valid utf8"),
            bobs_response
        );

        run_interaction(
            &mut alice_store,
            &alice_address,
            &mut bob_store,
            &bob_address,
        )
        .await?;

        let mut alice_store = support::test_in_memory_protocol_store()?;

        let bob_pre_key_pair = KeyPair::generate(&mut csprng);
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

        let pre_key_id: u32 = 31337;
        let signed_pre_key_id: u32 = 22;

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,                                                            // device id
            Some(((pre_key_id + 1).into(), bob_pre_key_pair.public_key)), // pre key,
            (signed_pre_key_id + 1).into(),
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        bob_store
            .save_pre_key(
                (pre_key_id + 1).into(),
                &PreKeyRecord::new((pre_key_id + 1).into(), &bob_pre_key_pair),
                None,
            )
            .await?;
        bob_store
            .save_signed_pre_key(
                (signed_pre_key_id + 1).into(),
                &SignedPreKeyRecord::new(
                    (signed_pre_key_id + 1).into(),
                    /*timestamp*/ 42,
                    &bob_signed_pre_key_pair,
                    &bob_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message).await?;

        assert!(matches!(
            decrypt(&mut bob_store, &alice_address, &outgoing_message)
                .await
                .unwrap_err(),
            SignalProtocolError::UntrustedIdentity(a) if a == alice_address
        ));

        assert_eq!(
            bob_store
                .save_identity(
                    &alice_address,
                    alice_store
                        .get_identity_key_pair(None)
                        .await?
                        .identity_key(),
                    None,
                )
                .await?,
            true
        );

        let decrypted = decrypt(&mut bob_store, &alice_address, &outgoing_message).await?;
        assert_eq!(
            String::from_utf8(decrypted).expect("valid utf8"),
            original_message
        );

        // Sign pre-key with wrong key:
        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,                                                      // device id
            Some((pre_key_id.into(), bob_pre_key_pair.public_key)), // pre key
            signed_pre_key_id.into(),
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *alice_store
                .get_identity_key_pair(None)
                .await?
                .identity_key(),
        )?;

        assert!(process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await
        .is_err());

        Ok(())
    })
}

#[test]
#[ignore = "slow to run locally"]
#[allow(clippy::eval_order_dependence)]
fn chain_jump_over_limit() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let bob_pre_key_pair = KeyPair::generate(&mut csprng);
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

        let pre_key_id = 31337;
        let signed_pre_key_id = 22;

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,                                                      // device id
            Some((pre_key_id.into(), bob_pre_key_pair.public_key)), // pre key
            signed_pre_key_id.into(),                               // signed pre key id
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        bob_store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &bob_pre_key_pair),
                None,
            )
            .await?;
        bob_store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    /*timestamp*/ 42,
                    &bob_signed_pre_key_pair,
                    &bob_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        // Same as library consts.rs
        pub const MAX_FORWARD_JUMPS: usize = 25_000;

        for _i in 0..(MAX_FORWARD_JUMPS + 1) {
            let _msg = encrypt(
                &mut alice_store,
                &bob_address,
                "Yet another message for you",
            )
            .await?;
        }

        let too_far = encrypt(&mut alice_store, &bob_address, "Now you have gone too far").await?;

        assert!(decrypt(&mut bob_store, &alice_address, &too_far)
            .await
            .is_err());
        Ok(())
    })
}

#[test]
#[ignore = "slow to run locally"]
#[allow(clippy::eval_order_dependence)]
fn chain_jump_over_limit_with_self() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let device_id_1: DeviceId = 1.into();
        let a1_address = ProtocolAddress::new("+14151111111".to_owned(), device_id_1);
        let device_id_2: DeviceId = 2.into();
        let a2_address = ProtocolAddress::new("+14151111111".to_owned(), device_id_2);

        let mut a1_store = support::test_in_memory_protocol_store()?;
        let mut a2_store = a1_store.clone(); // same key!

        let a2_pre_key_pair = KeyPair::generate(&mut csprng);
        let a2_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let a2_signed_pre_key_public = a2_signed_pre_key_pair.public_key.serialize();
        let a2_signed_pre_key_signature = a2_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&a2_signed_pre_key_public, &mut csprng)?;

        let pre_key_id = 31337;
        let signed_pre_key_id = 22;

        let a2_pre_key_bundle = PreKeyBundle::new(
            a2_store.get_local_registration_id(None).await?.into(),
            1,                                                     // device id
            Some((pre_key_id.into(), a2_pre_key_pair.public_key)), // pre key
            signed_pre_key_id.into(),                              // signed pre key id
            a2_signed_pre_key_pair.public_key,
            a2_signed_pre_key_signature.to_vec(),
            *a2_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &a2_address,
            &mut a1_store.session_store,
            &mut a1_store.identity_store,
            &a2_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        a2_store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &a2_pre_key_pair),
                None,
            )
            .await?;
        a2_store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    /*timestamp*/ 42,
                    &a2_signed_pre_key_pair,
                    &a2_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        // Same as library consts.rs
        pub const MAX_FORWARD_JUMPS: usize = 25_000;

        for _i in 0..(MAX_FORWARD_JUMPS + 1) {
            let _msg = encrypt(
                &mut a1_store,
                &a2_address,
                "Yet another message for youself",
            )
            .await?;
        }

        let too_far = encrypt(
            &mut a1_store,
            &a2_address,
            "This is the song that never ends",
        )
        .await?;

        let ptext = decrypt(&mut a2_store, &a1_address, &too_far).await?;
        assert_eq!(
            String::from_utf8(ptext).unwrap(),
            "This is the song that never ends"
        );

        Ok(())
    })
}

#[test]
#[allow(clippy::eval_order_dependence)]
fn test_bad_signed_pre_key_signature() -> Result<(), SignalProtocolError> {
    block_on(async {
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let bob_store = support::test_in_memory_protocol_store()?;

        let mut csprng = OsRng;
        let bob_pre_key_pair = KeyPair::generate(&mut csprng);
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?
            .to_vec();

        let pre_key_id = 31337;
        let signed_pre_key_id = 22;

        for bit in 0..8 * bob_signed_pre_key_signature.len() {
            let mut bad_signature = bob_signed_pre_key_signature.clone();

            bad_signature[bit / 8] ^= 0x01u8 << (bit % 8);

            let bob_pre_key_bundle = PreKeyBundle::new(
                bob_store.get_local_registration_id(None).await?.into(),
                1,
                Some((pre_key_id.into(), bob_pre_key_pair.public_key)),
                signed_pre_key_id.into(),
                bob_signed_pre_key_pair.public_key,
                bad_signature,
                *bob_store.get_identity_key_pair(None).await?.identity_key(),
            )?;

            assert!(process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await
            .is_err());
        }

        // Finally check that the non-corrupted signature is accepted:

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,
            Some((pre_key_id.into(), bob_pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature,
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        Ok(())
    })
}

// testRepeatBundleMessageV2 cannot be represented

#[test]
#[allow(clippy::eval_order_dependence)]
fn repeat_bundle_message_v3() -> Result<(), SignalProtocolError> {
    block_on(async {
        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let mut csprng = OsRng;
        let bob_pre_key_pair = KeyPair::generate(&mut csprng);
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

        let pre_key_id = 31337;
        let signed_pre_key_id = 22;

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,                                                      // device id
            Some((pre_key_id.into(), bob_pre_key_pair.public_key)), // pre key
            signed_pre_key_id.into(),                               // signed pre key id
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        assert!(alice_store
            .load_session(&bob_address, None)
            .await?
            .is_some());
        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        let original_message = "L'homme est condamné à être libre";

        let outgoing_message1 = encrypt(&mut alice_store, &bob_address, original_message).await?;
        let outgoing_message2 = encrypt(&mut alice_store, &bob_address, original_message).await?;

        assert_eq!(
            outgoing_message1.message_type(),
            CiphertextMessageType::PreKey
        );
        assert_eq!(
            outgoing_message2.message_type(),
            CiphertextMessageType::PreKey
        );

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message1.serialize())?,
        );

        bob_store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &bob_pre_key_pair),
                None,
            )
            .await?;
        bob_store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    /*timestamp*/ 42,
                    &bob_signed_pre_key_pair,
                    &bob_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message).await?;
        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        let bob_outgoing = encrypt(&mut bob_store, &alice_address, original_message).await?;
        assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);
        let alice_decrypts = decrypt(&mut alice_store, &bob_address, &bob_outgoing).await?;
        assert_eq!(
            String::from_utf8(alice_decrypts).expect("valid utf8"),
            original_message
        );

        // The test

        let incoming_message2 = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message2.serialize())?,
        );

        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message2).await?;
        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        let bob_outgoing = encrypt(&mut bob_store, &alice_address, original_message).await?;
        let alice_decrypts = decrypt(&mut alice_store, &bob_address, &bob_outgoing).await?;
        assert_eq!(
            String::from_utf8(alice_decrypts).expect("valid utf8"),
            original_message
        );

        Ok(())
    })
}

#[test]
#[allow(clippy::eval_order_dependence)]
fn bad_message_bundle() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let bob_pre_key_pair = KeyPair::generate(&mut csprng);
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

        let pre_key_id = 31337;
        let signed_pre_key_id = 22;

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1, // device id
            Some((pre_key_id.into(), bob_pre_key_pair.public_key)),
            signed_pre_key_id.into(), // signed pre key id
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        bob_store
            .save_pre_key(
                pre_key_id.into(),
                &PreKeyRecord::new(pre_key_id.into(), &bob_pre_key_pair),
                None,
            )
            .await?;
        bob_store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    /*timestamp*/ 42,
                    &bob_signed_pre_key_pair,
                    &bob_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        assert!(alice_store
            .load_session(&bob_address, None)
            .await?
            .is_some());
        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        let original_message = "L'homme est condamné à être libre";

        assert!(bob_store.get_pre_key(pre_key_id.into(), None).await.is_ok());
        let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message).await?;

        assert_eq!(
            outgoing_message.message_type(),
            CiphertextMessageType::PreKey
        );

        let outgoing_message = outgoing_message.serialize().to_vec();

        let mut corrupted_message: Vec<u8> = outgoing_message.clone();
        corrupted_message[outgoing_message.len() - 10] ^= 1;

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(corrupted_message.as_slice())?,
        );

        assert!(decrypt(&mut bob_store, &alice_address, &incoming_message)
            .await
            .is_err());
        assert!(bob_store.get_pre_key(pre_key_id.into(), None).await.is_ok());

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message.as_slice())?,
        );

        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message).await?;

        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );
        assert!(matches!(
            bob_store
                .get_pre_key(pre_key_id.into(), None)
                .await
                .unwrap_err(),
            SignalProtocolError::InvalidPreKeyId
        ));

        Ok(())
    })
}

#[test]
#[allow(clippy::eval_order_dependence)]
fn optional_one_time_prekey() -> Result<(), SignalProtocolError> {
    block_on(async {
        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let mut csprng = OsRng;
        let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
        let bob_signed_pre_key_signature = bob_store
            .get_identity_key_pair(None)
            .await?
            .private_key()
            .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

        let signed_pre_key_id = 22;

        let bob_pre_key_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id(None).await?.into(),
            1,                        // device id
            None,                     // no pre key
            signed_pre_key_id.into(), // signed pre key id
            bob_signed_pre_key_pair.public_key,
            bob_signed_pre_key_signature.to_vec(),
            *bob_store.get_identity_key_pair(None).await?.identity_key(),
        )?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        let original_message = "L'homme est condamné à être libre";

        let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message).await?;

        assert_eq!(
            outgoing_message.message_type(),
            CiphertextMessageType::PreKey
        );

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message.serialize())?,
        );

        bob_store
            .save_signed_pre_key(
                signed_pre_key_id.into(),
                &SignedPreKeyRecord::new(
                    signed_pre_key_id.into(),
                    /*timestamp*/ 42,
                    &bob_signed_pre_key_pair,
                    &bob_signed_pre_key_signature,
                ),
                None,
            )
            .await?;

        let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message).await?;

        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        Ok(())
    })
}

#[test]
fn basic_session_v3() -> Result<(), SignalProtocolError> {
    let (alice_session, bob_session) = initialize_sessions_v3()?;
    run_session_interaction(alice_session, bob_session)?;
    Ok(())
}

#[test]
fn message_key_limits() -> Result<(), SignalProtocolError> {
    block_on(async {
        let (alice_session_record, bob_session_record) = initialize_sessions_v3()?;

        let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        alice_store
            .store_session(&bob_address, &alice_session_record, None)
            .await?;
        bob_store
            .store_session(&alice_address, &bob_session_record, None)
            .await?;

        const MAX_MESSAGE_KEYS: usize = 2000; // same value as in library
        const TOO_MANY_MESSAGES: usize = MAX_MESSAGE_KEYS + 300;

        let mut inflight = Vec::with_capacity(TOO_MANY_MESSAGES);

        for i in 0..TOO_MANY_MESSAGES {
            inflight
                .push(encrypt(&mut alice_store, &bob_address, &format!("It's over {}", i)).await?);
        }

        assert_eq!(
            String::from_utf8(decrypt(&mut bob_store, &alice_address, &inflight[1000]).await?)
                .expect("valid utf8"),
            "It's over 1000"
        );
        assert_eq!(
            String::from_utf8(
                decrypt(
                    &mut bob_store,
                    &alice_address,
                    &inflight[TOO_MANY_MESSAGES - 1]
                )
                .await?
            )
            .expect("valid utf8"),
            format!("It's over {}", TOO_MANY_MESSAGES - 1)
        );

        let err = decrypt(&mut bob_store, &alice_address, &inflight[5])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SignalProtocolError::DuplicatedMessage(2300, 5)
        ));
        Ok(())
    })
}

#[allow(clippy::needless_range_loop)]
fn run_session_interaction(
    alice_session: SessionRecord,
    bob_session: SessionRecord,
) -> Result<(), SignalProtocolError> {
    block_on(async {
        use rand::seq::SliceRandom;

        let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        alice_store
            .store_session(&bob_address, &alice_session, None)
            .await?;
        bob_store
            .store_session(&alice_address, &bob_session, None)
            .await?;

        let alice_plaintext = "This is Alice's message";
        let alice_ciphertext = encrypt(&mut alice_store, &bob_address, alice_plaintext).await?;
        let bob_decrypted = decrypt(&mut bob_store, &alice_address, &alice_ciphertext).await?;
        assert_eq!(
            String::from_utf8(bob_decrypted).expect("valid utf8"),
            alice_plaintext
        );

        let bob_plaintext = "This is Bob's reply";

        let bob_ciphertext = encrypt(&mut bob_store, &alice_address, bob_plaintext).await?;
        let alice_decrypted = decrypt(&mut alice_store, &bob_address, &bob_ciphertext).await?;
        assert_eq!(
            String::from_utf8(alice_decrypted).expect("valid utf8"),
            bob_plaintext
        );

        const ALICE_MESSAGE_COUNT: usize = 50;
        const BOB_MESSAGE_COUNT: usize = 50;

        let mut alice_messages = Vec::with_capacity(ALICE_MESSAGE_COUNT);

        for i in 0..ALICE_MESSAGE_COUNT {
            let ptext = format!("смерть за смерть {}", i);
            let ctext = encrypt(&mut alice_store, &bob_address, &ptext).await?;
            alice_messages.push((ptext, ctext));
        }

        let mut rng = rand::rngs::OsRng;

        alice_messages.shuffle(&mut rng);

        for i in 0..ALICE_MESSAGE_COUNT / 2 {
            let ptext = decrypt(&mut bob_store, &alice_address, &alice_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                alice_messages[i].0
            );
        }

        let mut bob_messages = Vec::with_capacity(BOB_MESSAGE_COUNT);

        for i in 0..BOB_MESSAGE_COUNT {
            let ptext = format!("Relax in the safety of your own delusions. {}", i);
            let ctext = encrypt(&mut bob_store, &alice_address, &ptext).await?;
            bob_messages.push((ptext, ctext));
        }

        bob_messages.shuffle(&mut rng);

        for i in 0..BOB_MESSAGE_COUNT / 2 {
            let ptext = decrypt(&mut alice_store, &bob_address, &bob_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                bob_messages[i].0
            );
        }

        for i in ALICE_MESSAGE_COUNT / 2..ALICE_MESSAGE_COUNT {
            let ptext = decrypt(&mut bob_store, &alice_address, &alice_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                alice_messages[i].0
            );
        }

        for i in BOB_MESSAGE_COUNT / 2..BOB_MESSAGE_COUNT {
            let ptext = decrypt(&mut alice_store, &bob_address, &bob_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                bob_messages[i].0
            );
        }

        Ok(())
    })
}

async fn run_interaction(
    alice_store: &mut InMemSignalProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &mut InMemSignalProtocolStore,
    bob_address: &ProtocolAddress,
) -> Result<(), SignalProtocolError> {
    let alice_ptext = "It's rabbit season";

    let alice_message = encrypt(alice_store, bob_address, alice_ptext).await?;
    assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
            .expect("valid utf8"),
        alice_ptext
    );

    let bob_ptext = "It's duck season";

    let bob_message = encrypt(bob_store, alice_address, bob_ptext).await?;
    assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
            .expect("valid utf8"),
        bob_ptext
    );

    for i in 0..10 {
        let alice_ptext = format!("A->B message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message {}", i);
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    let mut alice_ooo_messages = vec![];

    for i in 0..10 {
        let alice_ptext = format!("A->B OOO message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        alice_ooo_messages.push((alice_ptext, alice_message));
    }

    for i in 0..10 {
        let alice_ptext = format!("A->B post-OOO message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message post-OOO {}", i);
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    for (ptext, ctext) in alice_ooo_messages {
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &ctext).await?)
                .expect("valid utf8"),
            ptext
        );
    }

    Ok(())
}

#[allow(clippy::eval_order_dependence)]
async fn is_session_id_equal(
    alice_store: &dyn ProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &dyn ProtocolStore,
    bob_address: &ProtocolAddress,
) -> Result<bool, SignalProtocolError> {
    Ok(alice_store
        .load_session(bob_address, None)
        .await?
        .expect("session found")
        .alice_base_key()?
        == bob_store
            .load_session(alice_address, None)
            .await?
            .expect("session found")
            .alice_base_key()?)
}

#[test]
fn basic_simultaneous_initiate() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut csprng).await?;
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
        let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

        assert_eq!(
            message_for_bob.message_type(),
            CiphertextMessageType::PreKey
        );
        assert_eq!(
            message_for_alice.message_type(),
            CiphertextMessageType::PreKey
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let alice_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_alice.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(alice_plaintext).expect("valid utf8"),
            "hi alice"
        );

        let bob_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_bob.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "hi bob"
        );

        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );
        assert_eq!(
            bob_store
                .load_session(&alice_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let alice_response = encrypt(&mut alice_store, &bob_address, "nice to see you").await?;

        assert_eq!(
            alice_response.message_type(),
            CiphertextMessageType::Whisper
        );

        let response_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(alice_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "nice to see you"
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            true
        );

        let bob_response = encrypt(&mut bob_store, &alice_address, "you as well").await?;

        assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

        let response_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(bob_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "you as well"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            true
        );

        Ok(())
    })
}

#[test]
fn simultaneous_initiate_with_lossage() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut csprng).await?;
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
        let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

        assert_eq!(
            message_for_bob.message_type(),
            CiphertextMessageType::PreKey
        );
        assert_eq!(
            message_for_alice.message_type(),
            CiphertextMessageType::PreKey
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let bob_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_bob.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "hi bob"
        );

        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );
        assert_eq!(
            bob_store
                .load_session(&alice_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        let alice_response = encrypt(&mut alice_store, &bob_address, "nice to see you").await?;

        assert_eq!(alice_response.message_type(), CiphertextMessageType::PreKey);

        let response_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                alice_response.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "nice to see you"
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            true
        );

        let bob_response = encrypt(&mut bob_store, &alice_address, "you as well").await?;

        assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

        let response_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(bob_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "you as well"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            true
        );

        Ok(())
    })
}

#[test]
fn simultaneous_initiate_lost_message() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut csprng).await?;
        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
        let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

        assert_eq!(
            message_for_bob.message_type(),
            CiphertextMessageType::PreKey
        );
        assert_eq!(
            message_for_alice.message_type(),
            CiphertextMessageType::PreKey
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let alice_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_alice.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(alice_plaintext).expect("valid utf8"),
            "hi alice"
        );

        let bob_plaintext = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                message_for_bob.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "hi bob"
        );

        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );
        assert_eq!(
            bob_store
                .load_session(&alice_address, None)
                .await?
                .expect("session found")
                .session_version()?,
            3
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let alice_response = encrypt(&mut alice_store, &bob_address, "nice to see you").await?;

        assert_eq!(
            alice_response.message_type(),
            CiphertextMessageType::Whisper
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let bob_response = encrypt(&mut bob_store, &alice_address, "you as well").await?;

        assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

        let response_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(bob_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "you as well"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            true
        );

        Ok(())
    })
}

#[test]
fn simultaneous_initiate_repeated_messages() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        for _ in 0..15 {
            let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut csprng).await?;
            let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::PreKey
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::PreKey
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );

            let alice_plaintext = decrypt(
                &mut alice_store,
                &bob_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_alice.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(alice_plaintext).expect("valid utf8"),
                "hi alice"
            );

            let bob_plaintext = decrypt(
                &mut bob_store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store
                    .load_session(&bob_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );
            assert_eq!(
                bob_store
                    .load_session(&alice_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );
        }

        for _ in 0..50 {
            let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::Whisper
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::Whisper
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );

            let alice_plaintext = decrypt(
                &mut alice_store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    message_for_alice.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(alice_plaintext).expect("valid utf8"),
                "hi alice"
            );

            let bob_plaintext = decrypt(
                &mut bob_store,
                &alice_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store
                    .load_session(&bob_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );
            assert_eq!(
                bob_store
                    .load_session(&alice_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );
        }

        let alice_response = encrypt(&mut alice_store, &bob_address, "nice to see you").await?;

        assert_eq!(
            alice_response.message_type(),
            CiphertextMessageType::Whisper
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let bob_response = encrypt(&mut bob_store, &alice_address, "you as well").await?;

        assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

        let response_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(bob_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "you as well"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            true
        );

        Ok(())
    })
}

#[test]
fn simultaneous_initiate_lost_message_repeated_messages() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut csprng = OsRng;

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;
        let lost_message_for_bob =
            encrypt(&mut alice_store, &bob_address, "it was so long ago").await?;

        for _ in 0..15 {
            let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut csprng).await?;
            let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::PreKey
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::PreKey
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );

            let alice_plaintext = decrypt(
                &mut alice_store,
                &bob_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_alice.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(alice_plaintext).expect("valid utf8"),
                "hi alice"
            );

            let bob_plaintext = decrypt(
                &mut bob_store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store
                    .load_session(&bob_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );
            assert_eq!(
                bob_store
                    .load_session(&alice_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );
        }

        for _ in 0..50 {
            let message_for_bob = encrypt(&mut alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(&mut bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::Whisper
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::Whisper
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );

            let alice_plaintext = decrypt(
                &mut alice_store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    message_for_alice.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(alice_plaintext).expect("valid utf8"),
                "hi alice"
            );

            let bob_plaintext = decrypt(
                &mut bob_store,
                &alice_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store
                    .load_session(&bob_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );
            assert_eq!(
                bob_store
                    .load_session(&alice_address, None)
                    .await?
                    .expect("session found")
                    .session_version()?,
                3
            );

            assert_eq!(
                is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
                false
            );
        }

        let alice_response = encrypt(&mut alice_store, &bob_address, "nice to see you").await?;

        assert_eq!(
            alice_response.message_type(),
            CiphertextMessageType::Whisper
        );

        assert_eq!(
            is_session_id_equal(&alice_store, &alice_address, &bob_store, &bob_address).await?,
            false
        );

        let bob_response = encrypt(&mut bob_store, &alice_address, "you as well").await?;

        assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

        let response_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(bob_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "you as well"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            true
        );

        let blast_from_the_past = decrypt(
            &mut bob_store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                lost_message_for_bob.serialize(),
            )?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(blast_from_the_past).expect("valid utf8"),
            "it was so long ago"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            false
        );

        let bob_response = encrypt(&mut bob_store, &alice_address, "so it was").await?;

        assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

        let response_plaintext = decrypt(
            &mut alice_store,
            &bob_address,
            &CiphertextMessage::SignalMessage(SignalMessage::try_from(bob_response.serialize())?),
        )
        .await?;
        assert_eq!(
            String::from_utf8(response_plaintext).expect("valid utf8"),
            "so it was"
        );

        assert_eq!(
            is_session_id_equal(&bob_store, &bob_address, &alice_store, &alice_address).await?,
            true
        );

        Ok(())
    })
}
