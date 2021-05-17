//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod support;
use support::*;

use futures::executor::block_on;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use std::convert::TryFrom;
use uuid::Uuid;

#[test]
fn test_server_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let serialized = server_cert.serialized()?.to_vec();

    let recovered = ServerCertificate::deserialize(&serialized)?;

    assert_eq!(recovered.validate(&trust_root.public_key)?, true);

    let mut cert_data = serialized;
    let cert_bits = cert_data.len() * 8;

    for b in 0..cert_bits {
        cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = ServerCertificate::deserialize(&cert_data);
        cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert_eq!(cert.validate(&trust_root.public_key)?, false);
            }
            Err(e) => match e {
                SignalProtocolError::InvalidProtobufEncoding
                | SignalProtocolError::ProtobufDecodingError(_)
                | SignalProtocolError::BadKeyType(_)
                | SignalProtocolError::BadKeyLength(_, _) => {}

                unexpected_err => {
                    panic!("unexpected error {:?}", unexpected_err)
                }
            },
        }
    }

    Ok(())
}

#[test]
fn test_revoked_server_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let revoked_id = 0xDEADC357;

    let server_cert = ServerCertificate::new(
        revoked_id,
        server_key.public_key,
        &trust_root.private_key,
        &mut rng,
    )?;

    let serialized = server_cert.serialized()?.to_vec();

    let recovered = ServerCertificate::deserialize(&serialized)?;

    assert_eq!(recovered.validate(&trust_root.public_key)?, false);

    Ok(())
}

#[test]
fn test_sender_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);
    let key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let device_id: DeviceId = 42.into();
    let expires = 1605722925;

    let sender_cert = SenderCertificate::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string(),
        Some("+14152222222".to_string()),
        key.public_key,
        device_id,
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )?;

    assert_eq!(sender_cert.validate(&trust_root.public_key, expires)?, true);
    assert_eq!(
        sender_cert.validate(&trust_root.public_key, expires + 1)?,
        false
    ); // expired

    let mut sender_cert_data = sender_cert.serialized()?.to_vec();
    let sender_cert_bits = sender_cert_data.len() * 8;

    for b in 0..sender_cert_bits {
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = SenderCertificate::deserialize(&sender_cert_data);
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert_eq!(cert.validate(&trust_root.public_key, expires)?, false);
            }
            Err(e) => match e {
                SignalProtocolError::InvalidProtobufEncoding
                | SignalProtocolError::ProtobufDecodingError(_)
                | SignalProtocolError::BadKeyLength(_, _)
                | SignalProtocolError::BadKeyType(_) => {}

                unexpected_err => {
                    panic!("unexpected error {:?}", unexpected_err)
                }
            },
        }
    }

    Ok(())
}

#[test]
fn test_sealed_sender() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();
        let bob_e164 = "+14151114444".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair(None).await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut rng,
            None,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = 1605722925;

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let alice_ptext = vec![1, 2, 3, 23, 99];
        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &trust_root.public_key,
            expires - 1,
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await?;

        assert_eq!(bob_ptext.message, alice_ptext);
        assert_eq!(bob_ptext.sender_uuid, alice_uuid);
        assert_eq!(bob_ptext.sender_e164, Some(alice_e164));
        assert_eq!(bob_ptext.device_id, alice_device_id);

        // Now test but with an expired cert:

        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &trust_root.public_key,
            expires + 11,
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        // Now test but try to verify using some other trust root

        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let wrong_trust_root = KeyPair::generate(&mut rng);

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &wrong_trust_root.public_key,
            expires - 1,
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        Ok(())
    })
}

#[test]
fn test_sender_key_in_sealed_sender() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let device_id: DeviceId = 1.into();
        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), device_id);
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair(None).await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut rng,
            None,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = 1605722925;

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let distribution_message = create_sender_key_distribution_message(
            &alice_uuid_address,
            distribution_id,
            &mut alice_store,
            &mut rng,
            None,
        )
        .await?;

        process_sender_key_distribution_message(
            &alice_uuid_address,
            &distribution_message,
            &mut bob_store,
            None,
        )
        .await?;

        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            "swim camp".as_bytes(),
            &mut rng,
            None,
        )
        .await?;
        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            alice_message.serialized().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let alice_ctext = sealed_sender_encrypt_from_usmc(
            &bob_uuid_address,
            &alice_usmc,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let bob_usmc =
            sealed_sender_decrypt_to_usmc(&alice_ctext, &mut bob_store.identity_store, None)
                .await?;

        assert!(matches!(
            bob_usmc.msg_type()?,
            CiphertextMessageType::SenderKey,
        ));

        let bob_plaintext = group_decrypt(
            bob_usmc.contents()?,
            &mut bob_store,
            &alice_uuid_address,
            None,
        )
        .await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid UTF-8"),
            "swim camp"
        );

        Ok(())
    })
}

#[test]
fn test_sealed_sender_multi_recipient() -> Result<(), SignalProtocolError> {
    block_on(async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();
        let bob_e164 = "+14151114444".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair(None).await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut rng,
            None,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = 1605722925;

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let alice_ptext = vec![1, 2, 3, 23, 99];
        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &[&bob_uuid_address],
            &alice_usmc,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let [bob_ctext] = <[_; 1]>::try_from(sealed_sender_multi_recipient_fan_out(&alice_ctext)?)
            .expect("only one recipient");

        let bob_ptext = sealed_sender_decrypt(
            &bob_ctext,
            &trust_root.public_key,
            expires - 1,
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await?;

        assert_eq!(bob_ptext.message, alice_ptext);
        assert_eq!(bob_ptext.sender_uuid, alice_uuid);
        assert_eq!(bob_ptext.sender_e164, Some(alice_e164));
        assert_eq!(bob_ptext.device_id, alice_device_id);

        // Now test but with an expired cert:
        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &[&bob_uuid_address],
            &alice_usmc,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let [bob_ctext] = <[_; 1]>::try_from(sealed_sender_multi_recipient_fan_out(&alice_ctext)?)
            .expect("only one recipient");

        let bob_ptext = sealed_sender_decrypt(
            &bob_ctext,
            &trust_root.public_key,
            expires + 11,
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        // Now test but try to verify using some other trust root

        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &[&bob_uuid_address],
            &alice_usmc,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let wrong_trust_root = KeyPair::generate(&mut rng);

        let [bob_ctext] = <[_; 1]>::try_from(sealed_sender_multi_recipient_fan_out(&alice_ctext)?)
            .expect("only one recipient");

        let bob_ptext = sealed_sender_decrypt(
            &bob_ctext,
            &wrong_trust_root.public_key,
            expires - 1,
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        Ok(())
    })
}
