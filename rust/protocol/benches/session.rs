//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion};
use futures::executor::block_on;
use libsignal_protocol::*;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn session_encrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session_record, bob_session_record) = support::initialize_sessions_v3()?;

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1);
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1);

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    block_on(alice_store.store_session(&bob_address, &alice_session_record))?;
    block_on(bob_store.store_session(&alice_address, &bob_session_record))?;

    let message_to_decrypt = block_on(support::encrypt(
        &mut alice_store,
        &bob_address,
        "a short message",
    ))?;

    c.bench_function("session decrypt first message", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            block_on(support::decrypt(
                &mut bob_store,
                &alice_address,
                &message_to_decrypt,
            ))
            .expect("success");
        })
    });

    let _ = block_on(support::decrypt(
        &mut bob_store,
        &alice_address,
        &message_to_decrypt,
    ))?;
    let message_to_decrypt = block_on(support::encrypt(
        &mut alice_store,
        &bob_address,
        "a short message",
    ))?;

    c.bench_function("session encrypt", |b| {
        b.iter(|| {
            block_on(support::encrypt(
                &mut alice_store,
                &bob_address,
                "a short message",
            ))
            .expect("success");
        })
    });
    c.bench_function("session decrypt", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            block_on(support::decrypt(
                &mut bob_store,
                &alice_address,
                &message_to_decrypt,
            ))
            .expect("success");
        })
    });

    Ok(())
}

pub fn session_encrypt_decrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session_record, bob_session_record) = support::initialize_sessions_v3()?;

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1);
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1);

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    block_on(alice_store.store_session(&bob_address, &alice_session_record))?;
    block_on(bob_store.store_session(&alice_address, &bob_session_record))?;

    c.bench_function("session encrypt+decrypt 1 way", |b| {
        b.iter(|| {
            let ctext = block_on(support::encrypt(
                &mut alice_store,
                &bob_address,
                "a short message",
            ))
            .expect("success");
            let _ptext = block_on(support::decrypt(&mut bob_store, &alice_address, &ctext))
                .expect("success");
        })
    });

    c.bench_function("session encrypt+decrypt ping pong", |b| {
        b.iter(|| {
            let ctext = block_on(support::encrypt(
                &mut alice_store,
                &bob_address,
                "a short message",
            ))
            .expect("success");
            let _ptext = block_on(support::decrypt(&mut bob_store, &alice_address, &ctext))
                .expect("success");

            let ctext = block_on(support::encrypt(
                &mut bob_store,
                &alice_address,
                "a short message",
            ))
            .expect("success");
            let _ptext = block_on(support::decrypt(&mut alice_store, &bob_address, &ctext))
                .expect("success");
        })
    });

    Ok(())
}

pub fn session_encrypt(mut c: &mut Criterion) {
    session_encrypt_result(&mut c).expect("success");
}

pub fn session_encrypt_decrypt(mut c: &mut Criterion) {
    session_encrypt_decrypt_result(&mut c).expect("success");
}

criterion_group!(benches, session_encrypt, session_encrypt_decrypt);

criterion_main!(benches);
