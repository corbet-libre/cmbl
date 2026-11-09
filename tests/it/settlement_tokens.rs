//! Real maintained RFC9474/PSS and Ed25519 vectors. These prove only the token
//! primitive, not native Deposit verification, issuance quota or daily freeze.
use blind_rsa_signatures::{DefaultRng, KeyPair, PSS, Randomized, Sha384};
use cmbl::settlement::{Epoch, PreparedToken, Purpose, Request, Verifier};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn epoch(public_key_der: Vec<u8>) -> Epoch {
    Epoch {
        purpose: Purpose::OutcomeDeposit,
        community: "test".into(),
        epoch: 1,
        valid_from: 50,
        valid_until: 500,
        public_key_der,
    }
}
fn request() -> Request {
    Request {
        deposit: [7; 32],
        operation: [9; 16],
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_token_binds_deposit_epoch_request_and_exclusive_time() {
    let pair = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 3072).unwrap();
    let epoch = epoch(pair.pk.to_der().unwrap());
    let prepared = PreparedToken::new(&epoch, request().deposit, 100).unwrap();
    let blind = prepared.request();
    assert_eq!(blind.context, epoch.context().unwrap());
    assert_eq!(blind.blinded.len(), 384);
    let value = serde_json::to_value(&blind).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["blinded", "context"]
    );
    let signature = pair.sk.blind_sign(&blind.blinded).unwrap();
    let client = prepared.finalize(&signature.0, 100).unwrap();
    let verifier = Verifier::new(epoch.clone(), "boot".into()).unwrap();
    let proof = client.prove(&request(), "boot", 100).unwrap();
    let permit = verifier.verify(&proof, &request(), 100).unwrap();
    assert_eq!(permit.context(), epoch.context().unwrap());
    assert_eq!(permit.deposit(), request().deposit);
    assert_eq!(permit.epoch(), 1);
    assert_eq!(permit.valid_until(), 500);
    assert_ne!(permit.token(), [0; 32]);
    assert_eq!(
        verifier.verify(&proof, &request(), 499).unwrap().token(),
        permit.token()
    );
    assert!(verifier.verify(&proof, &request(), 49).is_err());
    assert!(verifier.verify(&proof, &request(), 500).is_err());
    assert!(client.prove(&request(), "boot", 500).is_err());
    assert!(PreparedToken::new(&epoch, request().deposit, 500).is_err());

    let mut altered = request();
    altered.deposit = [8; 32];
    assert!(client.prove(&altered, "boot", 100).is_err());
    assert!(verifier.verify(&proof, &altered, 100).is_err());
    altered = request();
    altered.operation = [10; 16];
    assert!(verifier.verify(&proof, &altered, 100).is_err());
    // A fresh possession signature permits exact-deposit reconciliation with a
    // new request. Its stable token identity cannot replenish a spent allowance.
    let retried = client.prove(&altered, "boot", 100).unwrap();
    assert_eq!(
        verifier.verify(&retried, &altered, 100).unwrap().token(),
        permit.token()
    );
    assert!(
        Verifier::new(epoch.clone(), "restart".into())
            .unwrap()
            .verify(&proof, &request(), 100)
            .is_err()
    );
    for mutation in 0..5 {
        let mut other = epoch.clone();
        match mutation {
            0 => other.community = "other".into(),
            1 => other.epoch = 2,
            2 => other.valid_from = 51,
            3 => other.valid_until = 501,
            _ => {
                other.public_key_der =
                    KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 3072)
                        .unwrap()
                        .pk
                        .to_der()
                        .unwrap()
            }
        }
        assert!(
            Verifier::new(other, "boot".into())
                .unwrap()
                .verify(&proof, &request(), 100)
                .is_err()
        );
    }
    for pointer in [
        "/token/context",
        "/token/deposit",
        "/token/possession_key",
        "/token/randomizer",
        "/token/signature",
        "/signature",
    ] {
        let mut tampered: serde_json::Value = serde_json::from_slice(&proof).unwrap();
        let bytes = tampered
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap();
        bytes[0] = serde_json::json!(bytes[0].as_u64().unwrap() ^ 1);
        assert!(
            verifier
                .verify(&serde_json::to_vec(&tampered).unwrap(), &request(), 100)
                .is_err()
        );
    }
    let mut unknown: serde_json::Value = serde_json::from_slice(&proof).unwrap();
    unknown["token"]["member"] = serde_json::json!("untrusted");
    assert!(
        verifier
            .verify(&serde_json::to_vec(&unknown).unwrap(), &request(), 100)
            .is_err()
    );
    assert!(verifier.verify(&vec![0; 8193], &request(), 100).is_err());
    assert!(verifier.verify(b"{}", &request(), 100).is_err());
    for bad in [
        Request {
            deposit: [0; 32],
            ..request()
        },
        Request {
            operation: [0; 16],
            ..request()
        },
    ] {
        assert!(verifier.verify(&proof, &bad, 100).is_err());
        assert!(client.prove(&bad, "boot", 100).is_err());
    }
    for incarnation in ["".to_owned(), "x".repeat(257)] {
        assert!(client.prove(&request(), &incarnation, 100).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cancelled_blinding_and_invalid_descriptors_never_produce_a_token() {
    let pair = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 3072).unwrap();
    let original = epoch(pair.pk.to_der().unwrap());
    drop(PreparedToken::new(&original, request().deposit, 100).unwrap());
    assert!(PreparedToken::new(&original, [0; 32], 100).is_err());
    assert!(PreparedToken::new(&original, request().deposit, 49).is_err());
    for signature in [vec![], vec![0; 383], vec![0; 384]] {
        let prepared = PreparedToken::new(&original, request().deposit, 100).unwrap();
        assert!(prepared.finalize(&signature, 100).is_err());
    }
    let prepared = PreparedToken::new(&original, request().deposit, 100).unwrap();
    let signature = pair.sk.blind_sign(&prepared.request().blinded).unwrap();
    assert!(prepared.finalize(&signature.0, 500).is_err());
    for mutation in 0..6 {
        let mut bad = original.clone();
        match mutation {
            0 => bad.epoch = 0,
            1 => bad.valid_from = 0,
            2 => bad.valid_until = bad.valid_from,
            3 => bad.community.clear(),
            4 => bad.public_key_der = vec![0; 1025],
            _ => bad.public_key_der.push(0),
        }
        assert!(bad.context().is_err());
    }
    let mut old = serde_json::to_value(&original).unwrap();
    old.as_object_mut().unwrap().remove("purpose");
    assert!(serde_json::from_value::<Epoch>(old).is_err());
    let mut wrong = serde_json::to_value(&original).unwrap();
    wrong["purpose"] = serde_json::json!("room-admission");
    assert!(serde_json::from_value::<Epoch>(wrong).is_err());
    let small = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048).unwrap();
    assert!(epoch(small.pk.to_der().unwrap()).context().is_err());
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
#[test]
fn provisioned_key_restore_matches_original_anchor_and_old_tokens_need_no_private_key() {
    use cmbl::settlement::issuer::Issuer;
    use openssl::rsa::Rsa;
    use zeroize::Zeroizing;
    let rsa = Rsa::generate(3072).unwrap();
    let private = Zeroizing::new(rsa.private_key_to_der().unwrap());
    let epoch = epoch(rsa.public_key_to_der().unwrap());
    let issuer = Issuer::from_pkcs1_der(epoch.clone(), &private).unwrap();
    assert!(issuer.epoch() == &epoch);
    let prepared = PreparedToken::new(&epoch, request().deposit, 100).unwrap();
    let blind = prepared.request();
    let signature = issuer.sign(&blind, 100).unwrap();
    let client = prepared.finalize(&signature, 100).unwrap();
    let proof = client.prove(&request(), "boot", 100).unwrap();
    drop(issuer);
    // Key loss does not invalidate a previously authenticated public descriptor
    // or its already-issued token. No replacement issuance is implied.
    let verifier = Verifier::new(epoch.clone(), "boot".into()).unwrap();
    assert!(verifier.verify(&proof, &request(), 499).is_ok());
    assert!(verifier.verify(&proof, &request(), 500).is_err());
    let restored = Issuer::from_pkcs1_der(epoch.clone(), &private).unwrap();
    assert_eq!(restored.sign(&blind, 100).unwrap(), signature);
    assert!(restored.sign(&blind, 500).is_err());
    for mutation in 0..4 {
        let mut bad = blind.clone();
        match mutation {
            0 => bad.context = [0; 32],
            1 => bad.blinded.truncate(383),
            2 => bad.blinded.fill(0),
            _ => bad.blinded.fill(255),
        }
        assert!(restored.sign(&bad, 100).is_err());
    }
    assert!(matches!(
        Issuer::from_pkcs1_der(epoch.clone(), &vec![0; 4097]),
        Err(cmbl::Error::Invalid)
    ));
    assert!(Issuer::from_pkcs1_der(epoch.clone(), &[]).is_err());
    let other = Rsa::generate(3072).unwrap();
    let other_private = Zeroizing::new(other.private_key_to_der().unwrap());
    assert!(Issuer::from_pkcs1_der(epoch.clone(), &other_private).is_err());
    let mut replaced = epoch.clone();
    replaced.public_key_der = other.public_key_to_der().unwrap();
    assert!(Issuer::from_pkcs1_der(replaced.clone(), &private).is_err());
    assert!(
        Verifier::new(replaced, "boot".into())
            .unwrap()
            .verify(&proof, &request(), 100)
            .is_err()
    );
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
#[test]
fn room_and_outcome_transcripts_are_distinct_and_dedicated_keys_refuse_cross_use() {
    use cmbl::{Action, ProofVerifier, passes, settlement::issuer::Issuer};
    use openssl::rsa::Rsa;
    use zeroize::Zeroizing;
    let room_key = Rsa::generate(3072).unwrap();
    let deposit_key = Rsa::generate(3072).unwrap();
    let room_epoch = passes::Epoch {
        community: "test".into(),
        epoch: 1,
        valid_from: 50,
        valid_until: 500,
        public_key_der: room_key.public_key_to_der().unwrap(),
    };
    let settlement_epoch = epoch(deposit_key.public_key_to_der().unwrap());
    assert_ne!(room_epoch.public_key_der, settlement_epoch.public_key_der);
    assert_ne!(
        room_epoch.context().unwrap(),
        settlement_epoch.context().unwrap()
    );
    let room_issuer = passes::issuer::Issuer::from_pkcs1_der(
        room_epoch.clone(),
        &Zeroizing::new(room_key.private_key_to_der().unwrap()),
    )
    .unwrap();
    let settlement_issuer = Issuer::from_pkcs1_der(
        settlement_epoch.clone(),
        &Zeroizing::new(deposit_key.private_key_to_der().unwrap()),
    )
    .unwrap();
    let room = passes::PreparedPass::new(&room_epoch, [1; 16], 100).unwrap();
    let outcome = PreparedToken::new(&settlement_epoch, request().deposit, 100).unwrap();
    assert!(
        room_issuer
            .sign(
                &passes::BlindRequest {
                    context: outcome.request().context,
                    blinded: outcome.request().blinded
                },
                100
            )
            .is_err()
    );
    assert!(
        settlement_issuer
            .sign(
                &cmbl::settlement::BlindRequest {
                    context: room.request().context,
                    blinded: room.request().blinded
                },
                100
            )
            .is_err()
    );
    // Relabelling the visible context cannot defeat the distinct private keys.
    let foreign = room_issuer
        .sign(
            &passes::BlindRequest {
                context: room_epoch.context().unwrap(),
                blinded: outcome.request().blinded,
            },
            100,
        )
        .unwrap();
    assert!(outcome.finalize(&foreign, 100).is_err());
    let signature = room_issuer.sign(&room.request(), 100).unwrap();
    let client = room.finalize(&signature, 100).unwrap();
    let original = cmbl::Request {
        room: [1; 16],
        operation: [3; 16],
        action: Action::Resume {
            connection: client.connection(),
        },
    };
    let room_proof = client.prove(&original, "boot", 100).unwrap();
    assert!(
        passes::Verifier::new(room_epoch, "boot".into())
            .unwrap()
            .verify(&room_proof, &original, 100)
            .is_ok()
    );
    assert!(
        Verifier::new(settlement_epoch, "boot".into())
            .unwrap()
            .verify(&room_proof, &request(), 100)
            .is_err()
    );
}
