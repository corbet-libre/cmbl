//! Real RSA blind issue/unblind and request signatures through actual Memory CAS.
//! Pure-Rust private RSA below is a test issuer only. Production uses OpenSSL.
use blind_rsa_signatures::{DefaultRng, KeyPair, PSS, Randomized, Sha384};
use cmbl::{
    Action, Assembly, Error, Limits, PortalGate, PortalRole, ProofVerifier, Request,
    passes::{Epoch, PreparedPass, Verifier},
};
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

struct Gate(Option<PortalRole>);
impl PortalGate for Gate {
    fn role(&self) -> Option<PortalRole> {
        self.0.clone()
    }
}

#[derive(Clone, Copy)]
struct Time;
impl cmmr::Clock for Time {
    fn now(&self) -> std::result::Result<u64, cmmr::Error> {
        Ok(100)
    }
}
fn assembly() -> Assembly<Arc<cmmr::Memory<Time>>> {
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("test", "boot").unwrap(),
            cmmr::Limits {
                records: 8,
                value_bytes: 100_000,
                batch: 8,
                indexes_per_record: 0,
                page: 8,
                ttl_ms: 10_000,
            },
            Time,
        )
        .unwrap(),
    );
    Assembly::new(
        store,
        "test".into(),
        "boot".into(),
        Limits {
            connections: 4,
            relay_messages: 8,
            message_bytes: 100,
            lifetime_ms: 1_000,
            proof_bytes: 8192,
            operation_receipts: 32,
        },
    )
    .unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn actual_blind_pass_binds_room_connection_request_epoch_and_restart() {
    futures::executor::block_on(async {
        let key = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 3072).unwrap();
        let epoch = Epoch {
            community: "test".into(),
            epoch: 1,
            valid_from: 50,
            valid_until: 500,
            public_key_der: key.pk.to_der().unwrap(),
        };
        let verifier = Verifier::new(epoch.clone(), "boot".into()).unwrap();
        let prepared = PreparedPass::new(&epoch, [1; 16], 100).unwrap();
        let request = prepared.request();
        assert_eq!(request.context, epoch.context().unwrap());
        assert_eq!(request.blinded.len(), 384);
        let wire = serde_json::to_value(&request).unwrap();
        let fields: Vec<_> = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(fields, vec!["blinded", "context"]);
        let signed = key.sk.blind_sign(&request.blinded).unwrap();
        let client = prepared.finalize(&signed.0, 100).unwrap();
        let resume = Request {
            room: [1; 16],
            operation: [2; 16],
            action: Action::Resume {
                connection: client.connection(),
            },
        };
        let proof = client.prove(&resume, "boot", 100).unwrap();
        let a = assembly();
        let first = a.execute(&resume, &proof, &verifier, 100).await.unwrap();
        assert_eq!(first.counter, 0);
        assert_eq!(first.active_connections, 1);
        assert_eq!(
            a.execute(&resume, &proof, &verifier, 100).await.unwrap(),
            first
        );
        let order = Request {
            room: [1; 16],
            operation: [3; 16],
            action: Action::Order {
                expected: 0,
                ciphertext: vec![1, 2, 3],
            },
        };
        let order_proof = client.prove(&order, "boot", 100).unwrap();
        assert!(verifier.verify(&proof, &order, 100).is_err());
        let result = a
            .execute(&order, &order_proof, &verifier, 100)
            .await
            .unwrap();
        assert_eq!(result.counter, 1);
        assert_eq!(result.ordering, first.ordering);
        // Members never receive the volume: it is not part of their outcome.
        assert!(!serde_json::to_string(&result).unwrap().contains("traffic"));
        let root = Gate(Some(PortalRole::Root));
        assert_eq!(
            a.traffic(&[1; 16], &root, 100)
                .await
                .unwrap()
                .unwrap()
                .traffic_bytes,
            3
        );
        let mut changed = order.clone();
        changed.operation = [4; 16];
        assert!(verifier.verify(&order_proof, &changed, 100).is_err());
        changed.room = [9; 16];
        assert!(verifier.verify(&order_proof, &changed, 100).is_err());
        assert!(client.prove(&changed, "boot", 100).is_err());
        assert!(
            Verifier::new(epoch.clone(), "next-boot".into())
                .unwrap()
                .verify(&order_proof, &order, 100)
                .is_err()
        );
        assert!(verifier.verify(&order_proof, &order, 500).is_err());
        assert!(verifier.verify(&order_proof, &order, 49).is_err());
        assert!(client.prove(&order, "boot", 500).is_err());
        assert!(PreparedPass::new(&epoch, [1; 16], 500).is_err());
        let mut altered: serde_json::Value = serde_json::from_slice(&order_proof).unwrap();
        let changed_byte = altered["pass"]["signature"][0].as_u64().unwrap() ^ 1;
        altered["pass"]["signature"][0] = serde_json::json!(changed_byte);
        assert!(
            verifier
                .verify(&serde_json::to_vec(&altered).unwrap(), &order, 100)
                .is_err()
        );
        assert!(verifier.verify(&vec![0; 8193], &order, 100).is_err());
        let foreign_connection = Request {
            action: Action::Renew {
                connection: [99; 16],
            },
            ..resume.clone()
        };
        assert!(client.prove(&foreign_connection, "boot", 100).is_err());

        // A second actual token cannot write before joining its own connection.
        let other_prepared = PreparedPass::new(&epoch, [1; 16], 100).unwrap();
        let other_signed = key
            .sk
            .blind_sign(&other_prepared.request().blinded)
            .unwrap();
        let other = other_prepared.finalize(&other_signed.0, 100).unwrap();
        let relay = Request {
            room: [1; 16],
            operation: [5; 16],
            action: Action::Relay {
                ciphertext: vec![4],
            },
        };
        assert_eq!(
            a.execute(
                &relay,
                &other.prove(&relay, "boot", 100).unwrap(),
                &verifier,
                100
            )
            .await,
            Err(Error::Refused)
        );
        let connect = Request {
            room: [1; 16],
            operation: [6; 16],
            action: Action::Connect {
                connection: other.connection(),
            },
        };
        assert_eq!(
            a.execute(
                &connect,
                &other.prove(&connect, "boot", 100).unwrap(),
                &verifier,
                100
            )
            .await
            .unwrap()
            .active_connections,
            2
        );
        a.execute(
            &relay,
            &other.prove(&relay, "boot", 100).unwrap(),
            &verifier,
            100,
        )
        .await
        .unwrap();
        let admin = Gate(Some(PortalRole::Admin {
            community: "test".into(),
        }));
        assert_eq!(
            a.traffic(&[1; 16], &admin, 100)
                .await
                .unwrap()
                .unwrap()
                .traffic_bytes,
            4
        );
        for refused in [
            Gate(None),
            Gate(Some(PortalRole::Admin {
                community: "other".into(),
            })),
        ] {
            assert_eq!(
                a.traffic(&[1; 16], &refused, 100).await,
                Err(Error::Refused)
            );
        }
        // No room, or a room whose connections have all lapsed, has no total.
        assert_eq!(a.traffic(&[9; 16], &admin, 100).await, Ok(None));
        assert_eq!(a.traffic(&[1; 16], &admin, 100_000).await, Ok(None));

        let restarted = assembly()
            .execute(&resume, &proof, &verifier, 100)
            .await
            .unwrap();
        assert_ne!(restarted.ordering, first.ordering);
        assert_eq!(restarted.counter, 0);
        // Transport reset does not assert or recover any MLS epoch/member count.
    });
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
#[test]
fn actual_openssl_issuer_has_no_ledger_and_refuses_foreign_epoch_or_malformed_blind() {
    let rsa = openssl::rsa::Rsa::generate(3072).unwrap();
    let epoch = Epoch {
        community: "test".into(),
        epoch: 7,
        valid_from: 50,
        valid_until: 500,
        public_key_der: rsa.public_key_to_der().unwrap(),
    };
    let issuer = cmbl::passes::issuer::Issuer::from_pkcs1_der(
        epoch.clone(),
        &rsa.private_key_to_der().unwrap(),
    )
    .unwrap();
    let prepared = PreparedPass::new(&epoch, [1; 16], 100).unwrap();
    let mut request = prepared.request();
    let signature = issuer.sign(&request, 100).unwrap();
    let client = prepared.finalize(&signature, 100).unwrap();
    let resume = Request {
        room: [1; 16],
        operation: [2; 16],
        action: Action::Resume {
            connection: client.connection(),
        },
    };
    let verifier = Verifier::new(epoch.clone(), "boot".into()).unwrap();
    assert!(
        verifier
            .verify(&client.prove(&resume, "boot", 100).unwrap(), &resume, 100)
            .is_ok()
    );
    assert!(issuer.sign(&request, 500).is_err());
    request.context = [0; 32];
    assert!(issuer.sign(&request, 100).is_err());
    request.context = epoch.context().unwrap();
    request.blinded.fill(0);
    assert!(issuer.sign(&request, 100).is_err());
    request.blinded = vec![255; 384];
    assert!(issuer.sign(&request, 100).is_err());
    request.blinded.pop();
    assert!(issuer.sign(&request, 100).is_err());
    let mut wrong = epoch.clone();
    wrong.epoch = 0;
    assert!(Verifier::new(wrong, "boot".into()).is_err());
    let mut wrong = epoch;
    wrong.public_key_der = vec![0; 1025];
    assert!(Verifier::new(wrong, "boot".into()).is_err());
}
