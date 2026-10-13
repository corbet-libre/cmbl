#![cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
//! Actual OpenSSL issuer, RFC9474 client and shared Memory atomic budget.
use cmbl::{
    Error,
    passes::{PreparedPass, Verifier, issuer::BudgetedIssuer},
};
use cmmr::{Record, Revision, Store, Write};
use std::sync::{Arc, Barrier};

struct Time;
impl cmmr::Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(100)
    }
}
fn store() -> Arc<cmmr::Memory<Time>> {
    Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("test", "quota-boot").unwrap(),
            cmmr::Limits {
                records: 16,
                value_bytes: 100_000,
                batch: 4,
                indexes_per_record: 0,
                page: 8,
                ttl_ms: 10_000,
            },
            Time,
        )
        .unwrap(),
    )
}
async fn create(
    store: Arc<cmmr::Memory<Time>>,
    epoch: u64,
    quota: u16,
) -> BudgetedIssuer<Arc<cmmr::Memory<Time>>> {
    BudgetedIssuer::create(store, "test".into(), epoch, 50, 500, quota)
        .await
        .unwrap()
}

#[test]
fn common_allowance_exact_retry_and_epoch_loss_use_actual_crypto() {
    futures::executor::block_on(async {
        let store = store();
        for quota in [0, 1025] {
            assert!(matches!(
                BudgetedIssuer::create(store.clone(), "test".into(), 1, 50, 500, quota).await,
                Err(Error::Invalid)
            ));
        }
        let issuer = create(store.clone(), 1, 1).await;
        assert!(matches!(
            BudgetedIssuer::create(store.clone(), "test".into(), 1, 50, 500, 1).await,
            Err(Error::Conflict)
        ));
        let first = PreparedPass::new(issuer.epoch(), [1; 16], 100).unwrap();
        let request = first.request();
        let mut malformed = request.clone();
        malformed.blinded.fill(0);
        assert_eq!(
            issuer.issue("member-a", [1; 16], &malformed, 100).await,
            Err(Error::Invalid)
        );
        assert_eq!(
            issuer.issue("", [1; 16], &request, 100).await,
            Err(Error::Invalid)
        );
        assert_eq!(
            issuer.issue("member-a", [0; 16], &request, 100).await,
            Err(Error::Invalid)
        );
        malformed.context = [0; 32];
        assert_eq!(
            issuer.issue("member-a", [1; 16], &malformed, 100).await,
            Err(Error::Invalid)
        );
        let signature = issuer
            .issue("member-a", [1; 16], &request, 100)
            .await
            .unwrap();
        let shared = issuer.share(100).await.unwrap();
        assert!(shared.epoch() == issuer.epoch());
        assert!(matches!(issuer.share(500).await, Err(Error::Refused)));
        // Reopening an in-process handle retains the original key AND budget.
        // Dropping the creator cannot reset the allowance of the remaining one.
        drop(issuer);
        let issuer = shared;
        // Reconcile a discarded/lost client response without consuming another
        // allowance or generating another client key, blinding or room binding.
        assert_eq!(
            issuer
                .issue("member-a", [1; 16], &request, 100)
                .await
                .unwrap(),
            signature
        );
        let other_room = PreparedPass::new(issuer.epoch(), [2; 16], 100).unwrap();
        assert_eq!(
            issuer
                .issue("member-a", [1; 16], &other_room.request(), 100)
                .await,
            Err(Error::Conflict)
        );
        assert_eq!(
            issuer
                .issue("member-a", [2; 16], &other_room.request(), 100)
                .await,
            Err(Error::Capacity)
        );
        let other_signature = issuer
            .issue("member-b", [1; 16], &other_room.request(), 100)
            .await
            .unwrap();
        other_room.finalize(&other_signature, 100).unwrap();
        let client = first.finalize(&signature, 100).unwrap();
        let resume = cmbl::Request {
            room: [1; 16],
            operation: [3; 16],
            action: cmbl::Action::Resume {
                connection: client.connection(),
            },
        };
        let proof = client.prove(&resume, "quota-boot", 100).unwrap();
        let verifier = Verifier::new(issuer.epoch().clone(), "quota-boot".into()).unwrap();
        cmbl::ProofVerifier::verify(&verifier, &proof, &resume, 100).unwrap();
        assert_eq!(
            issuer.issue("member-a", [1; 16], &request, 500).await,
            Err(Error::Refused)
        );

        let anchor = store.get("room-pass-issuer").await.unwrap().unwrap();
        store.delete_generation(&anchor.generation).await.unwrap();
        assert!(matches!(issuer.share(100).await, Err(Error::Storage)));
        assert_eq!(
            issuer.issue("member-a", [1; 16], &request, 100).await,
            Err(Error::Storage)
        );
        assert_eq!(
            issuer.issue("new-member", [4; 16], &request, 100).await,
            Err(Error::Storage)
        );
        let replacement = create(store.clone(), 2, 1).await;
        assert_ne!(
            replacement.epoch().context().unwrap(),
            issuer.epoch().context().unwrap()
        );
        let verifier = Verifier::new(replacement.epoch().clone(), "quota-boot".into()).unwrap();
        assert!(cmbl::ProofVerifier::verify(&verifier, &proof, &resume, 100).is_err());
        // Corruption is not interpreted as an empty budget or a fresh epoch.
        let anchor = store.get("room-pass-issuer").await.unwrap().unwrap();
        let mut value = anchor.value.clone();
        value[0] ^= 1;
        store
            .compare_exchange(&[Write {
                expected: Some(anchor.revision),
                record: Record {
                    revision: Revision([99; 16]),
                    value,
                    ..anchor
                },
            }])
            .await
            .unwrap();
        let request = PreparedPass::new(replacement.epoch(), [1; 16], 100)
            .unwrap()
            .request();
        assert_eq!(
            replacement.issue("member-a", [1; 16], &request, 100).await,
            Err(Error::Storage)
        );
        assert!(matches!(replacement.share(100).await, Err(Error::Storage)));
    });
}

#[test]
fn concurrent_real_issuance_cannot_spend_one_allowance_twice() {
    let issuer = futures::executor::block_on(create(store(), 1, 1));
    let first = PreparedPass::new(issuer.epoch(), [1; 16], 100).unwrap();
    let second = PreparedPass::new(issuer.epoch(), [2; 16], 100).unwrap();
    let requests = [first.request(), second.request()];
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let tasks: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let issuer = futures::executor::block_on(issuer.share(100)).unwrap();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    futures::executor::block_on(issuer.issue(
                        "same-member",
                        [(index + 1) as u8; 16],
                        request,
                        100,
                    ))
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    for (index, result) in results.into_iter().enumerate() {
        if result.is_err() {
            assert!(matches!(result, Err(Error::Conflict | Error::Capacity)));
            assert_eq!(
                futures::executor::block_on(issuer.issue(
                    "same-member",
                    [(index + 1) as u8; 16],
                    &requests[index],
                    100
                )),
                Err(Error::Capacity)
            );
        }
    }
}
