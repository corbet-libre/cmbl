//! Real volatile backend vector under Assembly's internal test module.
//! Permit preconditions exercise storage only, never production authorization.
use super::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
struct WallClock;
impl cmmr::Clock for WallClock {
    fn now(&self) -> std::result::Result<u64, cmmr::Error> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| cmmr::Error::Invalid)?
            .as_millis() as u64)
    }
}
fn now() -> u64 {
    cmmr::Clock::now(&WallClock).unwrap()
}
struct PermitPrecondition {
    until: u64,
}
impl ProofVerifier for PermitPrecondition {
    fn verify(&self, _: &[u8], r: &Request, _: u64) -> Result<Permit> {
        Ok(Permit {
            room: r.room,
            incarnation: "room-parity".into(),
            community: "test".into(),
            request: digest(r)?,
            valid_until: self.until,
            resume_counter: Some(8),
        })
    }
}
fn record_limits() -> cmmr::Limits {
    cmmr::Limits {
        records: 20,
        value_bytes: 100_000,
        batch: 10,
        indexes_per_record: 0,
        page: 10,
        ttl_ms: 10_000,
    }
}
fn assembly<S: Store>(store: S) -> Assembly<S> {
    Assembly::new(
        store,
        "test".into(),
        "room-parity".into(),
        Limits {
            connections: 2,
            relay_messages: 8,
            message_bytes: 100,
            lifetime_ms: 2000,
            proof_bytes: 1000,
            operation_receipts: 32,
        },
    )
    .unwrap()
}
async fn parity<S: Store>(a: Assembly<S>) {
    let started = now();
    let proofs = PermitPrecondition {
        until: started + 10_000,
    };
    a.execute(
        &request(
            1,
            Action::Resume {
                connection: [1; 16],
            },
        ),
        &[],
        &proofs,
        now(),
    )
    .await
    .unwrap();
    let relay = request(
        2,
        Action::Relay {
            ciphertext: vec![7],
        },
    );
    let original = a.execute(&relay, &[], &proofs, now()).await.unwrap();
    a.execute(
        &request(
            3,
            Action::Renew {
                connection: [1; 16],
            },
        ),
        &[],
        &proofs,
        now(),
    )
    .await
    .unwrap();
    assert_eq!(
        a.execute(&relay, &[], &proofs, now()).await.unwrap(),
        original
    );
    assert_eq!(
        a.execute(
            &request(
                2,
                Action::Relay {
                    ciphertext: vec![8]
                }
            ),
            &[],
            &proofs,
            now()
        )
        .await,
        Err(Error::Conflict)
    );
    // Relay traffic must not extend the anonymous connection's lease.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    a.execute(
        &request(
            4,
            Action::Relay {
                ciphertext: vec![9],
            },
        ),
        &[],
        &proofs,
        now(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        a.execute(
            &request(
                5,
                Action::Order {
                    expected: 8,
                    ciphertext: vec![10]
                }
            ),
            &[],
            &proofs,
            now()
        )
        .await,
        Err(Error::ResumeRequired)
    );
    assert!(a.store.get(&hex(&[1; 16])).await.unwrap().is_none());
}
#[tokio::test]
async fn real_memory_and_valkey_replay_expiry_parity() {
    let scope = cmmr::Scope::new("test", "room-parity").unwrap();
    let memory = cmmr::Memory::new(scope.clone(), record_limits(), WallClock).unwrap();
    parity(assembly(memory)).await;
    let url = std::env::var("VALKEY_URL").expect("CI must supply a disposable Valkey");
    let connection = redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let network = Arc::new(cvlk::RedisNetwork::new(connection, Duration::from_secs(5)).unwrap());
    let valkey = cvlk::Valkey::open(network, scope, record_limits(), WallClock)
        .await
        .unwrap();
    parity(assembly(valkey)).await;
}
