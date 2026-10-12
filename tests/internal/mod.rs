use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl cmmr::Clock for Time {
    fn now(&self) -> std::result::Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
fn setup() -> (Assembly<InterleavedStore>, Time) {
    let time = Time(Arc::new(AtomicU64::new(100)));
    let memory = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("test", "boot").unwrap(),
            cmmr::Limits {
                records: 20,
                value_bytes: 100_000,
                batch: 10,
                indexes_per_record: 0,
                page: 10,
                ttl_ms: 10_000,
            },
            time.clone(),
        )
        .unwrap(),
    );
    (
        Assembly::new(
            InterleavedStore {
                memory,
                race: AtomicU8::new(0),
            },
            "test".into(),
            "boot".into(),
            Limits {
                connections: 2,
                relay_messages: 2,
                message_bytes: 100,
                lifetime_ms: 1_000,
                proof_bytes: 1_000,
                operation_receipts: 32,
            },
        )
        .unwrap(),
        time,
    )
}
fn request(op: u8, action: Action) -> Request {
    Request {
        room: [1; 16],
        operation: [op; 16],
        action,
    }
}
// Internal preconditions only. This is not an anonymous proof implementation,
// is unavailable outside cfg(test), and establishes no authentication evidence.
struct Preconditions;
impl ProofVerifier for Preconditions {
    fn verify(&self, _: &[u8], r: &Request, _: u64) -> Result<Permit> {
        Ok(Permit {
            room: r.room,
            incarnation: "boot".into(),
            community: "test".into(),
            request: digest(r)?,
            valid_until: 5_000,
            connection: match r.action {
                Action::Resume { connection }
                | Action::Connect { connection }
                | Action::Renew { connection }
                | Action::Disconnect { connection } => connection,
                _ => [1; 16],
            },
            resume_counter: Some(8),
        })
    }
}
struct Gate(Option<PortalRole>);
impl PortalGate for Gate {
    fn role(&self) -> Option<PortalRole> {
        self.0.clone()
    }
}

async fn execute<S: Store>(a: &Assembly<S>, r: &Request) -> Result<Outcome> {
    a.execute(r, &[], &Preconditions, 100).await
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_memory_order_replay_expiry_and_restart() {
    futures::executor::block_on(async {
        let (a, time) = setup();
        let resume = request(
            1,
            Action::Resume {
                connection: [1; 16],
            },
        );
        assert_eq!(
            a.execute(&resume, &[], &UnavailableProofs, 100).await,
            Err(Error::ProofUnavailable)
        );
        assert!(a.store.get(&hex(&[1; 16])).await.unwrap().is_none());
        assert_eq!(a.handover(&[]), Err(Error::ProofUnavailable));
        assert_eq!(execute(&a, &resume).await.unwrap().counter, 8);
        let order = request(
            2,
            Action::Order {
                expected: 8,
                ciphertext: vec![1, 2, 3],
            },
        );
        let first = execute(&a, &order).await.unwrap();
        assert_eq!(first.counter, 9);
        assert_eq!(
            a.traffic(&[1; 16], &Gate(Some(PortalRole::Root)), 100)
                .await
                .unwrap()
                .unwrap()
                .traffic_bytes,
            3
        );
        assert_eq!(
            a.traffic(&[1; 16], &Gate(None), 100).await,
            Err(Error::Refused)
        );
        assert_eq!(execute(&a, &order).await.unwrap(), first);
        let conflict = request(
            3,
            Action::Order {
                expected: 8,
                ciphertext: vec![4],
            },
        );
        assert_eq!(execute(&a, &conflict).await, Err(Error::Conflict));
        assert_eq!(
            execute(
                &a,
                &request(
                    2,
                    Action::Relay {
                        ciphertext: vec![4]
                    }
                )
            )
            .await,
            Err(Error::Conflict)
        );
        let row = a.store.get(&hex(&[1; 16])).await.unwrap().unwrap();
        let room: Room = postcard::from_bytes(&row.value).unwrap();
        assert_eq!(room.frames[0].ciphertext, vec![1, 2, 3]);
        assert_eq!(room.frames[0].counter, 9);
        assert!(row.indexes.is_empty());
        time.0.store(1_100, Ordering::SeqCst);
        assert_eq!(
            a.execute(&order, &[], &Preconditions, 1_100).await,
            Err(Error::ResumeRequired)
        );
        let (b, _) = setup();
        assert_eq!(execute(&b, &order).await, Err(Error::ResumeRequired));
        assert_eq!(execute(&b, &resume).await.unwrap().counter, 8);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn connections_and_bounded_relay() {
    futures::executor::block_on(async {
        let (a, _) = setup();
        execute(
            &a,
            &request(
                1,
                Action::Resume {
                    connection: [1; 16],
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            execute(
                &a,
                &request(
                    2,
                    Action::Resume {
                        connection: [1; 16]
                    }
                )
            )
            .await,
            Err(Error::Conflict)
        );
        assert_eq!(
            execute(
                &a,
                &request(
                    2,
                    Action::Connect {
                        connection: [1; 16]
                    }
                )
            )
            .await,
            Err(Error::Conflict)
        );
        assert_eq!(
            execute(
                &a,
                &request(
                    2,
                    Action::Connect {
                        connection: [2; 16]
                    }
                )
            )
            .await
            .unwrap()
            .active_connections,
            2
        );
        assert_eq!(
            execute(
                &a,
                &request(
                    3,
                    Action::Connect {
                        connection: [3; 16]
                    }
                )
            )
            .await,
            Err(Error::Capacity)
        );
        execute(
            &a,
            &request(
                3,
                Action::Renew {
                    connection: [1; 16],
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            execute(
                &a,
                &request(
                    4,
                    Action::Renew {
                        connection: [3; 16]
                    }
                )
            )
            .await,
            Err(Error::Refused)
        );
        assert_eq!(
            execute(
                &a,
                &request(
                    4,
                    Action::Disconnect {
                        connection: [3; 16]
                    }
                )
            )
            .await,
            Err(Error::Refused)
        );
        for bytes in [vec![], vec![0; 101]] {
            assert_eq!(
                execute(&a, &request(4, Action::Relay { ciphertext: bytes })).await,
                Err(Error::Invalid)
            );
        }
        for op in [4, 5] {
            execute(
                &a,
                &request(
                    op,
                    Action::Relay {
                        ciphertext: vec![op],
                    },
                ),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            execute(
                &a,
                &request(
                    6,
                    Action::Relay {
                        ciphertext: vec![9]
                    }
                )
            )
            .await,
            Err(Error::Capacity)
        );
        assert_eq!(
            execute(
                &a,
                &request(
                    6,
                    Action::Disconnect {
                        connection: [2; 16]
                    }
                )
            )
            .await
            .unwrap()
            .active_connections,
            1
        );
        assert_eq!(
            execute(
                &a,
                &request(
                    7,
                    Action::Disconnect {
                        connection: [1; 16]
                    }
                )
            )
            .await
            .unwrap()
            .active_connections,
            0
        );
        assert!(a.store.get(&hex(&[1; 16])).await.unwrap().is_none());
    });
}

struct Altered(u8);
impl ProofVerifier for Altered {
    fn verify(&self, p: &[u8], r: &Request, now: u64) -> Result<Permit> {
        let mut proof = Preconditions.verify(p, r, now)?;
        match self.0 {
            0 => proof.room = [9; 16],
            1 => proof.community = "wrong".into(),
            2 => proof.incarnation = "old".into(),
            3 => proof.request = [9; 32],
            4 => proof.valid_until = now,
            _ => proof.resume_counter = None,
        };
        Ok(proof)
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scope_and_freshness_fail_before_storage() {
    futures::executor::block_on(async {
        let (a, _) = setup();
        let r = request(
            1,
            Action::Resume {
                connection: [1; 16],
            },
        );
        for n in 0..6 {
            assert_eq!(
                a.execute(&r, &[], &Altered(n), 100).await,
                Err(Error::Refused)
            );
        }
        assert_eq!(
            a.execute(
                &request(
                    0,
                    Action::Resume {
                        connection: [1; 16]
                    }
                ),
                &[],
                &Preconditions,
                100
            )
            .await,
            Err(Error::Invalid)
        );
        assert_eq!(
            a.execute(&r, &vec![0; 1001], &Preconditions, 100).await,
            Err(Error::Invalid)
        );
        assert!(a.store.get(&hex(&[1; 16])).await.unwrap().is_none());
        a.store.close();
        assert_eq!(execute(&a, &r).await, Err(Error::Storage));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn limits_are_checked_before_opening() {
    for field in 0..6 {
        let (a, _) = setup();
        let mut limits = a.limits;
        match field {
            0 => limits.connections = 0,
            1 => limits.relay_messages = 0,
            2 => limits.message_bytes = 0,
            3 => limits.lifetime_ms = 0,
            4 => limits.proof_bytes = 0,
            _ => limits.operation_receipts = 0,
        }
        assert!(matches!(
            Assembly::new(a.store, "test".into(), "boot".into(), limits),
            Err(Error::Invalid)
        ));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_storage_refuses_corruption_and_impossible_deadline() {
    futures::executor::block_on(async {
        let (a, _) = setup();
        let r = request(
            1,
            Action::Resume {
                connection: [1; 16],
            },
        );
        let mut p = Preconditions.verify(&[], &r, 100).unwrap();
        p.valid_until = u64::MAX;
        assert_eq!(a.apply(&r, p, u64::MAX).await, Err(Error::Invalid));
        execute(&a, &r).await.unwrap();
        let mut record = a.store.get(&hex(&[1; 16])).await.unwrap().unwrap();
        let old = record.revision;
        record.revision = Revision([9; 16]);
        record.value = vec![255];
        a.store
            .compare_exchange(&[Write {
                expected: Some(old),
                record,
            }])
            .await
            .unwrap();
        assert_eq!(
            execute(
                &a,
                &request(
                    2,
                    Action::Relay {
                        ciphertext: vec![1]
                    }
                )
            )
            .await,
            Err(Error::Storage)
        );
        let (mut a, _) = setup();
        a.limits.lifetime_ms = 20_000;
        let mut p = Preconditions.verify(&[], &r, 100).unwrap();
        p.valid_until = 100_000;
        assert_eq!(a.apply(&r, p, 100).await, Err(Error::Storage));
    });
}

// Fault scheduling wraps the actual store. It causes real CAS conflicts and
// delayed-delete races; it does not replace room decisions or storage logic.
struct InterleavedStore {
    memory: Arc<cmmr::Memory<Time>>,
    race: AtomicU8,
}
impl Store for InterleavedStore {
    fn state(&self) -> cmmr::State {
        self.memory.state()
    }
    async fn get(&self, key: &str) -> std::result::Result<Option<Record>, cmmr::Error> {
        self.memory.get(key).await
    }
    async fn compare_exchange(&self, batch: &[Write]) -> std::result::Result<(), cmmr::Error> {
        if self.race.swap(0, Ordering::SeqCst) == 1 {
            let mut record = batch[0].record.clone();
            record.revision = Revision([99; 16]);
            record.generation = "competing".into();
            self.memory
                .compare_exchange(&[Write {
                    expected: batch[0].expected,
                    record,
                }])
                .await?;
        }
        self.memory.compare_exchange(batch).await
    }
    async fn delete_generation(&self, generation: &str) -> std::result::Result<usize, cmmr::Error> {
        match self.race.swap(0, Ordering::SeqCst) {
            2 => {
                let mut record = self.memory.get(&hex(&[1; 16])).await?.unwrap();
                let expected = record.revision;
                record.revision = Revision([99; 16]);
                record.generation = "newer-connection".into();
                self.memory
                    .compare_exchange(&[Write {
                        expected: Some(expected),
                        record,
                    }])
                    .await?;
            }
            3 => self.memory.close(),
            _ => {}
        }
        self.memory.delete_generation(generation).await
    }
    async fn page(
        &self,
        index: &str,
        cursor: Option<&cmmr::Cursor>,
        limit: usize,
    ) -> std::result::Result<cmmr::Page, cmmr::Error> {
        self.memory.page(index, cursor, limit).await
    }
    async fn maintain(&self) -> std::result::Result<usize, cmmr::Error> {
        self.memory.maintain().await
    }
    fn close(&self) {
        self.memory.close()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_cas_and_generation_races_do_not_remove_a_new_room() {
    futures::executor::block_on(async {
        for race in 1..=3 {
            let (a, _) = setup();
            execute(
                &a,
                &request(
                    1,
                    Action::Resume {
                        connection: [1; 16],
                    },
                ),
            )
            .await
            .unwrap();
            a.store.race.store(race, Ordering::SeqCst);
            let action = if race == 1 {
                Action::Relay {
                    ciphertext: vec![3],
                }
            } else {
                Action::Disconnect {
                    connection: [1; 16],
                }
            };
            let expected = if race == 3 {
                Error::Storage
            } else {
                Error::Conflict
            };
            assert_eq!(execute(&a, &request(2, action)).await, Err(expected));
            if race == 2 {
                assert_eq!(
                    a.store.get(&hex(&[1; 16])).await.unwrap().unwrap().revision,
                    Revision([99; 16])
                );
            }
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn room_scoped_generations_and_frame_expiry() {
    futures::executor::block_on(async {
        let (a, time) = setup();
        execute(
            &a,
            &request(
                1,
                Action::Resume {
                    connection: [1; 16],
                },
            ),
        )
        .await
        .unwrap();
        let mut other = request(
            1,
            Action::Resume {
                connection: [1; 16],
            },
        );
        other.room = [2; 16];
        execute(&a, &other).await.unwrap();
        execute(
            &a,
            &request(
                2,
                Action::Relay {
                    ciphertext: vec![1],
                },
            ),
        )
        .await
        .unwrap();
        time.0.store(600, Ordering::SeqCst);
        a.execute(
            &request(
                3,
                Action::Renew {
                    connection: [1; 16],
                },
            ),
            &[],
            &Preconditions,
            600,
        )
        .await
        .unwrap();
        time.0.store(1100, Ordering::SeqCst);
        a.execute(
            &request(
                4,
                Action::Renew {
                    connection: [1; 16],
                },
            ),
            &[],
            &Preconditions,
            1100,
        )
        .await
        .unwrap();
        let row = a.store.get(&hex(&[1; 16])).await.unwrap().unwrap();
        let room: Room = postcard::from_bytes(&row.value).unwrap();
        assert!(room.frames.is_empty());
        // Recreate the second room after TTL, then use the same operation in both.
        other.operation = [4; 16];
        a.execute(&other, &[], &Preconditions, 1100).await.unwrap();
        a.execute(
            &request(
                5,
                Action::Disconnect {
                    connection: [1; 16],
                },
            ),
            &[],
            &Preconditions,
            1100,
        )
        .await
        .unwrap();
        assert!(a.store.get(&hex(&[2; 16])).await.unwrap().is_some());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounded_reads_report_expiry_gaps_without_attendance_identity() {
    futures::executor::block_on(async {
        let (a, time) = setup();
        execute(
            &a,
            &request(
                1,
                Action::Resume {
                    connection: [1; 16],
                },
            ),
        )
        .await
        .unwrap();
        let empty = execute(&a, &request(9, Action::Read { after: 0 }))
            .await
            .unwrap();
        assert!(!empty.gap);
        assert!(empty.frames.is_empty());
        execute(
            &a,
            &request(
                2,
                Action::Relay {
                    ciphertext: vec![8],
                },
            ),
        )
        .await
        .unwrap();
        execute(
            &a,
            &request(
                3,
                Action::Order {
                    expected: 8,
                    ciphertext: vec![9, 10],
                },
            ),
        )
        .await
        .unwrap();
        let all = execute(&a, &request(9, Action::Read { after: 0 }))
            .await
            .unwrap();
        assert_eq!(all.through, 2);
        assert!(!all.gap);
        assert_eq!(all.frames.len(), 2);
        assert_eq!(all.frames[1].sequence, 2);
        assert_eq!(all.frames[1].counter, 9);
        assert_eq!(format!("{:?}", all.frames[1]), "RelayFrame([redacted])");
        let suffix = execute(&a, &request(9, Action::Read { after: 1 }))
            .await
            .unwrap();
        assert_eq!(suffix.frames.len(), 1);
        assert!(
            execute(&a, &request(9, Action::Read { after: 2 }))
                .await
                .unwrap()
                .frames
                .is_empty()
        );
        assert_eq!(
            execute(&a, &request(9, Action::Read { after: 3 })).await,
            Err(Error::Conflict)
        );
        time.0.store(600, Ordering::SeqCst);
        a.execute(
            &request(
                4,
                Action::Renew {
                    connection: [1; 16],
                },
            ),
            &[],
            &Preconditions,
            600,
        )
        .await
        .unwrap();
        time.0.store(1100, Ordering::SeqCst);
        let expired = a
            .execute(
                &request(9, Action::Read { after: 0 }),
                &[],
                &Preconditions,
                1100,
            )
            .await
            .unwrap();
        assert!(expired.gap);
        assert!(expired.frames.is_empty());
        a.execute(
            &request(
                5,
                Action::Relay {
                    ciphertext: vec![11],
                },
            ),
            &[],
            &Preconditions,
            1100,
        )
        .await
        .unwrap();
        let gap = a
            .execute(
                &request(9, Action::Read { after: 0 }),
                &[],
                &Preconditions,
                1100,
            )
            .await
            .unwrap();
        assert!(gap.gap);
        assert_eq!(gap.frames[0].sequence, 3);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn nonadjacent_replay_is_bounded_and_connection_loss_forgets_room() {
    futures::executor::block_on(async {
        let (a, time) = setup();
        let resume = request(
            1,
            Action::Resume {
                connection: [1; 16],
            },
        );
        execute(&a, &resume).await.unwrap();
        let relay = request(
            2,
            Action::Relay {
                ciphertext: vec![3],
            },
        );
        let first = execute(&a, &relay).await.unwrap();
        execute(
            &a,
            &request(
                3,
                Action::Renew {
                    connection: [1; 16],
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(execute(&a, &relay).await.unwrap(), first);
        assert_eq!(
            execute(
                &a,
                &request(
                    2,
                    Action::Relay {
                        ciphertext: vec![4]
                    }
                )
            )
            .await,
            Err(Error::Conflict)
        );
        time.0.store(1000, Ordering::SeqCst);
        a.execute(
            &request(
                4,
                Action::Relay {
                    ciphertext: vec![5],
                },
            ),
            &[],
            &Preconditions,
            1000,
        )
        .await
        .unwrap();
        time.0.store(1200, Ordering::SeqCst);
        assert_eq!(
            a.execute(
                &request(
                    5,
                    Action::Order {
                        expected: 8,
                        ciphertext: vec![6]
                    }
                ),
                &[],
                &Preconditions,
                1200
            )
            .await,
            Err(Error::ResumeRequired)
        );
        assert!(a.store.get(&hex(&[1; 16])).await.unwrap().is_none());
        let (mut a, _) = setup();
        a.limits.operation_receipts = 1;
        execute(&a, &resume).await.unwrap();
        assert_eq!(execute(&a, &relay).await, Err(Error::Capacity));
        assert!(
            execute(&a, &request(9, Action::Read { after: 0 }))
                .await
                .is_ok()
        );
        // If the storage clock lags the injected authority clock, stale connection
        // state is still forgotten rather than permitting a zero-connection room.
        for race in 0..=3 {
            if race == 1 {
                continue;
            }
            let (a, _) = setup();
            execute(&a, &resume).await.unwrap();
            a.store.race.store(race, Ordering::SeqCst);
            let result = a.execute(&relay, &[], &Preconditions, 1200).await;
            assert_eq!(
                result,
                Err(match race {
                    2 => Error::Conflict,
                    3 => Error::Storage,
                    _ => Error::ResumeRequired,
                })
            );
        }
    });
}

#[cfg(all(not(target_arch = "wasm32"), feature = "valkey-conformance"))]
mod valkey;

fn listing_assembly() -> Assembly<Arc<cmmr::Memory<Time>>> {
    let time = Time(Arc::new(AtomicU64::new(100)));
    let memory = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("test", "boot").unwrap(),
            cmmr::Limits {
                records: 20,
                value_bytes: 100_000,
                batch: 10,
                indexes_per_record: 1,
                page: 10,
                ttl_ms: 10_000,
            },
            time,
        )
        .unwrap(),
    );
    Assembly::new(
        memory,
        "test".into(),
        "boot".into(),
        Limits {
            connections: 2,
            relay_messages: 2,
            message_bytes: 100,
            lifetime_ms: 1_000,
            proof_bytes: 1_000,
            operation_receipts: 32,
        },
    )
    .unwrap()
}
fn listing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}
fn listing_entry(
    key: &ed25519_dalek::SigningKey,
    counter: u64,
    withdrawn: bool,
) -> listing::SignedEntry {
    listing::SignedEntry::sign(
        listing::Entry {
            key: key.verifying_key().to_bytes(),
            name: "Chess".into(),
            description: "Friendly games".into(),
            counter,
            expires_ms: 5_000,
            withdrawn,
        },
        key,
    )
    .unwrap()
}
fn listing_request(
    op: u8,
    key: &ed25519_dalek::SigningKey,
    entry: listing::SignedEntry,
) -> Request {
    Request {
        room: listing::room_id(&key.verifying_key().to_bytes()),
        operation: [op; 16],
        action: Action::Publish { entry },
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn listing_is_signed_by_the_room_key_live_only_and_never_shows_traffic() {
    futures::executor::block_on(async {
        let a = listing_assembly();
        let key = listing_key(7);
        let room = listing::room_id(&key.verifying_key().to_bytes());
        let publish = |op: u8, entry| listing_request(op, &key, entry);
        // No live room yet: a pass holder cannot list a room that is not there.
        assert_eq!(
            execute(&a, &publish(1, listing_entry(&key, 1, false))).await,
            Err(Error::Refused)
        );
        let resume = Request {
            room,
            operation: [2; 16],
            action: Action::Resume {
                connection: [1; 16],
            },
        };
        execute(&a, &resume).await.unwrap();
        let outcome = execute(&a, &publish(3, listing_entry(&key, 1, false)))
            .await
            .unwrap();
        assert_eq!(outcome.active_connections, 1);
        let page = a.list(None, 10, 100).await.unwrap();
        assert_eq!(
            page.rooms,
            vec![listing::Listed {
                room,
                name: "Chess".into(),
                description: "Friendly games".into(),
                here_now: 1,
            }]
        );
        // The same entry may be refreshed; an older or conflicting one may not replace it.
        execute(&a, &publish(4, listing_entry(&key, 1, false)))
            .await
            .unwrap();
        let mut other = listing_entry(&key, 2, false);
        other.entry.name = "Go".into();
        let other = listing::SignedEntry::sign(other.entry, &key).unwrap();
        execute(&a, &publish(5, other)).await.unwrap();
        assert_eq!(a.list(None, 10, 100).await.unwrap().rooms[0].name, "Go");
        assert_eq!(
            execute(&a, &publish(6, listing_entry(&key, 1, false))).await,
            Err(Error::Conflict)
        );
        // Another key cannot sign for this room; a forged signature is refused.
        let intruder = listing_key(8);
        assert_eq!(
            execute(&a, &publish(7, listing_entry(&intruder, 9, false))).await,
            Err(Error::Refused)
        );
        let mut forged = listing_entry(&key, 3, false);
        forged.entry.name = "Other".into();
        assert_eq!(execute(&a, &publish(8, forged)).await, Err(Error::Refused));
        // Content bounds.
        let mut long = listing_entry(&key, 3, false).entry;
        long.name = "x".repeat(listing::NAME_BYTES + 1);
        let long = listing::SignedEntry::sign(long, &key).unwrap();
        assert_eq!(execute(&a, &publish(9, long)).await, Err(Error::Invalid));
        let mut stale = listing_entry(&key, 3, false).entry;
        stale.expires_ms = 100;
        let stale = listing::SignedEntry::sign(stale, &key).unwrap();
        assert_eq!(execute(&a, &publish(10, stale)).await, Err(Error::Invalid));
        // A signed tombstone withdraws it and an older entry cannot revive it.
        execute(&a, &publish(11, listing_entry(&key, 3, true)))
            .await
            .unwrap();
        assert!(a.list(None, 10, 100).await.unwrap().rooms.is_empty());
        assert_eq!(
            execute(&a, &publish(12, listing_entry(&key, 2, false))).await,
            Err(Error::Conflict)
        );
        execute(&a, &publish(13, listing_entry(&key, 4, false)))
            .await
            .unwrap();
        assert_eq!(a.list(None, 10, 100).await.unwrap().rooms.len(), 1);
        // The listing ends with the room's last connection.
        let leave = Request {
            room,
            operation: [14; 16],
            action: Action::Disconnect {
                connection: [1; 16],
            },
        };
        execute(&a, &leave).await.unwrap();
        assert!(a.list(None, 10, 100).await.unwrap().rooms.is_empty());
        assert_eq!(a.list(None, 0, 100).await.unwrap_err(), Error::Invalid);
        assert!(a.with_listing_ttl(0).is_err());
    });
}
