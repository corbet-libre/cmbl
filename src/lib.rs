//! Blind expiring room ordering. Proof construction remains an explicit gate.
#![forbid(unsafe_code)]

use cmmr::{Deadline, Record, Revision, Store, Write};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Id = [u8; 16];
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, Serialize, schemars::JsonSchema)]
pub enum Error {
    #[error("invalid room request")]
    Invalid,
    #[error("room authority refused")]
    Refused,
    #[error("proof construction unavailable")]
    ProofUnavailable,
    #[error("room ordering conflict")]
    Conflict,
    #[error("room requires verified resumption")]
    ResumeRequired,
    #[error("room capacity reached")]
    Capacity,
    #[error("volatile storage unavailable; reconcile operation")]
    Storage,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Action {
    Resume { connection: Id },
    Connect { connection: Id },
    Renew { connection: Id },
    Disconnect { connection: Id },
    Order { expected: u64, ciphertext: Vec<u8> },
    Relay { ciphertext: Vec<u8> },
    Read { after: u64 },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Request {
    pub room: Id,
    pub operation: Id,
    pub action: Action,
}

/// Only a reviewed proof adapter may create this capability. It is deliberately
/// not deserializable and has no public constructor. Missing adapters cannot
/// manufacture successful authorization by returning an asserted counter.
pub struct Permit {
    room: Id,
    incarnation: String,
    community: String,
    request: [u8; 32],
    valid_until: u64,
    resume_counter: Option<u64>,
}

pub trait ProofVerifier: Send + Sync {
    fn verify(&self, proof: &[u8], request: &Request, now: u64) -> Result<Permit>;
}

/// No production room proof construction has been accepted yet. This adapter
/// is a refusal, not a development or permissive authentication mode.
pub struct UnavailableProofs;
impl ProofVerifier for UnavailableProofs {
    fn verify(&self, _: &[u8], _: &Request, _: u64) -> Result<Permit> {
        Err(Error::ProofUnavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub connections: usize,
    pub relay_messages: usize,
    pub message_bytes: usize,
    pub lifetime_ms: u64,
    pub proof_bytes: usize,
    pub operation_receipts: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct Frame {
    sequence: u64,
    counter: u64,
    ciphertext: Vec<u8>,
    expires: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Room {
    sequence: u64,
    counter: u64,
    connections: BTreeMap<Id, u64>,
    volume: u64,
    frames: Vec<Frame>,
    receipts: BTreeMap<Id, OperationReceipt>,
}

/// Opaque retained ciphertext. Sequence is independent of the MLS-order counter.
#[derive(Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct RelayFrame {
    pub sequence: u64,
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}
impl std::fmt::Debug for RelayFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayFrame([redacted])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct Outcome {
    pub counter: u64,
    pub active_connections: usize,
    pub traffic_bytes: u64,
    pub through: u64,
    pub gap: bool,
    pub frames: Vec<RelayFrame>,
}

#[derive(Clone, Serialize, Deserialize)]
struct OperationReceipt {
    fingerprint: [u8; 32],
    expires: u64,
    counter: u64,
    connections: usize,
    volume: u64,
    through: u64,
}
impl OperationReceipt {
    fn outcome(&self) -> Outcome {
        Outcome {
            counter: self.counter,
            active_connections: self.connections,
            traffic_bytes: self.volume,
            through: self.through,
            gap: false,
            frames: vec![],
        }
    }
}

pub struct Assembly<S> {
    store: S,
    community: String,
    incarnation: String,
    limits: Limits,
}

impl<S: Store> Assembly<S> {
    pub fn new(store: S, community: String, incarnation: String, limits: Limits) -> Result<Self> {
        cmmr::Scope::new(&community, &incarnation).map_err(|_| Error::Invalid)?;
        if limits.connections == 0
            || limits.relay_messages == 0
            || limits.message_bytes == 0
            || limits.lifetime_ms == 0
            || limits.proof_bytes == 0
            || limits.operation_receipts == 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            community,
            incarnation,
            limits,
        })
    }

    pub async fn execute(
        &self,
        request: &Request,
        proof: &[u8],
        verifier: &dyn ProofVerifier,
        now: u64,
    ) -> Result<Outcome> {
        if request.operation == [0; 16] || proof.len() > self.limits.proof_bytes {
            return Err(Error::Invalid);
        }
        let permit = verifier.verify(proof, request, now)?;
        if permit.room != request.room
            || permit.community != self.community
            || permit.incarnation != self.incarnation
            || permit.request != digest(request)?
            || permit.valid_until <= now
        {
            return Err(Error::Refused);
        }
        self.apply(request, permit, now).await
    }

    async fn apply(&self, request: &Request, permit: Permit, now: u64) -> Result<Outcome> {
        let key = hex(&request.room);
        let existing = self.store.get(&key).await.map_err(|_| Error::Storage)?;
        let fingerprint = digest(request)?;
        let deadline = now
            .checked_add(self.limits.lifetime_ms)
            .ok_or(Error::Invalid)?
            .min(permit.valid_until);
        let mut room = match &existing {
            Some(record) => {
                let mut room: Room =
                    postcard::from_bytes(&record.value).map_err(|_| Error::Storage)?;
                room.connections.retain(|_, until| *until > now);
                room.frames.retain(|frame| frame.expires > now);
                if room.connections.is_empty() {
                    let deleted = self
                        .store
                        .delete_generation(&record.generation)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if deleted != 1 {
                        return Err(Error::Conflict);
                    }
                    return Err(Error::ResumeRequired);
                }
                room.receipts.retain(|_, receipt| receipt.expires > now);
                if let Some(receipt) = room.receipts.get(&request.operation) {
                    return if receipt.fingerprint == fingerprint {
                        Ok(receipt.outcome())
                    } else {
                        Err(Error::Conflict)
                    };
                }
                if matches!(request.action, Action::Resume { .. }) {
                    return Err(Error::Conflict);
                }
                room
            }
            None => {
                let Action::Resume { connection } = request.action else {
                    return Err(Error::ResumeRequired);
                };
                let counter = permit.resume_counter.ok_or(Error::Refused)?;
                Room {
                    sequence: 0,
                    counter,
                    connections: BTreeMap::from([(connection, deadline)]),
                    volume: 0,
                    frames: vec![],
                    receipts: BTreeMap::new(),
                }
            }
        };
        if !matches!(request.action, Action::Read { .. })
            && room.receipts.len() >= self.limits.operation_receipts
        {
            return Err(Error::Capacity);
        }
        match &request.action {
            Action::Read { after } => {
                if *after > room.sequence {
                    return Err(Error::Conflict);
                }
                let mut result = outcome(&room);
                let first = room
                    .frames
                    .first()
                    .map_or(room.sequence.saturating_add(1), |f| f.sequence);
                result.gap = *after < first.saturating_sub(1);
                result.frames = room
                    .frames
                    .iter()
                    .filter(|f| f.sequence > *after)
                    .map(|f| RelayFrame {
                        sequence: f.sequence,
                        counter: f.counter,
                        ciphertext: f.ciphertext.clone(),
                    })
                    .collect();
                return Ok(result);
            }
            Action::Resume { .. } => {}
            Action::Connect { connection } => {
                if room.connections.contains_key(connection) {
                    return Err(Error::Conflict);
                }
                if room.connections.len() >= self.limits.connections {
                    return Err(Error::Capacity);
                }
                room.connections.insert(*connection, deadline);
            }
            Action::Renew { connection } => {
                let until = room.connections.get_mut(connection).ok_or(Error::Refused)?;
                *until = deadline;
            }
            Action::Disconnect { connection } => {
                if room.connections.remove(connection).is_none() {
                    return Err(Error::Refused);
                }
                if room.connections.is_empty() {
                    let record = existing.as_ref().ok_or(Error::ResumeRequired)?;
                    let deleted = self
                        .store
                        .delete_generation(&record.generation)
                        .await
                        .map_err(|_| Error::Storage)?;
                    if deleted != 1 {
                        return Err(Error::Conflict);
                    }
                    return Ok(outcome(&room));
                }
            }
            Action::Order {
                expected,
                ciphertext,
            } => {
                if *expected != room.counter {
                    return Err(Error::Conflict);
                }
                room.counter = room.counter.checked_add(1).ok_or(Error::Capacity)?;
                self.append(&mut room, ciphertext, deadline)?;
            }
            Action::Relay { ciphertext } => {
                self.append(&mut room, ciphertext, deadline)?;
            }
        }
        let result = outcome(&room);
        room.receipts.insert(
            request.operation,
            OperationReceipt {
                fingerprint,
                expires: permit.valid_until,
                counter: result.counter,
                connections: result.active_connections,
                volume: result.traffic_bytes,
                through: result.through,
            },
        );
        // Physical retention cannot outlive the last anonymously renewed connection.
        let connection_deadline = room
            .connections
            .values()
            .copied()
            .max()
            .ok_or(Error::ResumeRequired)?;
        let deadline = deadline.min(connection_deadline);
        let value = postcard::to_allocvec(&room).map_err(|_| Error::Storage)?;
        let generation = format!("{key}-{}", hex(&request.operation));
        let record = Record {
            key,
            generation,
            revision: Revision(request.operation),
            deadline: Deadline::new(deadline).map_err(|_| Error::Invalid)?,
            value,
            indexes: vec![],
        };
        self.store
            .compare_exchange(&[Write {
                expected: existing.map(|r| r.revision),
                record,
            }])
            .await
            .map_err(|e| match e {
                cmmr::Error::Conflict => Error::Conflict,
                _ => Error::Storage,
            })?;
        Ok(outcome(&room))
    }

    fn append(&self, room: &mut Room, ciphertext: &[u8], expires: u64) -> Result<()> {
        if ciphertext.is_empty() || ciphertext.len() > self.limits.message_bytes {
            return Err(Error::Invalid);
        }
        if room.frames.len() >= self.limits.relay_messages {
            return Err(Error::Capacity);
        }
        room.volume = room
            .volume
            .checked_add(ciphertext.len() as u64)
            .ok_or(Error::Capacity)?;
        room.sequence = room.sequence.checked_add(1).ok_or(Error::Capacity)?;
        room.frames.push(Frame {
            sequence: room.sequence,
            counter: room.counter,
            ciphertext: ciphertext.to_vec(),
            expires,
        });
        Ok(())
    }

    /// No raw size/lineage claims can authorize a listing transfer. The missing
    /// anonymous size, age and 72-hour handover proof is an explicit refusal.
    pub fn handover(&self, _proof: &[u8]) -> Result<()> {
        Err(Error::ProofUnavailable)
    }
}

fn digest(request: &Request) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(request).map_err(|_| Error::Invalid)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
fn hex(value: &Id) -> String {
    data_encoding::HEXLOWER.encode(value)
}
fn outcome(room: &Room) -> Outcome {
    Outcome {
        counter: room.counter,
        active_connections: room.connections.len(),
        traffic_bytes: room.volume,
        through: room.sequence,
        gap: false,
        frames: vec![],
    }
}

#[cfg(test)]
#[path = "../tests/internal/mod.rs"]
mod tests;
