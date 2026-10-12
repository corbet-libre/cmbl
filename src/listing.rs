//! Public-room listing. An entry is signed by the room's own listing key and
//! the opaque room identifier is derived from that key, so the server checks
//! "signature matches room" without learning any identity. Entries live only
//! in the volatile store; members never receive traffic volume.
use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const NAME_BYTES: usize = 64;
pub const DESCRIPTION_BYTES: usize = 512;
/// A signed entry cannot be replayed beyond the expiry it carries, so a
/// tombstone that has itself expired cannot be undone by an old entry.
pub const MAX_VALIDITY_MS: u64 = 7 * 24 * 3600 * 1000;
pub const DEFAULT_TTL_MS: u64 = 24 * 3600 * 1000;
pub const MAX_PAGE: usize = 64;
const INDEX: &str = "listing";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Entry {
    /// The room's listing public key; the room id is derived from it.
    pub key: [u8; 32],
    pub name: String,
    pub description: String,
    /// Only a newer counter replaces an entry; the same entry may be refreshed.
    pub counter: u64,
    /// Absolute millisecond expiry chosen by the signer.
    pub expires_ms: u64,
    /// A signed tombstone withdraws the listing.
    pub withdrawn: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignedEntry {
    pub entry: Entry,
    pub signature: Vec<u8>,
}

/// One listed room as members see it: no traffic volume, no identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Listed {
    pub room: Id,
    pub name: String,
    pub description: String,
    pub here_now: usize,
}

pub struct ListPage {
    pub rooms: Vec<Listed>,
    pub next: Option<cmmr::Cursor>,
}

/// The opaque public-room id for a listing key.
pub fn room_id(key: &[u8; 32]) -> Id {
    let digest = blake3::derive_key("cmbl listing room id v1", key);
    digest[..16].try_into().expect("fixed length")
}

fn message(entry: &Entry) -> Result<Vec<u8>> {
    postcard::to_allocvec(&("cmbl.listing.entry.v1", entry)).map_err(|_| Error::Invalid)
}

impl SignedEntry {
    pub fn sign(entry: Entry, key: &SigningKey) -> Result<Self> {
        if entry.key != key.verifying_key().to_bytes() {
            return Err(Error::Invalid);
        }
        let signature = key.sign(&message(&entry)?).to_bytes().to_vec();
        Ok(Self { entry, signature })
    }
    pub fn room(&self) -> Id {
        room_id(&self.entry.key)
    }
    fn verify(&self) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.entry.key).map_err(|_| Error::Invalid)?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| Error::Invalid)?;
        key.verify(&message(&self.entry)?, &signature)
            .map_err(|_| Error::Refused)
    }
    fn check_content(&self, now: u64) -> Result<()> {
        let entry = &self.entry;
        let text = |value: &str, maximum: usize| {
            value.len() <= maximum && !value.chars().any(char::is_control)
        };
        if !text(&entry.name, NAME_BYTES)
            || !text(&entry.description, DESCRIPTION_BYTES)
            || (!entry.withdrawn && entry.name.trim().is_empty())
            || entry.expires_ms <= now
            || entry.expires_ms > now.saturating_add(MAX_VALIDITY_MS)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

fn key_of(room: &Id) -> String {
    format!("listing-{}", hex(room))
}

impl<S: Store> Assembly<S> {
    /// Publish, refresh, replace or withdraw (signed tombstone) the listing of
    /// the request's room. Any holder of a valid pass for a live room may
    /// submit the entry; the room's listing key alone decides its content.
    pub(crate) async fn publish(
        &self,
        request: &Request,
        permit: &Permit,
        signed: &SignedEntry,
        now: u64,
    ) -> Result<Outcome> {
        signed.verify()?;
        signed.check_content(now)?;
        if signed.room() != request.room {
            return Err(Error::Refused);
        }
        let record = self
            .store
            .get(&hex(&request.room))
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Refused)?;
        let mut room: Room = postcard::from_bytes(&record.value).map_err(|_| Error::Storage)?;
        room.connections.retain(|_, until| *until > now);
        if !room.connections.contains_key(&permit.connection) {
            return Err(Error::Refused);
        }
        let key = key_of(&request.room);
        let existing = self.store.get(&key).await.map_err(|_| Error::Storage)?;
        if let Some(record) = &existing {
            let current: SignedEntry =
                postcard::from_bytes(&record.value).map_err(|_| Error::Storage)?;
            if signed.entry.counter < current.entry.counter
                || (signed.entry.counter == current.entry.counter && signed != &current)
            {
                return Err(Error::Conflict);
            }
        }
        let deadline = now
            .saturating_add(self.listing_ttl_ms)
            .min(signed.entry.expires_ms);
        let value = postcard::to_allocvec(signed).map_err(|_| Error::Invalid)?;
        let write = Write {
            expected: existing.as_ref().map(|record| record.revision),
            record: Record {
                generation: format!("{key}-{}", hex(&request.operation)),
                key,
                revision: Revision(request.operation),
                deadline: Deadline::new(deadline).map_err(|_| Error::Invalid)?,
                value,
                indexes: vec![INDEX.into()],
            },
        };
        self.store
            .compare_exchange(&[write])
            .await
            .map_err(|error| match error {
                cmmr::Error::Conflict => Error::Conflict,
                _ => Error::Storage,
            })?;
        Ok(outcome(&room))
    }

    /// One page of live listed rooms. A room whose last connection has gone is
    /// not shown even while its entry is still within its refresh window.
    pub async fn list(
        &self,
        cursor: Option<&cmmr::Cursor>,
        limit: usize,
        now: u64,
    ) -> Result<ListPage> {
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Invalid);
        }
        let page = self
            .store
            .page(INDEX, cursor, limit)
            .await
            .map_err(|_| Error::Storage)?;
        let mut rooms = Vec::new();
        for record in &page.records {
            let signed: SignedEntry =
                postcard::from_bytes(&record.value).map_err(|_| Error::Storage)?;
            if signed.entry.withdrawn || signed.entry.expires_ms <= now {
                continue;
            }
            let id = signed.room();
            let Some(live) = self
                .store
                .get(&hex(&id))
                .await
                .map_err(|_| Error::Storage)?
            else {
                continue;
            };
            let room: Room = postcard::from_bytes(&live.value).map_err(|_| Error::Storage)?;
            let here_now = room
                .connections
                .values()
                .filter(|until| **until > now)
                .count();
            if here_now == 0 {
                continue;
            }
            rooms.push(Listed {
                room: id,
                name: signed.entry.name,
                description: signed.entry.description,
                here_now,
            });
        }
        Ok(ListPage {
            rooms,
            next: page.next,
        })
    }
}
