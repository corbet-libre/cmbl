//! One common admission allowance; the issuer never receives a room identifier.
use super::{Issuer, PKey, Rsa};
use crate::{
    Error, Id, Result,
    passes::{BlindRequest, Epoch, RSA_BYTES},
};
use cmmr::{Deadline, Record, Revision, Store, Write};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

const ANCHOR: &str = "room-pass-issuer";
const MAX_PASSES: u16 = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    fingerprint: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    context: [u8; 32],
    member: [u8; 32],
    receipts: BTreeMap<Id, Receipt>,
}

/// Single common epoch issuer, shared by the authenticated Forum service.
/// The facade must verify current admission and Throttle before every call,
/// including retries, and supply its original canonical member pseudonym.
///
/// Activation always generates a fresh dedicated key. There is no restore from
/// a key with lost quotas. All member budgets and the anchor share one original
/// Memory generation and the exact epoch deadline; valid records cannot evict.
/// Missing/corrupt anchor state refuses issuance until a new common epoch is
/// activated in a fresh service scope and its descriptor replaces the old one.
pub struct BudgetedIssuer<S> {
    signer: Arc<Issuer>,
    store: Arc<S>,
    quota: u16,
    anchor_value: Vec<u8>,
    generation: String,
}

impl<S: Store> BudgetedIssuer<S> {
    /// Exactly one activation per fresh scoped service. Never call once per
    /// member/session: every client must receive the SAME authenticated Epoch.
    /// `quota` is the original signed community setting, not a client request.
    pub async fn create(
        store: S,
        community: String,
        epoch: u64,
        valid_from: u64,
        valid_until: u64,
        quota: u16,
    ) -> Result<Self> {
        if quota == 0 || quota > MAX_PASSES {
            return Err(Error::Invalid);
        }
        let deadline = Deadline::new(valid_until).map_err(|_| Error::Invalid)?;
        let rsa = Rsa::generate(3072).map_err(|_| Error::Refused)?;
        let epoch = Epoch {
            community,
            epoch,
            valid_from,
            valid_until,
            public_key_der: rsa.public_key_to_der().map_err(|_| Error::Refused)?,
        };
        let context = epoch.context()?;
        let signer = Issuer {
            epoch,
            context,
            key: PKey::from_rsa(rsa).map_err(|_| Error::Refused)?,
        };
        let anchor_value = postcard::to_allocvec(&(context, quota)).map_err(|_| Error::Invalid)?;
        let generation = format!("room-pass-{}", data_encoding::HEXLOWER.encode(&context));
        store
            .compare_exchange(&[Write {
                expected: None,
                record: Record {
                    key: ANCHOR.into(),
                    generation: generation.clone(),
                    revision: revision()?,
                    deadline,
                    value: anchor_value.clone(),
                    indexes: vec![],
                },
            }])
            .await
            .map_err(storage_error)?;
        Ok(Self {
            signer: Arc::new(signer),
            store: Arc::new(store),
            quota,
            anchor_value,
            generation,
        })
    }

    /// Common public descriptor only; publishing it is the authenticated
    /// service's responsibility. It must never be personalized per session.
    pub fn epoch(&self) -> &Epoch {
        &self.signer.epoch
    }

    /// Open another in-process handle to this exact common issuer and Store.
    /// No key, quota or descriptor can be replaced, exported or deserialized.
    /// The original anchor must still exist and match, even when no member has
    /// spent yet. A CAS fences loss between that check and returning the handle.
    ///
    /// This is not cross-process key recovery. Deploy one issuer process for an
    /// incarnation. Losing every handle requires a fresh service incarnation,
    /// fresh key and authenticated replacement of the common descriptor before
    /// accepting new passes; `create` refuses a still-live existing anchor.
    pub async fn share(&self, now: u64) -> Result<Self> {
        self.signer.epoch.check_time(now)?;
        let mut anchor = self.anchor().await?;
        let expected = anchor.revision;
        anchor.revision = revision()?;
        self.store
            .compare_exchange(&[Write {
                expected: Some(expected),
                record: anchor,
            }])
            .await
            .map_err(storage_error)?;
        Ok(Self {
            signer: Arc::clone(&self.signer),
            store: Arc::clone(&self.store),
            quota: self.quota,
            anchor_value: self.anchor_value.clone(),
            generation: self.generation.clone(),
        })
    }

    async fn anchor(&self) -> Result<Record> {
        let anchor = self
            .store
            .get(ANCHOR)
            .await
            .map_err(storage_error)?
            .ok_or(Error::Storage)?;
        if anchor.value != self.anchor_value
            || anchor.generation != self.generation
            || anchor.deadline.unix_ms() != self.signer.epoch.valid_until
            || !anchor.indexes.is_empty()
        {
            return Err(Error::Storage);
        }
        Ok(anchor)
    }

    /// Atomically consume one total allowance or reconcile the exact previous
    /// response. No blind signature escapes before the actual Store CAS.
    pub async fn issue(
        &self,
        admitted_member: &str,
        operation: Id,
        request: &BlindRequest,
        now: u64,
    ) -> Result<Vec<u8>> {
        self.signer.epoch.check_time(now)?;
        if admitted_member.is_empty()
            || admitted_member.len() > 4096
            || operation == [0; 16]
            || request.context != self.signer.context
            || request.blinded.len() != RSA_BYTES
        {
            return Err(Error::Invalid);
        }
        let mut anchor = self.anchor().await?;
        let member = *blake3::hash(
            &postcard::to_allocvec(&("cmbl.pass.budget.v1", self.signer.context, admitted_member))
                .map_err(|_| Error::Invalid)?,
        )
        .as_bytes();
        let key = format!("pass-member-{}", data_encoding::HEXLOWER.encode(&member));
        let previous = self.store.get(&key).await.map_err(storage_error)?;
        let mut budget: Budget = match &previous {
            Some(record) => {
                if record.value.len() > 1_048_576
                    || record.generation != self.generation
                    || record.deadline != anchor.deadline
                {
                    return Err(Error::Storage);
                }
                postcard::from_bytes(&record.value).map_err(|_| Error::Storage)?
            }
            None => Budget {
                context: self.signer.context,
                member,
                receipts: BTreeMap::new(),
            },
        };
        if budget.context != self.signer.context
            || budget.member != member
            || budget.receipts.len() > usize::from(self.quota)
            || budget
                .receipts
                .iter()
                .any(|(id, r)| *id == [0; 16] || r.signature.len() != RSA_BYTES)
        {
            return Err(Error::Storage);
        }
        let fingerprint =
            *blake3::hash(&postcard::to_allocvec(request).map_err(|_| Error::Invalid)?).as_bytes();
        let signature = if let Some(receipt) = budget.receipts.get(&operation) {
            if receipt.fingerprint != fingerprint {
                return Err(Error::Conflict);
            }
            receipt.signature.clone()
        } else {
            if budget.receipts.len() >= usize::from(self.quota) {
                return Err(Error::Capacity);
            }
            let signature = self.signer.sign(request, now)?;
            budget.receipts.insert(
                operation,
                Receipt {
                    fingerprint,
                    signature: signature.clone(),
                },
            );
            signature
        };
        let old_anchor = anchor.revision;
        anchor.revision = revision()?;
        let record = Record {
            key,
            generation: self.generation.clone(),
            revision: revision()?,
            deadline: anchor.deadline,
            value: postcard::to_allocvec(&budget).map_err(|_| Error::Storage)?,
            indexes: vec![],
        };
        // Also replace the unchanged anchor under CAS. This fences a scope wipe
        // between the reads and publication, including an exact-response retry.
        self.store
            .compare_exchange(&[
                Write {
                    expected: Some(old_anchor),
                    record: anchor,
                },
                Write {
                    expected: previous.map(|p| p.revision),
                    record,
                },
            ])
            .await
            .map_err(storage_error)?;
        Ok(signature)
    }
}

fn revision() -> Result<Revision> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Storage)?;
    if bytes == [0; 16] {
        return Err(Error::Storage);
    }
    Ok(Revision(bytes))
}
fn storage_error(error: cmmr::Error) -> Error {
    match error {
        cmmr::Error::Conflict => Error::Conflict,
        _ => Error::Storage,
    }
}
