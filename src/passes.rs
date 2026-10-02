//! Admission-only RFC9474 passes. The authenticated facade owns admission and
//! issuance limits; no allocation ledger or introduction debit exists here.
//! The common epoch descriptor must come from authenticated community policy,
//! never a personalized issuer response or the anonymous peer's presentation.
use crate::{Action, Error, Id, Permit, ProofVerifier, Request, Result};
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, PSS, PublicKey, Randomized,
    Sha384, Signature,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const RSA_BYTES: usize = 384;
pub const MAX_PROOF_BYTES: usize = 8192;
type RsaPublicKey = PublicKey<Sha384, PSS, Randomized>;

/// One common RSA-3072 key per community/epoch, dedicated to room admission.
/// All times are milliseconds, matching Assembly and volatile Storage.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub community: String,
    pub epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub public_key_der: Vec<u8>,
}
impl Epoch {
    fn key(&self) -> Result<RsaPublicKey> {
        if self.public_key_der.len() > 1024 {
            return Err(Error::Invalid);
        }
        let key = RsaPublicKey::from_der(&self.public_key_der).map_err(|_| Error::Invalid)?;
        if key.to_der().map_err(|_| Error::Invalid)? != self.public_key_der {
            return Err(Error::Invalid);
        }
        let modulus = key.components().n();
        let exponent = key.components().e();
        let exponent = exponent
            .iter()
            .position(|byte| *byte != 0)
            .map(|start| &exponent[start..])
            .unwrap_or_default();
        if modulus.len() != RSA_BYTES || modulus[0] & 0x80 == 0 || exponent != [1, 0, 1] {
            return Err(Error::Invalid);
        }
        Ok(key)
    }
    pub fn context(&self) -> Result<[u8; 32]> {
        cmmr::Scope::new(&self.community, "room-pass").map_err(|_| Error::Invalid)?;
        if self.epoch == 0 || self.valid_from == 0 || self.valid_from >= self.valid_until {
            return Err(Error::Invalid);
        }
        self.key()?;
        let bytes = postcard::to_allocvec(&("cmbl.admission.epoch.v1", self))
            .map_err(|_| Error::Invalid)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
    fn check_time(&self, now: u64) -> Result<()> {
        if now < self.valid_from || now >= self.valid_until {
            return Err(Error::Refused);
        }
        Ok(())
    }
}

/// The authenticated session sends only the common context and blinded bytes.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BlindRequest {
    pub context: [u8; 32],
    pub blinded: Vec<u8>,
}

/// Private in-memory client state, neither exportable nor deserializable.
/// Drop cancels local use; authenticated issuance reconciliation belongs to Link.
pub struct PreparedPass {
    epoch: Epoch,
    room: Id,
    signer: SigningKey,
    context: [u8; 32],
    blinding: BlindingResult,
}
impl Drop for PreparedPass {
    fn drop(&mut self) {
        self.blinding.secret.0.zeroize();
    }
}
impl PreparedPass {
    pub fn new(epoch: &Epoch, room: Id, now: u64) -> Result<Self> {
        let context = epoch.context()?;
        epoch.check_time(now)?;
        if room == [0; 16] {
            return Err(Error::Invalid);
        }
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Refused)?;
        let signer = SigningKey::from_bytes(&seed);
        let message = pass_message(&context, &room, &signer.verifying_key().to_bytes())?;
        let blinding = epoch
            .key()?
            .blind(&mut DefaultRng, &message)
            .map_err(|_| Error::Refused)?;
        if blinding.secret.0.len() != RSA_BYTES
            || blinding.blind_message.0.len() != RSA_BYTES
            || blinding.msg_randomizer.is_none()
        {
            return Err(Error::Refused);
        }
        Ok(Self {
            epoch: epoch.clone(),
            room,
            signer,
            context,
            blinding,
        })
    }
    pub fn request(&self) -> BlindRequest {
        BlindRequest {
            context: self.context,
            blinded: self.blinding.blind_message.0.clone(),
        }
    }
    pub fn finalize(self, blind_signature: &[u8], now: u64) -> Result<ClientPass> {
        self.epoch.check_time(now)?;
        if blind_signature.len() != RSA_BYTES {
            return Err(Error::Invalid);
        }
        let key = self.signer.verifying_key().to_bytes();
        let message = pass_message(&self.context, &self.room, &key)?;
        let signature = self
            .epoch
            .key()?
            .finalize(
                &BlindSignature(blind_signature.to_vec()),
                &self.blinding,
                &message,
            )
            .map_err(|_| Error::Refused)?;
        Ok(ClientPass {
            signer: self.signer.clone(),
            pass: Pass {
                context: self.context,
                room: self.room,
                connection_key: key,
                randomizer: self
                    .blinding
                    .msg_randomizer
                    .as_ref()
                    .ok_or(Error::Refused)?
                    .0,
                signature: signature.0,
            },
            valid_from: self.epoch.valid_from,
            valid_until: self.epoch.valid_until,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pass {
    context: [u8; 32],
    room: Id,
    connection_key: [u8; 32],
    randomizer: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Presentation {
    pass: Pass,
    incarnation: String,
    signature: Vec<u8>,
}

/// One anonymous connection key for one room/epoch. No member identifier exists.
pub struct ClientPass {
    signer: SigningKey,
    pass: Pass,
    valid_from: u64,
    valid_until: u64,
}
impl ClientPass {
    pub fn connection(&self) -> Id {
        connection(&self.pass.connection_key)
    }
    pub fn prove(&self, request: &Request, incarnation: &str, now: u64) -> Result<Vec<u8>> {
        if now < self.valid_from || now >= self.valid_until || request.room != self.pass.room {
            return Err(Error::Refused);
        }
        check_connection(request, self.connection())?;
        let bytes = request_message(&self.pass.context, incarnation, request)?;
        let proof = serde_json::to_vec(&serde_json::json!({
            "pass": self.pass, "incarnation": incarnation,
            "signature": self.signer.sign(&bytes).to_bytes().to_vec(),
        }))
        .map_err(|_| Error::Invalid)?;
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Invalid);
        }
        Ok(proof)
    }
}

/// Independently configured verifier; peer proofs never select the trusted key.
pub struct Verifier {
    epoch: Epoch,
    context: [u8; 32],
    key: RsaPublicKey,
    incarnation: String,
}
impl Verifier {
    pub fn new(epoch: Epoch, incarnation: String) -> Result<Self> {
        cmmr::Scope::new(&epoch.community, &incarnation).map_err(|_| Error::Invalid)?;
        Ok(Self {
            context: epoch.context()?,
            key: epoch.key()?,
            epoch,
            incarnation,
        })
    }
}
impl ProofVerifier for Verifier {
    fn verify(&self, proof: &[u8], request: &Request, now: u64) -> Result<Permit> {
        self.epoch.check_time(now)?;
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Invalid);
        }
        let presentation: Presentation =
            serde_json::from_slice(proof).map_err(|_| Error::Invalid)?;
        let pass = presentation.pass;
        if presentation.incarnation != self.incarnation
            || pass.context != self.context
            || pass.room != request.room
            || pass.signature.len() != RSA_BYTES
        {
            return Err(Error::Refused);
        }
        self.key
            .verify(
                &Signature(pass.signature),
                Some(MessageRandomizer(pass.randomizer)),
                &pass_message(&pass.context, &pass.room, &pass.connection_key)?,
            )
            .map_err(|_| Error::Refused)?;
        let key = VerifyingKey::from_bytes(&pass.connection_key).map_err(|_| Error::Refused)?;
        if key.is_weak() {
            return Err(Error::Refused);
        }
        let signature = ed25519_dalek::Signature::from_slice(&presentation.signature)
            .map_err(|_| Error::Refused)?;
        key.verify_strict(
            &request_message(&pass.context, &self.incarnation, request)?,
            &signature,
        )
        .map_err(|_| Error::Refused)?;
        let connection = connection(&pass.connection_key);
        check_connection(request, connection)?;
        Ok(Permit {
            room: request.room,
            incarnation: self.incarnation.clone(),
            community: self.epoch.community.clone(),
            request: crate::digest(request)?,
            valid_until: self.epoch.valid_until,
            connection,
            // Assembly's fresh transport generation starts at zero. This is NOT
            // an authenticated MLS epoch or recovered member counter.
            resume_counter: Some(0),
        })
    }
}

fn connection(key: &[u8; 32]) -> Id {
    let digest = blake3::derive_key("cmbl anonymous connection v1", key);
    digest[..16].try_into().expect("fixed length")
}
fn check_connection(request: &Request, expected: Id) -> Result<()> {
    match request.action {
        Action::Resume { connection }
        | Action::Connect { connection }
        | Action::Renew { connection }
        | Action::Disconnect { connection }
            if connection != expected =>
        {
            Err(Error::Refused)
        }
        _ => Ok(()),
    }
}
fn pass_message(context: &[u8; 32], room: &Id, key: &[u8; 32]) -> Result<Vec<u8>> {
    postcard::to_allocvec(&("cmbl.admission.pass.v1", context, room, key))
        .map_err(|_| Error::Invalid)
}
fn request_message(context: &[u8; 32], incarnation: &str, request: &Request) -> Result<Vec<u8>> {
    if incarnation.is_empty() || incarnation.len() > 256 {
        return Err(Error::Invalid);
    }
    postcard::to_allocvec(&("cmbl.admission.request.v1", context, incarnation, request))
        .map_err(|_| Error::Invalid)
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub mod issuer;
