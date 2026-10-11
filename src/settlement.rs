//! Outcome-deposit rate tokens. A verified token proves only possession of one
//! blind signature bound to a deposit digest; native Deposit verification,
//! authenticated quota issuance, replay accounting and daily freeze remain
//! responsibilities of their original owners.
use crate::{Error, Result, blind::RsaPublicKey, passes::RSA_BYTES};
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, Signature,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PROOF_BYTES: usize = 8192;

/// Required wire purpose, with no room-admission or caller-chosen alternative.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Purpose {
    #[serde(rename = "outcome-deposit-v1")]
    OutcomeDeposit,
}

/// Common authenticated descriptor for one dedicated settlement key/epoch.
/// Times are milliseconds. This key MUST differ from every room issuer key:
/// a blind signer cannot inspect the hidden purpose of its signed message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub purpose: Purpose,
    pub community: String,
    pub epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub public_key_der: Vec<u8>,
}
impl Epoch {
    pub fn context(&self) -> Result<[u8; 32]> {
        cmmr::Scope::new(&self.community, "settlement-pass").map_err(|_| Error::Invalid)?;
        if self.epoch == 0 || self.valid_from == 0 || self.valid_from >= self.valid_until {
            return Err(Error::Invalid);
        }
        self.key()?;
        let bytes = postcard::to_allocvec(&("cmbl.settlement.epoch.v1", self))
            .map_err(|_| Error::Invalid)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
    fn key(&self) -> Result<RsaPublicKey> {
        crate::blind::public_key(&self.public_key_der)
    }
    fn check_time(&self, now: u64) -> Result<()> {
        if now < self.valid_from || now >= self.valid_until {
            return Err(Error::Refused);
        }
        Ok(())
    }
}

/// The authenticated issuer sees only a common context and blinded bytes.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BlindRequest {
    pub context: [u8; 32],
    pub blinded: Vec<u8>,
}

/// Independently supplied canonical Deposit digest and opaque retry operation.
/// A token never validates the Deposit statement or its native proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub deposit: [u8; 32],
    pub operation: [u8; 16],
}
impl Request {
    fn validate(&self) -> Result<()> {
        if self.deposit == [0; 32] || self.operation == [0; 16] {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Private transient blinding and possession state; no serializer or key getter.
pub struct PreparedToken {
    epoch: Epoch,
    deposit: [u8; 32],
    signer: SigningKey,
    context: [u8; 32],
    blinding: BlindingResult,
}
impl Drop for PreparedToken {
    fn drop(&mut self) {
        self.blinding.secret.0.zeroize();
    }
}
impl PreparedToken {
    pub fn new(epoch: &Epoch, deposit: [u8; 32], now: u64) -> Result<Self> {
        let context = epoch.context()?;
        epoch.check_time(now)?;
        if deposit == [0; 32] {
            return Err(Error::Invalid);
        }
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Refused)?;
        let signer = SigningKey::from_bytes(&seed);
        let message = token_message(&context, &deposit, &signer.verifying_key().to_bytes())?;
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
            deposit,
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
    pub fn finalize(self, blind_signature: &[u8], now: u64) -> Result<ClientToken> {
        self.epoch.check_time(now)?;
        if blind_signature.len() != RSA_BYTES {
            return Err(Error::Invalid);
        }
        let key = self.signer.verifying_key().to_bytes();
        let message = token_message(&self.context, &self.deposit, &key)?;
        let signature = self
            .epoch
            .key()?
            .finalize(
                &BlindSignature(blind_signature.to_vec()),
                &self.blinding,
                &message,
            )
            .map_err(|_| Error::Refused)?;
        Ok(ClientToken {
            signer: self.signer.clone(),
            token: Token {
                context: self.context,
                deposit: self.deposit,
                possession_key: key,
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
struct Token {
    context: [u8; 32],
    deposit: [u8; 32],
    possession_key: [u8; 32],
    randomizer: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Presentation {
    token: Token,
    incarnation: String,
    signature: Vec<u8>,
}

/// One private client token bound to one canonical Deposit. The token can be
/// retried; only its owner's durable replay state can enforce one consumption.
pub struct ClientToken {
    signer: SigningKey,
    token: Token,
    valid_from: u64,
    valid_until: u64,
}
impl ClientToken {
    pub fn prove(&self, request: &Request, incarnation: &str, now: u64) -> Result<Vec<u8>> {
        request.validate()?;
        if now < self.valid_from || now >= self.valid_until || request.deposit != self.token.deposit
        {
            return Err(Error::Refused);
        }
        let message = request_message(&self.token.context, incarnation, request)?;
        let proof = serde_json::to_vec(&serde_json::json!({
            "token": self.token, "incarnation": incarnation,
            "signature": self.signer.sign(&message).to_bytes().to_vec(),
        }))
        .map_err(|_| Error::Invalid)?;
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Invalid);
        }
        Ok(proof)
    }
}

/// Private-constructor rate evidence, NOT admission or native proof authority.
pub struct RatePermit {
    context: [u8; 32],
    deposit: [u8; 32],
    token: [u8; 32],
    epoch: u64,
    valid_until: u64,
}
impl RatePermit {
    pub fn context(&self) -> [u8; 32] {
        self.context
    }
    pub fn deposit(&self) -> [u8; 32] {
        self.deposit
    }
    pub fn token(&self) -> [u8; 32] {
        self.token
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

/// Only an independently authenticated common descriptor selects the key.
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
    pub fn verify(&self, proof: &[u8], request: &Request, now: u64) -> Result<RatePermit> {
        self.epoch.check_time(now)?;
        request.validate()?;
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Invalid);
        }
        let presentation: Presentation =
            serde_json::from_slice(proof).map_err(|_| Error::Invalid)?;
        let token = presentation.token;
        if presentation.incarnation != self.incarnation
            || token.context != self.context
            || token.deposit != request.deposit
            || token.signature.len() != RSA_BYTES
        {
            return Err(Error::Refused);
        }
        self.key
            .verify(
                &Signature(token.signature.clone()),
                Some(MessageRandomizer(token.randomizer)),
                &token_message(&token.context, &token.deposit, &token.possession_key)?,
            )
            .map_err(|_| Error::Refused)?;
        let key = VerifyingKey::from_bytes(&token.possession_key).map_err(|_| Error::Refused)?;
        if key.is_weak() {
            return Err(Error::Refused);
        }
        let signature = ed25519_dalek::Signature::from_slice(&presentation.signature)
            .map_err(|_| Error::Refused)?;
        key.verify_strict(
            &request_message(&token.context, &self.incarnation, request)?,
            &signature,
        )
        .map_err(|_| Error::Refused)?;
        let bytes = postcard::to_allocvec(&("cmbl.settlement.replay.v1", &token))
            .map_err(|_| Error::Invalid)?;
        Ok(RatePermit {
            context: self.context,
            deposit: token.deposit,
            token: *blake3::hash(&bytes).as_bytes(),
            epoch: self.epoch.epoch,
            valid_until: self.epoch.valid_until,
        })
    }
}

fn token_message(context: &[u8; 32], deposit: &[u8; 32], key: &[u8; 32]) -> Result<Vec<u8>> {
    postcard::to_allocvec(&("cmbl.settlement.token.v1", context, deposit, key))
        .map_err(|_| Error::Invalid)
}
fn request_message(context: &[u8; 32], incarnation: &str, request: &Request) -> Result<Vec<u8>> {
    if incarnation.is_empty() || incarnation.len() > 256 {
        return Err(Error::Invalid);
    }
    postcard::to_allocvec(&("cmbl.settlement.request.v1", context, incarnation, request))
        .map_err(|_| Error::Invalid)
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub mod issuer;
