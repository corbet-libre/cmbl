//! Native blind signing only. Authenticated quota/anchor activation belongs to
//! the accounting owner and must precede exposure of any signed response.
use super::{BlindRequest, Epoch};
use crate::{Error, Result, passes::RSA_BYTES};
use openssl::pkey::{PKey, Private};

pub struct Issuer {
    epoch: Epoch,
    context: [u8; 32],
    key: PKey<Private>,
}
impl Issuer {
    /// Restore only the original provisioned dedicated purpose key matching the
    /// independently authenticated epoch anchor. Never use a room/TLS key or
    /// recreate a key/allowance after losing an existing epoch's private key.
    /// This primitive has no quota storage and cannot establish that anchor.
    pub fn from_pkcs1_der(epoch: Epoch, private_der: &[u8]) -> Result<Self> {
        let context = epoch.context()?;
        let key = crate::blind::private_key(private_der, &epoch.public_key_der)?;
        Ok(Self {
            epoch,
            context,
            key,
        })
    }
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    pub fn sign(&self, request: &BlindRequest, now: u64) -> Result<Vec<u8>> {
        self.epoch.check_time(now)?;
        if request.context != self.context || request.blinded.len() != RSA_BYTES {
            return Err(Error::Refused);
        }
        crate::blind::sign(&self.key, &request.blinded)
    }
}
