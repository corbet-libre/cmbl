//! Trusted authenticated-session primitive. The cfrm facade MUST first enforce
//! actual admission and its reviewed issuance quota plus cthl. No public endpoint
//! or new membership verdict is implemented by this primitive.
use super::{BlindRequest, Epoch, Error, RSA_BYTES, Result};
use crate::blind::RsaSecretKey;
mod quota;
pub use quota::BudgetedIssuer;

pub struct Issuer {
    epoch: Epoch,
    context: [u8; 32],
    key: RsaSecretKey,
}
impl Issuer {
    /// Dedicated operator-managed epoch key; no TLS or other-purpose key reuse.
    pub fn from_pkcs1_der(epoch: Epoch, private_der: &[u8]) -> Result<Self> {
        let context = epoch.context()?;
        let key = crate::blind::private_key(private_der, &epoch.public_key_der)?;
        Ok(Self {
            epoch,
            context,
            key,
        })
    }
    pub fn sign(&self, request: &BlindRequest, now: u64) -> Result<Vec<u8>> {
        self.epoch.check_time(now)?;
        if request.context != self.context || request.blinded.len() != RSA_BYTES {
            return Err(Error::Refused);
        }
        crate::blind::sign(&self.key, &request.blinded)
    }
}
