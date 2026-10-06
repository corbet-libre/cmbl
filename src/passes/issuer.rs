//! Trusted authenticated-session primitive. The cfrm facade MUST first enforce
//! actual admission and its reviewed issuance quota plus cthl. No public endpoint
//! or new membership verdict is implemented by this primitive.
use super::{BlindRequest, Epoch, Error, RSA_BYTES, Result};
use openssl::{
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
mod quota;
pub use quota::BudgetedIssuer;

pub struct Issuer {
    epoch: Epoch,
    context: [u8; 32],
    key: PKey<Private>,
}
impl Issuer {
    /// Dedicated operator-managed epoch key; no TLS or other-purpose key reuse.
    pub fn from_pkcs1_der(epoch: Epoch, private_der: &[u8]) -> Result<Self> {
        let context = epoch.context()?;
        if private_der.len() > 4096 {
            return Err(Error::Invalid);
        }
        let rsa = Rsa::private_key_from_der(private_der).map_err(|_| Error::Invalid)?;
        if !rsa.check_key().map_err(|_| Error::Invalid)?
            || rsa.n().num_bits() != 3072
            || rsa.e().to_vec() != [1, 0, 1]
            || rsa.public_key_to_der().map_err(|_| Error::Invalid)? != epoch.public_key_der
        {
            return Err(Error::Refused);
        }
        Ok(Self {
            epoch,
            context,
            key: PKey::from_rsa(rsa).map_err(|_| Error::Invalid)?,
        })
    }
    pub fn sign(&self, request: &BlindRequest, now: u64) -> Result<Vec<u8>> {
        self.epoch.check_time(now)?;
        if request.context != self.context || request.blinded.len() != RSA_BYTES {
            return Err(Error::Refused);
        }
        let modulus = self.key.rsa().map_err(|_| Error::Refused)?.n().to_vec();
        if request.blinded.iter().all(|byte| *byte == 0) || request.blinded >= modulus {
            return Err(Error::Invalid);
        }
        let mut signer = PkeyCtx::new(&self.key).map_err(|_| Error::Refused)?;
        signer.sign_init().map_err(|_| Error::Refused)?;
        signer
            .set_rsa_padding(Padding::NONE)
            .map_err(|_| Error::Refused)?;
        let mut signature = Vec::new();
        signer
            .sign_to_vec(&request.blinded, &mut signature)
            .map_err(|_| Error::Refused)?;
        if signature.len() != RSA_BYTES {
            return Err(Error::Refused);
        }
        let mut verify = PkeyCtx::new(&self.key).map_err(|_| Error::Refused)?;
        verify.verify_init().map_err(|_| Error::Refused)?;
        verify
            .set_rsa_padding(Padding::NONE)
            .map_err(|_| Error::Refused)?;
        if !verify
            .verify(&request.blinded, &signature)
            .map_err(|_| Error::Refused)?
        {
            return Err(Error::Refused);
        }
        Ok(signature)
    }
}
