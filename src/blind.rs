//! Shared maintained RSA suite; protocol transcripts belong to each purpose.
use crate::{Error, Result};
use blind_rsa_signatures::{PSS, PublicKey, Randomized, Sha384};

pub(crate) type RsaPublicKey = PublicKey<Sha384, PSS, Randomized>;

pub(crate) fn public_key(der: &[u8]) -> Result<RsaPublicKey> {
    if der.len() > 1024 {
        return Err(Error::Invalid);
    }
    let key = RsaPublicKey::from_der(der).map_err(|_| Error::Invalid)?;
    if key.to_der().map_err(|_| Error::Invalid)? != der {
        return Err(Error::Invalid);
    }
    let modulus = key.components().n();
    let exponent = key.components().e();
    let exponent = exponent
        .iter()
        .position(|byte| *byte != 0)
        .map(|start| &exponent[start..])
        .unwrap_or_default();
    if modulus.len() != crate::passes::RSA_BYTES || modulus[0] & 0x80 == 0 || exponent != [1, 0, 1]
    {
        return Err(Error::Invalid);
    }
    Ok(key)
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub(crate) fn private_key(
    der: &[u8],
    public_der: &[u8],
) -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    use openssl::{pkey::PKey, rsa::Rsa};
    if der.len() > 4096 {
        return Err(Error::Invalid);
    }
    let rsa = Rsa::private_key_from_der(der).map_err(|_| Error::Invalid)?;
    if !rsa.check_key().map_err(|_| Error::Invalid)?
        || rsa.n().num_bits() != 3072
        || rsa.e().to_vec() != [1, 0, 1]
        || rsa.public_key_to_der().map_err(|_| Error::Invalid)? != public_der
    {
        return Err(Error::Refused);
    }
    PKey::from_rsa(rsa).map_err(|_| Error::Invalid)
}

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub(crate) fn sign(
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
    blinded: &[u8],
) -> Result<Vec<u8>> {
    use openssl::{pkey_ctx::PkeyCtx, rsa::Padding};
    let modulus = key.rsa().map_err(|_| Error::Refused)?.n().to_vec();
    if blinded.iter().all(|byte| *byte == 0) || blinded >= modulus.as_slice() {
        return Err(Error::Invalid);
    }
    let mut signer = PkeyCtx::new(key).map_err(|_| Error::Refused)?;
    signer.sign_init().map_err(|_| Error::Refused)?;
    signer
        .set_rsa_padding(Padding::NONE)
        .map_err(|_| Error::Refused)?;
    let mut signature = Vec::new();
    signer
        .sign_to_vec(blinded, &mut signature)
        .map_err(|_| Error::Refused)?;
    if signature.len() != crate::passes::RSA_BYTES {
        return Err(Error::Refused);
    }
    let mut verify = PkeyCtx::new(key).map_err(|_| Error::Refused)?;
    verify.verify_init().map_err(|_| Error::Refused)?;
    verify
        .set_rsa_padding(Padding::NONE)
        .map_err(|_| Error::Refused)?;
    if !verify
        .verify(blinded, &signature)
        .map_err(|_| Error::Refused)?
    {
        return Err(Error::Refused);
    }
    Ok(signature)
}
