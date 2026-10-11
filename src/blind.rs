//! Shared maintained RSA suite; protocol transcripts belong to each purpose.
use crate::{Error, Result};
use blind_rsa_signatures::{PSS, PublicKey, Randomized, SecretKey, Sha384};

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

pub(crate) type RsaSecretKey = SecretKey<Sha384, PSS, Randomized>;

/// Parse an operator-provisioned issuer key (PKCS#1 or PKCS#8 DER) and require
/// it to be the exact 3072-bit key the epoch anchor names.
#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub(crate) fn private_key(der: &[u8], public_der: &[u8]) -> Result<RsaSecretKey> {
    if der.len() > 4096 {
        return Err(Error::Invalid);
    }
    // from_der validates the key material and precomputes the CRT values.
    let key = RsaSecretKey::from_der(der).map_err(|_| Error::Invalid)?;
    let derived = key.public_key().map_err(|_| Error::Invalid)?;
    if derived.to_der().map_err(|_| Error::Invalid)? != public_der
        || public_key(public_der).is_err()
    {
        return Err(Error::Refused);
    }
    Ok(key)
}

/// RFC 9474 blind signature over `blinded`, produced and re-verified by the
/// maintained `blind-rsa-signatures` crate. The wire format is unchanged: a
/// big-endian integer exactly as wide as the modulus.
#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub(crate) fn sign(key: &RsaSecretKey, blinded: &[u8]) -> Result<Vec<u8>> {
    if blinded.len() != crate::passes::RSA_BYTES || blinded.iter().all(|byte| *byte == 0) {
        return Err(Error::Invalid);
    }
    let signature = key.blind_sign(blinded).map_err(|error| match error {
        // An integer at or above the modulus is a malformed request.
        blind_rsa_signatures::Error::UnsupportedParameters => Error::Invalid,
        _ => Error::Refused,
    })?;
    if signature.0.len() != crate::passes::RSA_BYTES {
        return Err(Error::Refused);
    }
    Ok(signature.0)
}
