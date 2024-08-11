use anyhow::anyhow;
use anyhow::Result;
use bech32::Bech32;
use bech32::Hrp;
use bech32::{encode, encode_upper};
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::SecretKey as Ed25519SecretKey;
use sha2::Digest;
use sha2::Sha512;

use curve25519_dalek::edwards::CompressedEdwardsY;
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use thiserror::Error;

#[derive(Debug)]
pub struct AgeKey {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Invalid key")]
    InvalidKey,
}

impl TryFrom<PrivateKey> for AgeKey {
    type Error = Error;

    fn try_from(key: PrivateKey) -> Result<Self, Error> {
        if let KeypairData::Ed25519(key) = key.key_data() {
            let sec = key.private.to_bytes();
            let public = key.public;

            let pub_age = ssh_public_key_to_age(public.as_ref()).map_err(|_| Error::InvalidKey)?;
            let sec_age = ssh_private_key_to_age(&sec).map_err(|_| Error::InvalidKey)?;
            Ok(AgeKey {
                public_key: pub_age,
                private_key: sec_age,
            })
        } else {
            Err(Error::UnsupportedKeyType)
        }
    }
}

fn ssh_public_key_to_age(key: &[u8]) -> Result<String> {
    let pk = CompressedEdwardsY::from_slice(key)?;
    encode_public_key(&pk)
}

fn ssh_private_key_to_age(key: &[u8]) -> Result<String> {
    let ed25519_sk = Ed25519SecretKey::try_from(key)?;
    let private_key_bytes = ed25519_private_key_to_curve25519(&ed25519_sk)?;

    Ok(encode_upper::<Bech32>(
        Hrp::parse("AGE-SECRET-KEY-")?,
        &private_key_bytes,
    )?)
}

fn ed25519_private_key_to_curve25519(pk: &Ed25519SecretKey) -> Result<[u8; 32]> {
    let mut hasher = Sha512::new();
    hasher.update(&pk);
    let out = hasher.finalize();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&out[..32]);
    Ok(scalar)
}

fn ed25519_public_key_to_curve25519(pk: &CompressedEdwardsY) -> Result<[u8; 32]> {
    let edwards_point = pk
        .decompress()
        .ok_or(anyhow!("Failed to decompress edwards point"))?;
    if edwards_point.is_identity() {
        return Err(anyhow!("Edwards point is identity"));
    }
    let montgomery_point = edwards_point.to_montgomery();
    Ok(montgomery_point.0)
}

fn encode_public_key(pk: &CompressedEdwardsY) -> Result<String> {
    let mpk = ed25519_public_key_to_curve25519(pk)?;

    let hrp = Hrp::parse("age").map_err(|e| anyhow!(e))?;
    Ok(encode::<Bech32>(hrp, &mpk).map_err(|e| anyhow!(e))?)
}
