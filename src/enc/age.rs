use std::{
    fs,
    io::{BufReader, Read},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    aes::Aes256,
    AesGcm, Key, Nonce,
};
use age::IdentityFileEntry;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use thiserror::Error;
use tracing::{debug, error, info};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid key file")]
    InvalidKeyFile,
    #[error("Decryption error: {0}")]
    DecryptionError(#[from] age::DecryptError),
}

pub fn decrypt_kek(kek: &str, keyfile: &str) -> Result<Vec<u8>> {
    let armor_reader = age::armor::ArmoredReader::new(kek.as_bytes());

    let decryptor = match age::Decryptor::new(armor_reader) {
        Ok(age::Decryptor::Recipients(d)) => Ok(d),
        Ok(_) => Err(Error::InvalidKeyFile),
        Err(e) => Err(Error::DecryptionError(e)),
    }?;

    let identity = read_age_keyfile(keyfile)?;

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(
        identity
            .iter()
            .map(|IdentityFileEntry::Native(x)| x as &dyn age::Identity),
    )?;
    reader.read_to_end(&mut decrypted)?;

    Ok(decrypted)
}

pub type SopsGcm = AesGcm<Aes256, cipher::consts::U32>;

pub fn decrypt(data: String, key: &[u8; 32], path: Vec<String>) -> Result<String> {
    let raw_data = Aes256GcmData::try_from(data)?;
    let nonce = raw_data.iv;
    let aad = path.join(":") + ":";
    let cipher = raw_data.data;
    let tag = raw_data.tag;

    let ciphertext_tag = [cipher, tag].concat();

    let aad = aad.as_bytes();
    let payload = Payload {
        msg: &ciphertext_tag[..],
        aad: &aad[..],
    };

    let nonce = Nonce::from_slice(&nonce[..]);
    let key = Key::<SopsGcm>::from_slice(&key[..]);

    let cipher = SopsGcm::new(&key);
    match cipher.decrypt(&nonce, payload) {
        Ok(decrypted) => String::from_utf8(decrypted).map_err(|e| anyhow!(e)),
        Err(e) => Err(anyhow!(e)),
    }
}

fn read_age_keyfile(path: &str) -> Result<Vec<IdentityFileEntry>> {
    let f = fs::File::open(path)?;
    let f = BufReader::new(f);
    Ok(age::IdentityFile::from_buffer(f)?.into_identities())
}

pub fn get_public_keys(path: &str) -> Result<Vec<String>> {
    let identities = read_age_keyfile(path)?;
    Ok(identities
        .iter()
        .map(|i| match i {
            IdentityFileEntry::Native(n) => n.to_public().to_string(),
        })
        .collect())
}

#[derive(Debug)]
enum Aes256GcmType {
    String,
    Int,
    Float,
    Bytes,
    Bool,
    Comment,
    Unknown,
}

#[derive(Debug)]
struct Aes256GcmData {
    data: Vec<u8>,
    iv: Vec<u8>,
    tag: Vec<u8>,
    data_type: Aes256GcmType,
}

impl TryFrom<String> for Aes256GcmData {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, anyhow::Error> {
        debug!("Parsing AES256_GCM data: {}", value);
        if !value.starts_with("ENC[AES256_GCM") && !value.ends_with("]") {
            return Err(anyhow!("Invalid data type"));
        }

        let parts: Vec<&str> = value.split(",").collect();

        if parts.len() != 5 {
            return Err(anyhow!("Invalid data format. Missing parts"));
        }

        let data_part = parts[1]
            .strip_prefix("data:")
            .ok_or_else(|| anyhow!("Invalid data format"))?;
        let iv_part = parts[2]
            .strip_prefix("iv:")
            .ok_or_else(|| anyhow!("Invalid data format"))?;
        let tag_part = parts[3]
            .strip_prefix("tag:")
            .ok_or_else(|| anyhow!("Invalid data format"))?;
        let type_part = parts[4]
            .strip_prefix("type:")
            .ok_or_else(|| anyhow!("Invalid data format"))?;

        let data = general_purpose::STANDARD.decode(data_part)?;
        let iv = general_purpose::STANDARD.decode(iv_part)?;
        let tag = general_purpose::STANDARD.decode(tag_part)?;

        let data_type = match type_part {
            "str" => Aes256GcmType::String,
            _ => Aes256GcmType::Unknown,
        };

        Ok(Aes256GcmData {
            data,
            iv,
            tag,
            data_type,
        })
    }
}
