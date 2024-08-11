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
use tracing::{debug, error};

use regex::Regex;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid key file")]
    InvalidKeyFile,
    #[error("Decryption error: {0}")]
    DecryptionError(#[from] age::DecryptError),
}

pub enum DecryptedValue {
    String(String),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Bool(bool),
    Comment(()),
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

pub fn decrypt(data: String, key: &[u8; 32], path: Vec<String>) -> Result<DecryptedValue> {
    let raw_data = Aes256GcmData::try_from(data)?;
    let nonce = raw_data.iv;
    let aad = path.join(":") + ":";
    let cipher = raw_data.data;
    let tag = raw_data.tag;

    let ciphertext_tag = [cipher, tag].concat();

    let aad = aad.as_bytes();
    let payload = Payload {
        msg: &ciphertext_tag[..],
        aad,
    };

    let nonce = Nonce::from_slice(&nonce[..]);
    let key = Key::<SopsGcm>::from_slice(&key[..]);

    let cipher = SopsGcm::new(key);
    match cipher.decrypt(nonce, payload) {
        Ok(raw_decrypted) => {
            let decrypted = String::from_utf8(raw_decrypted).map_err(|e| anyhow!(e))?;

            match raw_data.data_type {
                Aes256GcmType::String => Ok(DecryptedValue::String(decrypted)),
                Aes256GcmType::Int => Ok(DecryptedValue::Int(decrypted.parse()?)),
                Aes256GcmType::Float => Ok(DecryptedValue::Float(decrypted.parse()?)),
                Aes256GcmType::Bytes => Ok(DecryptedValue::Bytes(decrypted.into_bytes())),
                Aes256GcmType::Bool => Ok(DecryptedValue::Bool(decrypted.parse()?)),
                Aes256GcmType::Comment => Ok(DecryptedValue::Comment(())),
                Aes256GcmType::Unknown => Err(anyhow!("Unknown data type")),
            }
        }
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

const AES256_GCM_REGEX: &str = r#"^ENC\[AES256_GCM,data:(.*),iv:(.*),tag:(.*),type:(.*)\]$"#;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid data format")]
    InvalidDataFormat,
    #[error("Error decoding {0}: {1}")]
    DataDecodeError(&'static str, #[source] base64::DecodeError),
}

impl TryFrom<String> for Aes256GcmData {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Aes256GcmData, ParseError> {
        let re = Regex::new(AES256_GCM_REGEX).unwrap();
        debug!("Parsing AES256_GCM data: {}", value);

        let Some((_, [data, iv, tag, data_type])) = re.captures(&value).map(|c| c.extract()) else {
            return Err(ParseError::InvalidDataFormat);
        };

        let data = general_purpose::STANDARD
            .decode(data)
            .map_err(|e| ParseError::DataDecodeError("data", e))?;
        let iv = general_purpose::STANDARD
            .decode(iv)
            .map_err(|e| ParseError::DataDecodeError("iv", e))?;
        let tag = general_purpose::STANDARD
            .decode(tag)
            .map_err(|e| ParseError::DataDecodeError("tag", e))?;

        let data_type = match data_type {
            "str" => Aes256GcmType::String,
            "int" => Aes256GcmType::Int,
            "float" => Aes256GcmType::Float,
            "bytes" => Aes256GcmType::Bytes,
            "bool" => Aes256GcmType::Bool,
            "comment" => Aes256GcmType::Comment,
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
