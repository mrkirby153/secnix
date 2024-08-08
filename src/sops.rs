use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

use crate::enc;

#[derive(Debug, Serialize, Deserialize)]
struct Age {
    recipient: String,
    enc: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SopsData {
    age: Vec<Age>,
    #[serde(rename = "lastmodified")]
    last_modified: String,
    mac: String,
    unencrypted_suffix: String,
    version: String,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not parse file as JSON or YAML")]
    ParseError,
    #[error("Could not decrypt data: {0}")]
    DecryptionError(#[from] DecryptionError),
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Invalid key file")]
    InvalidKeyFile,
    #[error("No recipients found")]
    NoRecipients,
    #[error("Error decrypting KEK: {0}")]
    KekDecryptionError(#[from] anyhow::Error),
    #[error("No key found")]
    NoKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SopsFile {
    pub sops: SopsData,
    #[serde(flatten)]
    other: HashMap<String, String>,
}

impl SopsFile {
    pub fn load(path: &str) -> Result<Self> {
        debug!("Loading file from path: {}", path);
        let data = std::fs::read_to_string(path)?;
        let as_json: Result<Self, serde_json::Error> = serde_json::from_str(&data);
        let as_yaml: Result<Self, serde_yaml::Error> = serde_yaml::from_str(&data);

        match as_json {
            Ok(json) => Ok(json),
            Err(_) => match as_yaml {
                Ok(yaml) => Ok(yaml),
                Err(_) => Err(anyhow!(Error::ParseError)),
            },
        }
    }

    pub fn get(&self, key: &str, keyfile: &str) -> Result<String> {
        debug!("Retrieving key {} with keyfile {}", key, keyfile);
        let raw = self.other.get(key);
        debug!("Raw data: {:?}", raw);

        let raw = match raw {
            Some(r) => r,
            None => return Err(anyhow!(Error::ParseError)),
        };

        let identities = match enc::age::get_public_keys(keyfile) {
            Ok(i) => i,
            Err(_) => return Err(anyhow!(DecryptionError::NoKey)),
        };
        debug!("Identities: {:?}", identities);

        let candidates: Vec<&Age> = self
            .sops
            .age
            .iter()
            .filter(|a| identities.contains(&a.recipient))
            .collect();

        debug!("Found {} candidates", candidates.len());

        if candidates.len() == 0 {
            return Err(anyhow!(DecryptionError::NoRecipients));
        }

        let candidate = candidates[0];

        debug!("Candidate: {:?}", candidate);

        let kek = enc::age::decrypt_kek(&candidate.enc, keyfile)
            .map_err(|e| DecryptionError::KekDecryptionError(e))?;
        let kek: &[u8; 32] = kek[..].try_into()?;

        debug!("KEK: {:?}", kek);

        enc::age::decrypt(raw.to_string(), kek, vec![key.to_string()])
    }
}
