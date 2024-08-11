use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::enc::{self, age::DecryptedValue};

#[derive(Debug, Serialize, Deserialize)]
struct Age {
    recipient: String,
    enc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SopsData {
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
    #[error("Missing data: {0}")]
    MissingData(String),
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("No recipients found")]
    NoRecipients,
    #[error("Error decrypting KEK: {0}")]
    KekDecryptionError(#[from] anyhow::Error),
    #[error("No key found")]
    NoKey,
}

pub trait SopsFile {
    fn get_key<'a>(&'a self, key: &[&'a str]) -> Option<&String>;

    fn decrypt(&self, key: &[&str], keyfile: &str) -> Result<DecryptedValue> {
        let data = self.get_key(key);
        match data {
            Some(d) => decrypt(key, d, keyfile, self.sops_metadata()),
            None => Err(anyhow!(Error::MissingData(key.join(".")))),
        }
    }

    fn sops_metadata(&self) -> &SopsData;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YamlSopsFile {
    pub sops: SopsData,
    #[serde(flatten)]
    other: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonSopsFile {
    pub sops: SopsData,
    #[serde(flatten)]
    other: HashMap<String, serde_json::Value>,
}

impl SopsFile for YamlSopsFile {
    fn get_key<'a>(&'a self, key: &[&'a str]) -> Option<&String> {
        let first = self.other.get(key[0]);
        match first {
            Some(serde_yaml::Value::String(s)) => {
                info!("Found string: {:?}", s);
                if key.len() == 1 {
                    return Some(s);
                }
                return None;
            }
            Some(other) => other.get_nested(&key[1..]),
            None => return None,
        }
    }

    fn sops_metadata(&self) -> &SopsData {
        &self.sops
    }
}

impl SopsFile for JsonSopsFile {
    fn get_key<'a>(&'a self, key: &[&'a str]) -> Option<&String> {
        let first = self.other.get(key[0]);
        match first {
            Some(serde_json::Value::String(s)) => {
                info!("Found string: {:?}", s);
                if key.len() == 1 {
                    return Some(s);
                }
                return None;
            }
            Some(other) => other.get_nested(&key[1..]),
            None => return None,
        }
    }

    fn sops_metadata(&self) -> &SopsData {
        &self.sops
    }
}

pub fn load_sops_file(path: &str) -> Result<Box<dyn SopsFile>> {
    debug!("Loading file from path: {}", path);
    let data = std::fs::read_to_string(path)?;

    let try_json: Result<JsonSopsFile, serde_json::Error> = serde_json::from_str(&data);

    if let Ok(json) = try_json {
        debug!("Loaded as JSON");
        return Ok(Box::new(json));
    }

    let try_yaml: Result<YamlSopsFile, serde_yaml::Error> = serde_yaml::from_str(&data);
    if let Ok(yaml) = try_yaml {
        debug!("Loaded as YAML");
        return Ok(Box::new(yaml));
    }

    Err(anyhow!(Error::ParseError))
}

fn decrypt(path: &[&str], data: &str, keyfile: &str, sops: &SopsData) -> Result<DecryptedValue> {
    debug!("Decrypting {} with keyfile {}", data, keyfile);
    let identities = match enc::age::get_public_keys(keyfile) {
        Ok(i) => i,
        Err(_) => return Err(anyhow!(DecryptionError::NoKey)),
    };
    debug!("Identities: {:?}", identities);
    let candidiates: Vec<&Age> = sops
        .age
        .iter()
        .filter(|a| identities.contains(&a.recipient))
        .collect();
    debug!("Found {} candidates", candidiates.len());
    if candidiates.len() == 0 {
        return Err(anyhow!(DecryptionError::NoRecipients));
    }

    let candidate = candidiates[0];
    debug!("Candidate: {:?}", candidate);

    let kek = enc::age::decrypt_kek(&candidate.enc, keyfile)
        .map_err(|e| DecryptionError::KekDecryptionError(e))?;
    let kek: &[u8; 32] = kek[..].try_into()?;

    enc::age::decrypt(
        data.to_string(),
        kek,
        path.into_iter().map(|f| f.to_string()).collect(),
    )
}

trait Leaf {
    fn is_leaf(&self) -> bool;
}

impl Leaf for serde_yaml::Value {
    fn is_leaf(&self) -> bool {
        !matches!(self, serde_yaml::Value::Mapping(_))
    }
}

impl Leaf for serde_json::Value {
    fn is_leaf(&self) -> bool {
        !matches!(self, serde_json::Value::Object(_))
    }
}

trait Nested {
    fn get_nested(&self, key: &[&str]) -> Option<&String>;
}

impl Nested for serde_yaml::Value {
    fn get_nested(&self, key: &[&str]) -> Option<&String> {
        match self {
            serde_yaml::Value::String(s) => {
                if key.len() == 0 {
                    Some(s)
                } else {
                    None
                }
            }
            serde_yaml::Value::Mapping(m) => {
                let current_key = key.get(0);
                let current = match current_key {
                    Some(k) => m.get(k),
                    None => None,
                };
                if let Some(value) = current {
                    value.get_nested(&key[1..])
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Nested for serde_json::Value {
    fn get_nested(&self, key: &[&str]) -> Option<&String> {
        match self {
            serde_json::Value::String(s) => {
                if key.len() == 0 {
                    Some(s)
                } else {
                    None
                }
            }
            serde_json::Value::Object(m) => {
                let current_key = key.get(0);
                let current = match current_key {
                    Some(k) => m.get(k.to_owned()),
                    None => None,
                };
                if let Some(value) = current {
                    value.get_nested(&key[1..])
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
