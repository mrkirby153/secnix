use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::enc;

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

    fn decrypt(&self, key: &[&str], keyfile: &str) -> Result<String> {
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
            Some(other) => get_key_yaml(&key[1..], Some(other)),
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
            Some(other) => get_key_json(&key[1..], Some(other)),
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

fn get_key_yaml<'a>(path: &[&'a str], node: Option<&'a serde_yaml::Value>) -> Option<&'a String> {
    debug!("Current key: {:?}", path);
    debug!("Node: {:?}", node);

    match node {
        Some(serde_yaml::Value::String(s)) => {
            info!("Found string: {:?}", s);
            if path.len() == 0 {
                return Some(s);
            }
            return None;
        }
        Some(serde_yaml::Value::Mapping(m)) => {
            let current_key = path.get(0);
            let current = match current_key {
                Some(k) => m.get(k),
                None => None,
            };

            return get_key_yaml(&path[1..], current);
        }
        _ => return None,
    }
}

fn get_key_json<'a>(path: &[&'a str], node: Option<&'a serde_json::Value>) -> Option<&'a String> {
    match node {
        Some(serde_json::Value::String(s)) => {
            if path.len() == 0 {
                return Some(s);
            }
            return None;
        }
        Some(serde_json::Value::Object(m)) => {
            let current_key = path.get(0);
            let current = match current_key {
                Some(k) => m.get(k.to_owned()),
                None => None,
            };

            return get_key_json(&path[1..], current);
        }
        _ => return None,
    }
}

fn decrypt(path: &[&str], data: &str, keyfile: &str, sops: &SopsData) -> Result<String> {
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
