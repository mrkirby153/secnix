use std::path::Path;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct SecnixManifest {
    /// The version of the manifest file.
    pub version: u64,
    /// Any secrets that should be installed
    pub secrets: Vec<SecretFile>,
    /// Any SSH keys that will be used to decrypt the secrets
    pub ssh_keys: Vec<String>,
    /// The directory where the secrets will be installed
    pub secret_directory: String,
    /// Whether or not to write the manifest file (Can clean up secrets between generations)
    pub write_manifest: bool,
}

#[derive(Debug, Deserialize)]
pub struct SecretFile {
    /// The type of file
    #[serde(rename = "type")]
    pub file_type: FileType,
    /// The name of the file
    pub name: String,

    /// The source of the file
    pub source: String,

    /// The key in the file
    pub key: Option<String>,

    /// The location where the file will be symlinked
    pub link: Option<String>,

    /// The mode of the file
    pub mode: Option<u32>,
    /// The owner of the file
    pub owner: Option<String>,
    /// The group of the file
    pub group: Option<String>,
    /// Whether or not to copy the file instead of symlinking it
    pub copy: Option<bool>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub enum FileType {
    #[serde(rename = "json")]
    JSON,
    #[serde(rename = "yaml", alias = "yml")]
    YAML,
    #[serde(rename = "binary")]
    Binary,
}

#[derive(Error, Debug)]
enum Error {
    #[error("Path does not exist")]
    PathDoesNotExist,
    #[error("Invalid manifest: {0}")]
    InvalidManifest(serde_json::Error),

    #[error("Unknown error: {0}")]
    UnknownError(#[from] anyhow::Error),
}

impl SecnixManifest {
    /// Create a new SecnixManifest from a file
    pub fn new(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::PathDoesNotExist.into());
        }
        let manifest =
            std::fs::read_to_string(path).map_err(|e| Error::UnknownError(anyhow!(e)))?;
        let manifest: SecnixManifest =
            serde_json::from_str(&manifest).map_err(|e| Error::InvalidManifest(e))?;

        Ok(manifest)
    }
}
