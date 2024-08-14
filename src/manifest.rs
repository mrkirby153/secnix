use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
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

    /// A list of templates that should be rendered
    pub templates: Vec<Template>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecretFile {
    /// The type of file
    #[serde(rename = "type")]
    pub file_type: FileType,
    /// The name of the file
    pub name: String,

    /// The source of the file
    pub source: String,

    /// The key in the file
    key: Option<String>,

    /// The location where the file will be symlinked
    pub link: Option<String>,

    /// The mode of the file
    pub mode: Option<String>,
    /// The owner of the file
    pub owner: Option<String>,
    /// The group of the file
    pub group: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub enum FileType {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "yaml", alias = "yml")]
    Yaml,
    #[serde(rename = "binary")]
    Binary,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Template {
    /// The name of the template file
    pub name: String,
    /// The source of the template
    pub source: String,
    /// The destination of the template
    pub destination: String,
    /// If the template should be symlinked or copied
    pub copy: Option<bool>,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

#[derive(Error, Debug)]
enum Error {
    #[error("Path does not exist")]
    PathDoesNotExist,
    #[error("Invalid manifest: {0}")]
    InvalidManifest(serde_json::Error),

    #[error("Unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

impl SecnixManifest {
    /// Create a new SecnixManifest from a file
    pub fn new(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::PathDoesNotExist.into());
        }
        let manifest = std::fs::read_to_string(path).map_err(|e| Error::Unknown(anyhow!(e)))?;
        let manifest: SecnixManifest =
            serde_json::from_str(&manifest).map_err(Error::InvalidManifest)?;

        Ok(manifest)
    }
}

impl SecretFile {
    pub fn get_key(&self) -> Option<String> {
        if let Some(key) = &self.key {
            Some(key.clone())
        } else if self.file_type == FileType::Binary {
            Some("data".to_string())
        } else {
            None
        }
    }
}
