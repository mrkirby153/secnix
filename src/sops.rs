use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

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

pub enum Error {}

pub enum FileType {
    Json,
    Yaml,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SopsFile {
    sops: SopsData,
    #[serde(flatten)]
    other: HashMap<String, String>,
}

impl SopsFile {
    pub fn load(path: &str) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let sops_file: SopsFile = serde_json::from_str(&data)?;

        Ok(sops_file)
    }

    fn try_load(path: &str, file_type: FileType) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let sops_file: SopsFile = match file_type {
            FileType::Json => serde_json::from_str(&data)?,
            FileType::Yaml => serde_yaml::from_str(&data)?,
        };

        Ok(sops_file)
    }
}
