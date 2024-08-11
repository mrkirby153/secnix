use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};
use thiserror::Error;
use tracing::{debug, info};

use crate::{
    manifest::{FileType, SecnixManifest},
    sops::load_sops_file,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// The path to the manifest file.
    pub manifest: String,
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Checks the provided manifest file for any issues.
    Check,
    /// Installs the secret files
    Install,
}

const MAX_SUPPORTED_VERSION: u64 = 1;

#[derive(Error, Debug)]
enum Error {
    #[error("Unsupported manifest version: {0}. The maximum supported version is {1}")]
    UnsupportedVersion(u64, u64),
    #[error("Checking {0} failed: {1}")]
    CheckFailed(String, String),
}

pub fn check(args: Cli) -> Result<()> {
    info!("Checking manifest {}", args.manifest);
    let manifest = load_manifest(&args.manifest)?;

    debug!("Read manifest: {:?}", manifest);

    for file in &manifest.secrets {
        debug!("Checking file: {:?}", file);

        let sops_file = load_sops_file(&file.source)?;
        debug!("Deserialized sops file");
        let metadata = sops_file.sops_metadata();

        debug!("Checking metadata {:?} for sops keys", metadata);
        if metadata.age.is_empty() {
            return Err(
                Error::CheckFailed(file.source.clone(), "No age keys found".to_string()).into(),
            );
        }
        debug!("Age keys found!");

        let key = file.key.as_ref();

        let key: Vec<&str> = {
            if let Some(key) = key {
                key.split('.').collect::<Vec<&str>>()
            } else {
                // Substitute ["data"] only if the file type is binary, otherwise return an error
                if file.file_type == FileType::Binary {
                    vec!["data"]
                } else {
                    return Err(Error::CheckFailed(
                        file.source.clone(),
                        "Key not found in manifest".to_string(),
                    )
                    .into());
                }
            }
        };

        debug!("Checking if {:?} exists in the file", key);
        let data = sops_file.get_key(&key);
        if data.is_none() {
            let raw = key.join(".");
            return Err(Error::CheckFailed(
                file.source.clone(),
                format!("Key {:?} not found in file", raw).to_string(),
            )
            .into());
        }
    }

    info!("Manifest is valid");

    Ok(())
}

pub fn install(_args: Cli) -> Result<()> {
    info!("Installing secrets");

    Ok(())
}

fn load_manifest(path: &str) -> Result<SecnixManifest> {
    let manifest = shellexpand::tilde(path);
    let path = Path::new(manifest.as_ref());
    let manifest = SecnixManifest::new(&path)?;

    if manifest.version > MAX_SUPPORTED_VERSION {
        Err(Error::UnsupportedVersion(manifest.version, MAX_SUPPORTED_VERSION).into())
    } else {
        Ok(manifest)
    }
}
