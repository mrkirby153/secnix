use std::{
    env::consts::OS,
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use thiserror::Error;
use tracing::{debug, info};

use crate::{
    fs::{activate_new_generation, clean_old_generations},
    manifest::SecnixManifest,
    sops::load_sops_file,
    ssh::AgeKey,
};

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

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

    debug!("Checking for duplicate names");
    let mut seen = std::collections::HashSet::new();
    let secrets = &manifest.secrets;
    for name in secrets.iter().map(|s| &s.name) {
        if !seen.insert(name) {
            return Err(Error::CheckFailed(
                args.manifest.clone(),
                format!("Duplicate name: {}", name).to_string(),
            )
            .into());
        }
    }

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

        let key = file.get_key();

        let key = if let Some(key) = key {
            key
        } else {
            return Err(Error::CheckFailed(
                file.source.clone(),
                "Key not found in manifest".to_string(),
            )
            .into());
        };

        let key = key.split('.').collect::<Vec<_>>();

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

pub fn install(args: Cli) -> Result<()> {
    info!("Installing secrets");

    let manifest = load_manifest(&args.manifest)?;

    let directory = get_secret_directory(&manifest)?;
    let directory = Path::new(&directory);

    let keyfile = write_ssh_keys(directory, &manifest.ssh_keys[..])?;
    let keyfile = keyfile.to_str();

    if let Some(keyfile) = keyfile {
        activate_new_generation(directory, manifest.secrets, manifest.templates, keyfile)?;
    } else {
        return Err(anyhow!("Failed to convert keyfile path to string"));
    }

    clean_old_generations(directory, 1)?;

    Ok(())
}

fn load_manifest(path: &str) -> Result<SecnixManifest> {
    let manifest = shellexpand::tilde(path);
    let path = Path::new(manifest.as_ref());
    let manifest = SecnixManifest::new(path)?;

    if manifest.version > MAX_SUPPORTED_VERSION {
        Err(Error::UnsupportedVersion(manifest.version, MAX_SUPPORTED_VERSION).into())
    } else {
        Ok(manifest)
    }
}

fn write_ssh_keys(directory: &Path, keys: &[String]) -> Result<PathBuf> {
    // Ensure the directory exists
    if !directory.exists() {
        debug!("Creating directory {}", directory.display());
        std::fs::create_dir_all(directory)?;
    }

    let path = directory.join("keys.txt");
    debug!("Writing ssh keys to {}", path.display());

    if path.exists() {
        debug!("Removing existing key file");
        std::fs::remove_file(&path)?;
    }

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    let mut buffer = std::io::BufWriter::new(file);
    for key in keys {
        let key = shellexpand::tilde(key);
        info!("Importing key: {}", key);
        let data = std::fs::read(key.into_owned())?;
        let private_key = ssh_key::PrivateKey::from_openssh(data)?;
        let age_key: AgeKey = private_key.try_into()?;
        debug!("Writing public key {}", age_key.public_key);
        writeln!(buffer, "# {}", age_key.public_key)?;
        writeln!(buffer, "{}", age_key.private_key)?;
    }
    debug!("Wrote age key to {}", path.display());
    buffer.flush()?;

    Ok(path)
}

fn get_secret_directory(manifest: &SecnixManifest) -> Result<String> {
    let basedir = manifest.secret_directory.as_str();
    if basedir.contains("%r") {
        debug!("Replacing %r with runtime directory");
        let runtime_direcotry = if cfg!(target_os = "linux") {
            std::env::var("XDG_RUNTIME_DIR")?
        } else if cfg!(target_os = "macos") {
            let output = std::process::Command::new("getconf")
                .args(["DARWIN_USER_TEMP_DIR"])
                .output()?;
            let output = String::from_utf8(output.stdout)?;
            output.trim().to_string()
        } else {
            return Err(anyhow!("Unsupported OS"));
        };
        let final_string = basedir.replace("%r", &runtime_direcotry);
        debug!("Runtime directory: {}", final_string);
        Ok(final_string)
    } else {
        Ok(manifest.secret_directory.clone())
    }
}
