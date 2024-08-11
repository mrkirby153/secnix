use std::{
    collections::{HashMap, HashSet},
    fs::rename,
    io::Write,
    os::unix::fs::symlink,
    path::Path,
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use anyhow::Result;
use tracing::{debug, warn};
use ulid::Ulid;

use crate::{enc::age::DecryptedValue, manifest::SecretFile, sops::load_sops_file};

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

/// Metadata about the secrets deployed on the system
#[derive(Debug, Serialize, Deserialize)]
struct FileSystemMetadata {
    /// A list of generations that have been deployed
    generations: HashMap<u64, String>,
    active_generation: Option<String>,
}

/// Metadata about a generation
#[derive(Debug, Serialize, Deserialize)]
struct DeployedSecretsMetadata {
    /// The generation id of this secret
    generation: String,
    /// The paths to the secret files that were symlinked
    secret_files: Vec<String>,
    secrets: Vec<SecretFile>,
}

/// Create a new generation of secrets, returning the generation id.
/// This will symlink the secret files on the system.
pub fn activate_new_generation(
    basedir: &Path,
    files: Vec<SecretFile>,
    identity_file: &str,
) -> Result<String> {
    let generation_id = Ulid::new().to_string();
    debug!(
        "Creating new generation with id: {} using identity file {}",
        generation_id, identity_file
    );

    let current_metadata = DeployedSecretsMetadata {
        generation: generation_id.clone(),
        secret_files: files
            .iter()
            .filter(|f| f.link.is_some())
            .map(|f| f.link.clone().unwrap())
            .collect(),
        secrets: files.clone(),
    };

    let generation_directory = get_generation_path(basedir, &generation_id);

    std::fs::create_dir_all(&generation_directory)?;

    debug!("Writing metadata for generation: {:?}", current_metadata);

    let metadata_file = get_generation_metadata_path(basedir, &generation_id);
    let metadata_file = std::fs::File::create(&metadata_file)?;
    serde_json::to_writer(metadata_file, &current_metadata)?;

    // Write the files
    for secret_file in files {
        let file_name = &secret_file.name;
        let file = generation_directory.join(&file_name);
        debug!("Writing file: {}", file.display());

        let encrypted = load_sops_file(&secret_file.source)?;
        if let Some(key) = &secret_file.get_key() {
            let path = key.split('.').collect::<Vec<_>>();
            let decrypted = encrypted.decrypt(&path, identity_file)?;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file)?;

            match decrypted {
                DecryptedValue::String(str) => {
                    file.write_all(str.as_bytes())?;
                }
                DecryptedValue::Int(int) => {
                    file.write_all(int.to_string().as_bytes())?;
                }
                DecryptedValue::Float(float) => {
                    file.write_all(float.to_string().as_bytes())?;
                }
                DecryptedValue::Bytes(bytes) => {
                    file.write_all(&bytes)?;
                }
                DecryptedValue::Bool(bool) => {
                    file.write_all(bool.to_string().as_bytes())?;
                }
                _ => {
                    warn!("Unsupported data type for file: {}", file_name);
                }
            }
            file.flush()?;
            debug!("File written successfully");
        } else {
            warn!("No key provided for file: {}", file_name);
        }
    }

    // Add the generation to the manifest
    debug!("Recording generation in manifest");
    let mut metadata = get_metadata(basedir)?;
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    metadata.generations.insert(time, generation_id.clone());

    let previous_generation = metadata.active_generation.take();
    debug!("Previous generation: {:?}", previous_generation);
    metadata.active_generation = Some(generation_id.clone());

    // Symlink the generation to the active generation
    debug!("Atomically symlinking to active generation");
    let temp_file = basedir.join(Ulid::new().to_string());
    symlink(get_generation_path(basedir, &generation_id), &temp_file)?;
    rename(temp_file, basedir.join("secrets"))?;

    // Remove previous generation files
    if let Some(previous_generation) = previous_generation {
        debug!("Removing stale symlinks from previous generation");
        let previous_manifest = get_generation_metadata_path(basedir, &previous_generation);
        let previous_manifest: DeployedSecretsMetadata =
            serde_json::from_reader(std::fs::File::open(&previous_manifest)?)?;

        let previous_files: HashSet<String> = HashSet::from_iter(previous_manifest.secret_files);
        let current_files: HashSet<String> = HashSet::from_iter(current_metadata.secret_files);
        debug!("Previous files: {:?}", previous_files);
        debug!("Current files: {:?}", current_files);

        let to_remove = previous_files.difference(&current_files);
        for file in to_remove {
            let file = basedir.join(file);
            debug!("Removing stale symlink: {}", file.display());
            std::fs::remove_file(&file)?;
        }
    }

    debug!("Writing metadata for filesystem");
    let metadata_file = basedir.join("metadata.json");
    let metadata_file = std::fs::File::create(&metadata_file)?;
    serde_json::to_writer(metadata_file, &metadata)?;

    debug!("Generation created successfully");
    Ok(generation_id)
}

fn get_generation_path(basedir: &Path, generation_id: &str) -> std::path::PathBuf {
    basedir.join("generations").join(generation_id)
}

fn get_generation_metadata_path(basedir: &Path, generation_id: &str) -> std::path::PathBuf {
    get_generation_path(basedir, generation_id).join(".metadata.json")
}

fn get_metadata(basedir: &Path) -> Result<FileSystemMetadata> {
    let metadata_file = basedir.join("metadata.json");
    if !metadata_file.exists() {
        Ok(FileSystemMetadata {
            generations: HashMap::new(),
            active_generation: None,
        })
    } else {
        let metadata_file = std::fs::File::open(&metadata_file)?;
        Ok(serde_json::from_reader(metadata_file)?)
    }
}
