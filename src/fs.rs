use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{rename, set_permissions, Permissions},
    io::Write,
    os::unix::fs::{chown, symlink},
    path::Path,
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use anyhow::Result;
use tracing::{debug, info, warn};
use ulid::Ulid;
use users::{get_group_by_name, get_user_by_name};

use crate::{
    enc::age::DecryptedValue,
    manifest::{SecretFile, Template},
    sops::load_sops_file,
};

use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Metadata about the secrets deployed on the system
#[derive(Debug, Serialize, Deserialize)]
struct FileSystemMetadata {
    /// A list of generations that have been deployed
    generations: BTreeMap<u64, String>,
    active_generation: Option<String>,
}

/// Metadata about a generation
#[derive(Debug, Serialize, Deserialize)]
struct DeployedSecretsMetadata {
    /// The generation id of this secret
    generation: String,
    /// The paths to the secret files that were symlinked
    secret_files: Vec<String>,
}

/// Create a new generation of secrets, returning the generation id.
/// This will symlink the secret files on the system.
pub fn activate_new_generation(
    basedir: &Path,
    files: Vec<SecretFile>,
    templates: Vec<Template>,
    identity_file: &str,
) -> Result<String> {
    let generation_id = Ulid::new().to_string();
    debug!(
        "Creating new generation with id: {} using identity file {}",
        generation_id, identity_file
    );

    let template_links: Vec<String> = templates.iter().map(|t| t.destination.clone()).collect();
    let file_links: Vec<String> = files.iter().filter_map(|f| f.link.clone()).collect();

    let current_metadata = DeployedSecretsMetadata {
        generation: generation_id.clone(),
        secret_files: [template_links, file_links].concat(),
    };

    let generation_directory = get_generation_path(basedir, &generation_id);

    std::fs::create_dir_all(&generation_directory)?;

    debug!("Writing metadata for generation: {:?}", current_metadata);

    let metadata_file = get_generation_metadata_path(basedir, &generation_id);
    let metadata_file = std::fs::File::create(&metadata_file)?;
    serde_json::to_writer(metadata_file, &current_metadata)?;

    let mut secrets: HashMap<&str, String> = HashMap::new();
    // Write the files
    for secret_file in &files {
        let file_name = &secret_file.name;
        let file_path = generation_directory.join(file_name);
        debug!("Writing file: {}", file_path.display());

        let encrypted = load_sops_file(&secret_file.source)?;
        if let Some(key) = &secret_file.get_key() {
            let path = key.split('.').collect::<Vec<_>>();
            let decrypted = encrypted.decrypt(&path, identity_file)?;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file_path)?;

            match decrypted {
                DecryptedValue::String(str) => {
                    file.write_all(str.as_bytes())?;
                    secrets.insert(file_name, str.clone());
                }
                DecryptedValue::Int(int) => {
                    file.write_all(int.to_string().as_bytes())?;
                    secrets.insert(file_name, int.to_string());
                }
                DecryptedValue::Float(float) => {
                    file.write_all(float.to_string().as_bytes())?;
                    secrets.insert(file_name, float.to_string());
                }
                DecryptedValue::Bytes(bytes) => {
                    file.write_all(&bytes)?;
                }
                DecryptedValue::Bool(bool) => {
                    file.write_all(bool.to_string().as_bytes())?;
                    secrets.insert(file_name, bool.to_string());
                }
                _ => {
                    warn!("Unsupported data type for file: {}", file_name);
                }
            }
            file.flush()?;
            // Make the file read-only

            let mode = secret_file.mode.map(FilePermission::Decimal);
            let group = secret_file.group.as_deref();
            let user = secret_file.owner.as_deref();
            if let Err(e) = set_file_permissions(&file_path, mode, group, user) {
                warn!(
                    "Failed to set file permissions for {}: {}",
                    file_path.display(),
                    e
                );
            }

            debug!("File written successfully");
        } else {
            warn!("No key provided for file: {}", file_name);
        }
    }

    // Render the templates
    debug!("Rendering templates");
    let rendered_template_dir = generation_directory.join("rendered");
    std::fs::create_dir_all(&rendered_template_dir)?;
    for template in &templates {
        debug!(
            "Rendering template {} to {}",
            template.source, template.name
        );
        let mut text = std::fs::read_to_string(&template.source)?;
        for (key, value) in &secrets {
            let target_key = format!("$$SECNIX::{}::SECNIX$$", key);
            debug!("Looking for key: {}", target_key);
            text = text.replace(&target_key, value);
        }
        let file_name = &template.name;
        let target = rendered_template_dir.join(file_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&target)?;
        file.write_all(text.as_bytes())?;

        let mode = template.mode.map(FilePermission::Decimal);
        let group = template.group.as_deref();
        let user = template.owner.as_deref();
        if let Err(e) = set_file_permissions(&target, mode, group, user) {
            warn!(
                "Failed to set file permissions for {}: {}",
                target.display(),
                e
            );
        }

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400))?;
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

    // Symlink all the files
    for secret_file in &files {
        if let Some(link) = &secret_file.link {
            let link = Path::new(&link);
            // Create parent directories
            if let Some(parent) = link.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let target = basedir.join("secrets").join(&secret_file.name);
            debug!("Symlinking {} -> {}", link.display(), target.display());

            // Create a temporary file and atomically move it to the target. The temp file is adjacent to the target
            let temp_file = link.with_extension("tmp");
            symlink(target, &temp_file)?;
            rename(temp_file, link)?;
        }
    }

    // Symlink the rendered templates
    for template in &templates {
        debug!("Symlinking template: {}", template.destination);
        let link = Path::new(&template.destination);
        // Create parent directories
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if template.copy.unwrap_or(false) {
            let source =
                rendered_template_dir.join(Path::new(&template.source).file_name().unwrap());
            debug!("Copying {} -> {}", source.display(), link.display());
            let temp = link.with_extension("tmp");
            std::fs::copy(source, &temp)?;
            rename(temp, link)?;
        } else {
            let target = basedir
                .join("secrets")
                .join("rendered")
                .join(&template.name);
            debug!("Symlinking {} -> {}", link.display(), target.display());

            let temp = link.with_extension("tmp");
            symlink(target, &temp)?;
            rename(temp, link)?;
        }
    }

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
            let file = Path::new(file);
            info!("Removing stale symlink: {}", file.display());
            if let Err(e) = std::fs::remove_file(file) {
                warn!("Failed to remove file: {}", e);
            }
        }
    }

    debug!("Writing metadata for filesystem");
    let metadata_file = basedir.join("metadata.json");
    let metadata_file = std::fs::File::create(&metadata_file)?;
    serde_json::to_writer(metadata_file, &metadata)?;

    debug!("Generation created successfully");
    Ok(generation_id)
}

pub fn clean_old_generations(basedir: &Path, to_keep: usize) -> Result<()> {
    info!("Cleaning old generations");

    let mut metadata = get_metadata(basedir)?;
    let active_generation = metadata.active_generation.as_ref();

    let to_remove = metadata.generations.len() - to_keep;
    let mut removed_count = 0;
    let mut removed_active = None;
    while removed_count < to_remove {
        let Some(removed) = metadata.generations.pop_first() else {
            info!("Removed {removed_count} old generations");
            return Ok(());
        };

        if active_generation.is_some_and(|id| id == &removed.1) {
            removed_active = Some(removed);
            continue;
        }

        removed_count += 1;

        let (_ts, id) = removed;
        info!("Removing old generation: {}", id);

        let path = get_generation_path(basedir, &id);
        if let Err(e) = std::fs::remove_dir_all(&path) {
            warn!("Failed to remove file {}: {}", path.display(), e);
        }
    }

    if let Some((ts, id)) = removed_active {
        metadata.generations.insert(ts, id);
    }

    let metadata_file = basedir.join("metadata.json");
    let metadata_file = std::fs::File::create(&metadata_file)?;
    serde_json::to_writer(metadata_file, &metadata)?;

    Ok(())
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
            generations: BTreeMap::new(),
            active_generation: None,
        })
    } else {
        let metadata_file = std::fs::File::open(&metadata_file)?;
        Ok(serde_json::from_reader(metadata_file)?)
    }
}

#[derive(Debug)]
enum FilePermission {
    Decimal(u32),
}

fn set_file_permissions(
    path: &Path,
    permissions: Option<FilePermission>,
    group: Option<&str>,
    user: Option<&str>,
) -> Result<()> {
    debug!(
        "Setting permissions for file: {} to {:?} {:?} {:?}",
        path.display(),
        permissions,
        group,
        user
    );

    let file_permissions = match permissions {
        Some(FilePermission::Decimal(perm)) => u32::from_str_radix(&perm.to_string(), 8)?,
        None => 0o400,
    };

    let user = user.and_then(get_user_by_name);
    let group = group.and_then(get_group_by_name);

    set_permissions(path, Permissions::from_mode(file_permissions))?;

    if let Some(user) = user {
        chown(path, Some(user.uid()), None)?;
    }
    if let Some(group) = group {
        chown(path, None, Some(group.gid()))?;
    };

    Ok(())
}
