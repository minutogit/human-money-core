//! Time-travel profile snapshot CLI subcommands and reusable internal primitives.
//!
//! Provides point-in-time state preservation and atomic rollback for wallet profiles,
//! primarily used for reproducible offline double-spend testing and scenario setup.

use crate::context::CliContext;
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use human_money_core::app_service::ProfileInfo;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Directory name under `data_dir` where snapshots are archived.
pub const SNAPSHOT_STORE_DIR: &str = ".cli_snapshots";

/// Metadata record associated with a saved profile snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub profile_name: String,
    pub folder_name: String,
    pub tag: String,
    pub created_at_utc: String,
    pub files_count: usize,
}

/// Snapshot management subcommands for creating, restoring, listing, and deleting snapshots.
#[derive(Subcommand, Debug)]
pub enum SnapshotCommand {
    /// Save a time-travel snapshot of a wallet profile.
    Save {
        /// Profile name or anonymous folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Snapshot tag identifier (e.g. "pre-spend", "initial").
        #[arg(long, short = 't')]
        tag: String,

        /// Overwrite existing snapshot with the same tag if it exists.
        #[arg(long)]
        overwrite: bool,
    },

    /// Restore a wallet profile to a previously saved snapshot.
    Restore {
        /// Profile name or anonymous folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Snapshot tag identifier to restore.
        #[arg(long, short = 't')]
        tag: String,
    },

    /// List available snapshots for one or all profiles.
    List {
        /// Optional profile name to filter snapshots.
        #[arg(long, short = 'u')]
        profile: Option<String>,
    },

    /// Delete a snapshot tag for a profile.
    Delete {
        /// Profile name or anonymous folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Snapshot tag identifier to delete.
        #[arg(long, short = 't')]
        tag: String,
    },
}

/// Dispatches snapshot commands.
pub fn handle_snapshot(ctx: &CliContext, cmd: SnapshotCommand) -> Result<()> {
    match cmd {
        SnapshotCommand::Save {
            profile,
            tag,
            overwrite,
        } => {
            let app = ctx.open_service()?;
            let prof_info = ctx.resolve_profile(&app, &profile)?;
            let meta = save_snapshot_internal(&ctx.data_dir, &prof_info, &tag, overwrite)?;

            ctx.output(&meta, |m| {
                println!(
                    "Snapshot '{}' successfully saved for profile '{}' ({} files).",
                    m.tag, m.profile_name, m.files_count
                );
            })
        }
        SnapshotCommand::Restore { profile, tag } => {
            let app = ctx.open_service()?;
            let prof_info = ctx.resolve_profile(&app, &profile)?;
            let meta = restore_snapshot_internal(&ctx.data_dir, &prof_info, &tag)?;

            ctx.output(&meta, |m| {
                println!(
                    "Profile '{}' successfully restored to snapshot '{}' ({} files).",
                    m.profile_name, m.tag, m.files_count
                );
            })
        }
        SnapshotCommand::List { profile } => {
            let app = ctx.open_service()?;
            let list = match profile {
                Some(name) => {
                    let prof_info = ctx.resolve_profile(&app, &name)?;
                    list_snapshots_for_profile(&ctx.data_dir, &prof_info)?
                }
                None => list_all_snapshots(&ctx.data_dir, &app.list_profiles()?)?,
            };

            ctx.output(&list, |items| {
                if items.is_empty() {
                    println!("No snapshots found.");
                } else {
                    println!(
                        "{:<20} {:<15} {:<6} {:<25}",
                        "PROFILE", "TAG", "FILES", "CREATED AT (UTC)"
                    );
                    println!("{}", "-".repeat(70));
                    for s in items {
                        println!(
                            "{:<20} {:<15} {:<6} {:<25}",
                            s.profile_name, s.tag, s.files_count, s.created_at_utc
                        );
                    }
                }
            })
        }
        SnapshotCommand::Delete { profile, tag } => {
            let app = ctx.open_service()?;
            let prof_info = ctx.resolve_profile(&app, &profile)?;
            let deleted = delete_snapshot_internal(&ctx.data_dir, &prof_info, &tag)?;

            ctx.output(&deleted, |m| {
                println!(
                    "Snapshot '{}' deleted for profile '{}'.",
                    m.tag, m.profile_name
                );
            })
        }
    }
}

/// Reusable helper to save an atomic snapshot of a profile's on-disk storage directory.
///
/// Invariants:
/// - Stored under `<data_dir>/.cli_snapshots/<folder_name>/<tag>/`.
/// - `snapshot_meta.json` saved as `<data_dir>/.cli_snapshots/<folder_name>/<tag>_meta.json` (outside raw copy dir).
/// - Lock files (`.wallet.lock`, `.wallet.transaction.lock`) and any `instance_id` files are never copied.
pub fn save_snapshot_internal(
    data_dir: &Path,
    profile: &ProfileInfo,
    tag: &str,
    overwrite: bool,
) -> Result<SnapshotMeta> {
    validate_tag_name(tag)?;

    let profile_dir = data_dir.join(&profile.folder_name);
    if !profile_dir.exists() {
        bail!(
            "Profile directory '{}' does not exist in '{}'",
            profile.folder_name,
            data_dir.display()
        );
    }
    check_no_active_lock(&profile_dir, &profile.profile_name)?;

    let snapshots_base = data_dir.join(SNAPSHOT_STORE_DIR).join(&profile.folder_name);
    let target_snapshot_dir = snapshots_base.join(tag);
    let target_meta_path = snapshots_base.join(format!("{tag}_meta.json"));

    if target_snapshot_dir.exists() {
        if !overwrite {
            bail!(
                "Snapshot '{}' already exists for profile '{}'. Pass `--overwrite` to replace it.",
                tag,
                profile.profile_name
            );
        }
        fs::remove_dir_all(&target_snapshot_dir)
            .with_context(|| format!("Failed to remove old snapshot dir '{}'", target_snapshot_dir.display()))?;
        if target_meta_path.exists() {
            let _ = fs::remove_file(&target_meta_path);
        }
    }

    fs::create_dir_all(&snapshots_base)
        .with_context(|| format!("Failed to create snapshot directory '{}'", snapshots_base.display()))?;

    // Copy atomically via temporary staging directory inside .cli_snapshots
    let nonce = uuid::Uuid::new_v4();
    let staging_dir = snapshots_base.join(format!(".tmp_save_{tag}_{nonce}"));

    let mut files_count = 0;
    let copy_result = copy_dir_recursive(&profile_dir, &staging_dir, &mut files_count);

    if let Err(err) = copy_result {
        if staging_dir.exists() {
            let _ = fs::remove_dir_all(&staging_dir);
        }
        return Err(err).context("Failed to copy profile files into snapshot staging area");
    }

    if let Err(err) = fs::rename(&staging_dir, &target_snapshot_dir) {
        if staging_dir.exists() {
            let _ = fs::remove_dir_all(&staging_dir);
        }
        return Err(err)
            .context(format!("Failed to move staging dir to final snapshot dir '{}'", target_snapshot_dir.display()));
    }

    let meta = SnapshotMeta {
        profile_name: profile.profile_name.clone(),
        folder_name: profile.folder_name.clone(),
        tag: tag.to_string(),
        created_at_utc: chrono::Utc::now().to_rfc3339(),
        files_count,
    };

    let serialized_meta = serde_json::to_string_pretty(&meta)
        .context("Failed to serialize snapshot metadata")?;
    fs::write(&target_meta_path, serialized_meta)
        .with_context(|| format!("Failed to write snapshot metadata to '{}'", target_meta_path.display()))?;

    Ok(meta)
}

/// Reusable helper to atomically restore a profile's on-disk storage directory from a snapshot.
///
/// Invariants:
/// - Verifies no active process holds a `.wallet.lock` on the target profile.
/// - Performs staging + atomic directory swap so target state is never left in an inconsistent half-copied state.
/// - Ensures restored folder never contains an active lock file.
pub fn restore_snapshot_internal(
    data_dir: &Path,
    profile: &ProfileInfo,
    tag: &str,
) -> Result<SnapshotMeta> {
    validate_tag_name(tag)?;

    let snapshots_base = data_dir.join(SNAPSHOT_STORE_DIR).join(&profile.folder_name);
    let snapshot_dir = snapshots_base.join(tag);
    let meta_path = snapshots_base.join(format!("{tag}_meta.json"));

    if !snapshot_dir.exists() {
        bail!(
            "Snapshot '{}' not found for profile '{}' at '{}'",
            tag,
            profile.profile_name,
            snapshot_dir.display()
        );
    }

    let target_dir = data_dir.join(&profile.folder_name);

    // Verify target directory has no active lock
    check_no_active_lock(&target_dir, &profile.profile_name)?;

    // Copy snapshot into a temporary staging directory in data_dir
    let nonce = uuid::Uuid::new_v4();
    let staging_dir = data_dir.join(format!(".tmp_restore_{}_{}", profile.folder_name, nonce));

    let mut restored_files_count = 0;
    let copy_res = copy_dir_recursive(&snapshot_dir, &staging_dir, &mut restored_files_count);

    if let Err(err) = copy_res {
        if staging_dir.exists() {
            let _ = fs::remove_dir_all(&staging_dir);
        }
        return Err(err).context("Failed to copy snapshot files to staging area");
    }

    // Atomic swap: move existing target_dir to backup, rename staging to target, then delete backup
    let backup_dir = data_dir.join(format!(".tmp_old_{}_{}", profile.folder_name, nonce));

    if target_dir.exists() {
        if let Err(err) = fs::rename(&target_dir, &backup_dir) {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(err).context(format!(
                "Failed to move existing profile dir '{}' to backup area",
                target_dir.display()
            ));
        }
    }

    if let Err(err) = fs::rename(&staging_dir, &target_dir) {
        // Rollback from backup if staging move failed
        if backup_dir.exists() {
            let _ = fs::rename(&backup_dir, &target_dir);
        }
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(err).context(format!(
            "Failed to move restored snapshot into target profile dir '{}'",
            target_dir.display()
        ));
    }

    if backup_dir.exists() {
        let _ = fs::remove_dir_all(&backup_dir);
    }

    // Guarantee that no lock files exist in the restored profile
    let lock_file = target_dir.join(".wallet.lock");
    if lock_file.exists() {
        let _ = fs::remove_file(lock_file);
    }
    let tx_lock_file = target_dir.join(".wallet.transaction.lock");
    if tx_lock_file.exists() {
        let _ = fs::remove_file(tx_lock_file);
    }

    // Read or construct metadata
    if meta_path.exists() {
        let content = fs::read_to_string(&meta_path)
            .with_context(|| format!("Failed to read metadata from '{}'", meta_path.display()))?;
        if let Ok(meta) = serde_json::from_str::<SnapshotMeta>(&content) {
            return Ok(meta);
        }
    }

    Ok(SnapshotMeta {
        profile_name: profile.profile_name.clone(),
        folder_name: profile.folder_name.clone(),
        tag: tag.to_string(),
        created_at_utc: chrono::Utc::now().to_rfc3339(),
        files_count: restored_files_count,
    })
}

/// Deletes a snapshot tag directory and its companion metadata.
pub fn delete_snapshot_internal(
    data_dir: &Path,
    profile: &ProfileInfo,
    tag: &str,
) -> Result<SnapshotMeta> {
    validate_tag_name(tag)?;

    let snapshots_base = data_dir.join(SNAPSHOT_STORE_DIR).join(&profile.folder_name);
    let snapshot_dir = snapshots_base.join(tag);
    let meta_path = snapshots_base.join(format!("{tag}_meta.json"));

    if !snapshot_dir.exists() && !meta_path.exists() {
        bail!(
            "Snapshot '{}' not found for profile '{}'",
            tag,
            profile.profile_name
        );
    }

    let meta = if meta_path.exists() {
        let content = fs::read_to_string(&meta_path)?;
        serde_json::from_str::<SnapshotMeta>(&content).unwrap_or_else(|_| SnapshotMeta {
            profile_name: profile.profile_name.clone(),
            folder_name: profile.folder_name.clone(),
            tag: tag.to_string(),
            created_at_utc: "unknown".to_string(),
            files_count: 0,
        })
    } else {
        SnapshotMeta {
            profile_name: profile.profile_name.clone(),
            folder_name: profile.folder_name.clone(),
            tag: tag.to_string(),
            created_at_utc: "unknown".to_string(),
            files_count: 0,
        }
    };

    if snapshot_dir.exists() {
        fs::remove_dir_all(&snapshot_dir)
            .with_context(|| format!("Failed to remove snapshot directory '{}'", snapshot_dir.display()))?;
    }
    if meta_path.exists() {
        fs::remove_file(&meta_path)
            .with_context(|| format!("Failed to remove snapshot metadata file '{}'", meta_path.display()))?;
    }

    Ok(meta)
}

/// Lists all snapshots available for a specific profile.
pub fn list_snapshots_for_profile(
    data_dir: &Path,
    profile: &ProfileInfo,
) -> Result<Vec<SnapshotMeta>> {
    let snapshots_base = data_dir.join(SNAPSHOT_STORE_DIR).join(&profile.folder_name);
    if !snapshots_base.exists() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    for entry in fs::read_dir(&snapshots_base)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let tag = entry.file_name().to_string_lossy().to_string();
            if tag.starts_with(".tmp_") {
                continue;
            }
            let meta_path = snapshots_base.join(format!("{tag}_meta.json"));
            if meta_path.exists() {
                if let Ok(content) = fs::read_to_string(&meta_path) {
                    if let Ok(meta) = serde_json::from_str::<SnapshotMeta>(&content) {
                        results.push(meta);
                        continue;
                    }
                }
            }
            // Fallback if meta file missing
            let mut file_count = 0;
            count_files_recursive(&path, &mut file_count);
            results.push(SnapshotMeta {
                profile_name: profile.profile_name.clone(),
                folder_name: profile.folder_name.clone(),
                tag,
                created_at_utc: "unknown".to_string(),
                files_count: file_count,
            });
        }
    }

    results.sort_by(|a, b| a.tag.cmp(&b.tag));
    Ok(results)
}

/// Lists all snapshots across all registered profiles in the wallet storage.
pub fn list_all_snapshots(
    data_dir: &Path,
    known_profiles: &[ProfileInfo],
) -> Result<Vec<SnapshotMeta>> {
    let snapshots_root = data_dir.join(SNAPSHOT_STORE_DIR);
    if !snapshots_root.exists() {
        return Ok(Vec::new());
    }

    let mut all = Vec::new();
    for entry in fs::read_dir(&snapshots_root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let folder_name = entry.file_name().to_string_lossy().to_string();
            let profile = known_profiles
                .iter()
                .find(|p| p.folder_name == folder_name)
                .cloned()
                .unwrap_or_else(|| ProfileInfo {
                    profile_name: folder_name.clone(),
                    folder_name: folder_name.clone(),
                });

            let prof_snapshots = list_snapshots_for_profile(data_dir, &profile)?;
            all.extend(prof_snapshots);
        }
    }

    all.sort_by(|a, b| match a.profile_name.cmp(&b.profile_name) {
        std::cmp::Ordering::Equal => a.tag.cmp(&b.tag),
        other => other,
    });
    Ok(all)
}

/// Recursively copies directory contents while filtering out locks and security traps.
fn copy_dir_recursive(src: &Path, dst: &Path, file_count: &mut usize) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create directory '{}'", dst.display()))?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Critical Security Guards:
        // 1. Never copy lock files (.wallet.lock, .wallet.transaction.lock)
        // 2. Never copy or create any file or folder named instance_id
        // 3. Skip temporary files
        if name_str == ".wallet.lock"
            || name_str == ".wallet.transaction.lock"
            || name_str == "instance_id"
            || name_str.starts_with(".tmp_")
        {
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(&file_name);

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path, file_count)?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("Failed to copy '{}' to '{}'", src_path.display(), dst_path.display()))?;
            *file_count += 1;
        }
    }

    Ok(())
}

fn count_files_recursive(dir: &Path, count: &mut usize) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    count_files_recursive(&entry.path(), count);
                } else if ft.is_file() {
                    *count += 1;
                }
            }
        }
    }
}

fn validate_tag_name(tag: &str) -> Result<()> {
    if tag.is_empty() {
        bail!("Snapshot tag cannot be empty");
    }
    if tag == "." {
        bail!("Invalid snapshot tag '.': path traversal not allowed");
    }
    if tag == "instance_id" {
        bail!("CRITICAL SECURITY VIOLATION: Tag cannot be named 'instance_id'");
    }
    if tag.len() > 64 {
        bail!("Snapshot tag '{}' exceeds maximum allowed length of 64 characters", tag);
    }
    if !tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        bail!("Invalid snapshot tag '{}': path separators and traversal not allowed (must be ASCII alphanumeric, '_' or '-')", tag);
    }
    Ok(())
}

fn check_no_active_lock(profile_dir: &Path, profile_name: &str) -> Result<()> {
    let lock_file = profile_dir.join(".wallet.lock");
    if lock_file.exists() {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(content) = fs::read_to_string(&lock_file) {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    let mut s = sysinfo::System::new();
                    s.refresh_processes();
                    if s.process(sysinfo::Pid::from_u32(pid)).is_some() {
                        bail!(
                            "Cannot access profile '{}': wallet is currently locked by active process (PID {})",
                            profile_name,
                            pid
                        );
                    }
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            bail!(
                "Cannot access profile '{}': wallet lock file is present",
                profile_name
            );
        }
    }

    #[cfg(unix)]
    {
        let tx_lock_path = profile_dir.join(".wallet.transaction.lock");
        if tx_lock_path.exists() {
            if let Ok(file) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&tx_lock_path)
            {
                if let Err(e) = file.try_lock() {
                    bail!(
                        "Cannot access profile '{}': wallet transaction is currently in progress ({})",
                        profile_name,
                        e
                    );
                }
                let _ = file.unlock();
            }
        }
    }

    Ok(())
}
