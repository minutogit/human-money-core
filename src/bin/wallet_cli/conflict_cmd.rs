//! Double-spend conflict and Layer-2 CLI subcommands.
//!
//! Provides inspection, export/import, override management, and resolution endorsement
//! for double-spend proofs, as well as Layer-2 lock/status queries and live synchronization.

use crate::context::CliContext;
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use human_money_core::models::conflict::{
    ProofOfDoubleSpend, ResolutionEndorsement, TrustStatus,
};
use human_money_core::models::l2_intent::L2SendIntent;
use human_money_core::models::layer2_api::L2ProcessingOutcome;
use human_money_core::wallet::ProofOfDoubleSpendSummary;
use serde::Serialize;
use std::path::{Path, PathBuf};

// =============================================================================
// CLI Subcommands
// =============================================================================

/// Subcommands for inspecting, exporting, importing, and resolving double-spend conflicts.
#[derive(Subcommand, Debug)]
pub enum ConflictCommand {
    /// List all known double-spend conflict proofs for a profile.
    List {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,
    },

    /// Show detailed information for a specific double-spend proof.
    Show {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Deterministic ID of the double-spend proof.
        proof_id: String,
    },

    /// Find the conflict proof associated with a local voucher instance.
    ForVoucher {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local voucher instance ID.
        local_id: String,
    },

    /// Check the reputation and trust status of a DID or local profile.
    Reputation {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// DID (`did:key:...`, `ephemeral:...`) or local profile name of the subject.
        did: String,
    },

    /// Export a double-spend proof to JSON or Base58 format.
    Export {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Deterministic ID of the double-spend proof.
        proof_id: String,

        /// Destination file path (optional, prints payload to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,

        /// Export as Base58-encoded JSON payload (matches `import_proof_from_json`).
        #[arg(long)]
        bs58: bool,
    },

    /// Import a double-spend proof from a file, container, or Base58 string.
    Import {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Input file path containing proof JSON or SecureContainer.
        #[arg(long = "in")]
        input: Option<PathBuf>,

        /// Base58-encoded proof JSON string.
        #[arg(long)]
        bs58: Option<String>,

        /// Flag indicating the input file is a SecureContainer.
        #[arg(long)]
        container: bool,
    },

    /// Set a manual trust override for a conflict proof.
    Override {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Deterministic ID of the double-spend proof.
        proof_id: String,

        /// Whether to allow / trust this conflict locally.
        #[arg(long)]
        allow: bool,

        /// Optional note explaining the reason for the override.
        #[arg(long)]
        note: Option<String>,
    },

    /// Create and sign a resolution endorsement for a settled conflict.
    EndorseResolution {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Deterministic ID of the double-spend proof.
        proof_id: String,

        /// Optional settlement note.
        #[arg(long)]
        notes: Option<String>,

        /// Destination file path to write the endorsement JSON (optional).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Import a signed resolution endorsement into the wallet.
    ImportEndorsement {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Input file path containing ResolutionEndorsement JSON.
        #[arg(long = "in")]
        input: PathBuf,
    },
}

/// Subcommands for Layer-2 lock/status operations and live synchronization.
#[derive(Subcommand, Debug)]
pub enum L2Command {
    /// Generate an immutable Layer-2 lock request for the latest transaction of a voucher.
    LockRequest {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local voucher instance ID.
        local_id: String,

        /// Output file path to write raw JSON bytes to (optional).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Generate a Layer-2 status query for a voucher instance.
    StatusQuery {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local voucher instance ID.
        local_id: String,

        /// Output file path to write raw JSON bytes to (optional).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Apply a raw Layer-2 HTTP response to the wallet state.
    ApplyResponse {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local voucher instance ID.
        local_id: String,

        /// Input file containing raw Layer-2 HTTP response bytes.
        #[arg(long = "in")]
        input: PathBuf,
    },

    /// List unresolved Layer-2 send intents in the wallet.
    Intents {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,
    },

    /// Synchronize a voucher's Layer-2 state directly with a gateway URL.
    Sync {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local voucher instance ID.
        local_id: String,

        /// Target Layer-2 gateway URL (e.g. http://localhost:8080/lock).
        #[arg(long)]
        url: String,
    },
}

// =============================================================================
// Output DTOs for JSON Serialization
// =============================================================================

#[derive(Serialize)]
struct ForVoucherOutput {
    local_instance_id: String,
    proof_id: Option<String>,
}

#[derive(Serialize)]
struct ReputationOutput {
    subject_id: String,
    trust_status: TrustStatus,
}

#[derive(Serialize)]
struct ExportOutput {
    proof_id: String,
    offender_id: String,
    format: String,
    out_file: Option<String>,
    payload: String,
}

#[derive(Serialize)]
struct ImportOutput {
    imported: bool,
    conflicts_count: usize,
}

#[derive(Serialize)]
struct OverrideOutput {
    proof_id: String,
    allow: bool,
    note: Option<String>,
}

#[derive(Serialize)]
struct ImportEndorsementOutput {
    imported: bool,
}

#[derive(Serialize)]
struct LockRequestOutput {
    local_instance_id: String,
    out_file: Option<String>,
    request: serde_json::Value,
}

#[derive(Serialize)]
struct StatusQueryOutput {
    local_instance_id: String,
    out_file: Option<String>,
    query: serde_json::Value,
}

#[derive(Serialize)]
struct ApplyResponseOutput {
    local_instance_id: String,
    outcome: L2ProcessingOutcome,
}

#[derive(Serialize)]
struct SyncOutput {
    local_instance_id: String,
    url: String,
    http_status: u16,
    outcome: L2ProcessingOutcome,
}

// =============================================================================
// Public Entrypoints
// =============================================================================

/// Dispatches conflict-related CLI commands.
pub fn handle_conflict(ctx: &CliContext, cmd: ConflictCommand) -> Result<()> {
    match cmd {
        ConflictCommand::List { profile } => list_conflicts(ctx, &profile),
        ConflictCommand::Show { profile, proof_id } => show_conflict(ctx, &profile, &proof_id),
        ConflictCommand::ForVoucher { profile, local_id } => for_voucher(ctx, &profile, &local_id),
        ConflictCommand::Reputation { profile, did } => check_reputation(ctx, &profile, &did),
        ConflictCommand::Export {
            profile,
            proof_id,
            out,
            bs58,
        } => export_proof(ctx, &profile, &proof_id, out, bs58),
        ConflictCommand::Import {
            profile,
            input,
            bs58,
            container,
        } => import_proof(ctx, &profile, input, bs58, container),
        ConflictCommand::Override {
            profile,
            proof_id,
            allow,
            note,
        } => set_override(ctx, &profile, &proof_id, allow, note),
        ConflictCommand::EndorseResolution {
            profile,
            proof_id,
            notes,
            out,
        } => endorse_resolution(ctx, &profile, &proof_id, notes, out),
        ConflictCommand::ImportEndorsement { profile, input } => {
            import_endorsement(ctx, &profile, &input)
        }
    }
}

/// Dispatches Layer-2 CLI commands.
pub fn handle_l2(ctx: &CliContext, cmd: L2Command) -> Result<()> {
    match cmd {
        L2Command::LockRequest {
            profile,
            local_id,
            out,
        } => lock_request(ctx, &profile, &local_id, out),
        L2Command::StatusQuery {
            profile,
            local_id,
            out,
        } => status_query(ctx, &profile, &local_id, out),
        L2Command::ApplyResponse {
            profile,
            local_id,
            input,
        } => apply_response(ctx, &profile, &local_id, &input),
        L2Command::Intents { profile } => list_intents(ctx, &profile),
        L2Command::Sync {
            profile,
            local_id,
            url,
        } => sync_l2(ctx, &profile, &local_id, &url),
    }
}

// =============================================================================
// Conflict Command Implementations
// =============================================================================

fn list_conflicts(ctx: &CliContext, profile: &str) -> Result<()> {
    let (app, profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let conflicts: Vec<ProofOfDoubleSpendSummary> = app
        .list_conflicts()
        .context("Failed to list double-spend conflicts")?;

    ctx.output(&conflicts, |list| {
        if list.is_empty() {
            println!(
                "No double-spend conflicts found for profile '{}'.",
                profile_info.profile_name
            );
        } else {
            println!(
                "Conflicts for profile '{}' ({} found):",
                profile_info.profile_name,
                list.len()
            );
            for c in list {
                let status = if c.is_resolved {
                    "Resolved"
                } else if c.local_override {
                    "Overridden (Trusted)"
                } else {
                    "Active / Fraud"
                };
                println!(
                    "  • Proof ID: {}\n    Offender: {}\n    Role: {:?}\n    Status: {}\n    Reported: {}",
                    c.proof_id, c.offender_id, c.conflict_role, status, c.report_timestamp
                );
                if let Some(ref note) = c.local_note {
                    println!("    Local Note: {note}");
                }
                if let Some(ref vname) = c.affected_voucher_name {
                    println!("    Voucher: {vname}");
                }
            }
        }
    })?;

    Ok(())
}

fn show_conflict(ctx: &CliContext, profile: &str, proof_id: &str) -> Result<()> {
    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let proof: ProofOfDoubleSpend = app
        .get_proof_of_double_spend(proof_id)
        .with_context(|| format!("Failed to find double-spend proof '{proof_id}'"))?;

    ctx.output(&proof, |p| {
        println!("Proof of Double-Spend: {}", p.proof_id);
        println!("  Offender ID: {}", p.offender_id);
        if let Some(ref s) = p.suspected_identity {
            println!("  Suspected Identity: {s}");
        }
        println!("  Fork Point Prev Hash: {}", p.fork_point_prev_hash);
        println!("  Report Timestamp: {}", p.report_timestamp);
        println!("  Reporter ID: {}", p.reporter_id);
        println!(
            "  Conflicting Transactions: {}",
            p.conflicting_transactions.len()
        );
        for (idx, tx) in p.conflicting_transactions.iter().enumerate() {
            println!(
                "    [{idx}] tx_id: {}, amount: {}, recipient: {}",
                tx.t_id, tx.amount, tx.recipient_id
            );
        }
        if let Some(ref resolutions) = p.resolutions {
            println!("  Resolutions ({}):", resolutions.len());
            for r in resolutions {
                println!(
                    "    - Endorsement {}: victim={}, ts={}",
                    r.endorsement_id, r.victim_id, r.resolution_timestamp
                );
                if let Some(ref note) = r.notes {
                    println!("      Note: {note}");
                }
            }
        }
        if let Some(ref verdict) = p.layer2_verdict {
            println!(
                "  L2 Verdict from {}: valid_tx={}",
                verdict.server_id, verdict.valid_transaction_id
            );
        }
    })?;

    Ok(())
}

fn for_voucher(ctx: &CliContext, profile: &str, local_id: &str) -> Result<()> {
    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let proof_id = app
        .get_proof_id_for_voucher(local_id)
        .with_context(|| format!("Failed to query conflict proof for voucher '{local_id}'"))?;

    let out = ForVoucherOutput {
        local_instance_id: local_id.to_string(),
        proof_id,
    };

    ctx.output(&out, |o| match &o.proof_id {
        Some(pid) => println!(
            "Voucher '{}' is associated with conflict proof ID: {}",
            o.local_instance_id, pid
        ),
        None => println!(
            "No conflict proof found for voucher '{}'.",
            o.local_instance_id
        ),
    })?;

    Ok(())
}

fn check_reputation(ctx: &CliContext, profile: &str, did: &str) -> Result<()> {
    let resolved_did = if did.contains("did:key:") || did.starts_with("ephemeral:") {
        did.to_string()
    } else {
        ctx.resolve_did_or_local_profile(did, None)?
    };

    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let trust_status = app
        .check_reputation(&resolved_did)
        .with_context(|| format!("Failed to check reputation for '{resolved_did}'"))?;

    let out = ReputationOutput {
        subject_id: resolved_did,
        trust_status,
    };

    ctx.output(&out, |o| {
        println!("Reputation for subject: {}", o.subject_id);
        match &o.trust_status {
            TrustStatus::Clean => println!("  Status: Clean (no known double-spend conflicts)"),
            TrustStatus::KnownOffender(pid) => {
                println!("  Status: Known Offender! Active conflict proof: {pid}");
            }
            TrustStatus::Resolved {
                proof_id,
                is_local,
                note,
            } => {
                println!(
                    "  Status: Resolved (proof: {proof_id}, local_override: {is_local})"
                );
                if let Some(n) = note {
                    println!("  Note: {n}");
                }
            }
        }
    })?;

    Ok(())
}

fn export_proof(
    ctx: &CliContext,
    profile: &str,
    proof_id: &str,
    out: Option<PathBuf>,
    use_bs58: bool,
) -> Result<()> {
    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let proof = app
        .get_proof_of_double_spend(proof_id)
        .with_context(|| format!("Failed to find double-spend proof '{proof_id}'"))?;

    let (format, payload) = if use_bs58 {
        let json_bytes = serde_json::to_vec(&proof)
            .context("Failed to serialize ProofOfDoubleSpend to JSON bytes")?;
        ("bs58".to_string(), bs58::encode(&json_bytes).into_string())
    } else {
        (
            "json".to_string(),
            serde_json::to_string_pretty(&proof)
                .context("Failed to serialize ProofOfDoubleSpend to pretty JSON")?,
        )
    };

    let out_file = if let Some(ref path) = out {
        std::fs::write(path, payload.as_bytes())
            .with_context(|| format!("Failed to write export to '{}'", path.display()))?;
        Some(path.display().to_string())
    } else {
        None
    };

    let result = ExportOutput {
        proof_id: proof.proof_id,
        offender_id: proof.offender_id,
        format,
        out_file,
        payload,
    };

    ctx.output(&result, |o| {
        if let Some(ref file) = o.out_file {
            println!(
                "Exported double-spend proof '{}' ({}) to '{}'.",
                o.proof_id, o.format, file
            );
        } else {
            println!("{}", o.payload);
        }
    })?;

    Ok(())
}

fn import_proof(
    ctx: &CliContext,
    profile: &str,
    input: Option<PathBuf>,
    bs58_arg: Option<String>,
    container: bool,
) -> Result<()> {
    let (mut app, _profile_info, pwd) = ctx.unlock_profile(profile)?;

    if let Some(ref str_val) = bs58_arg {
        app.import_proof_from_json(str_val.trim(), Some(&pwd))
            .context("Failed to import proof from Base58 string")?;
    } else if let Some(ref path) = input {
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read input file '{}'", path.display()))?;

        if container {
            app.import_proof_from_container(&bytes, Some(&pwd))
                .with_context(|| {
                    format!(
                        "Failed to import proof from SecureContainer in '{}'",
                        path.display()
                    )
                })?;
        } else {
            match serde_json::from_slice::<ProofOfDoubleSpend>(&bytes) {
                Ok(proof) => {
                    app.import_proof(proof, Some(&pwd))
                        .context("Failed to import proof into wallet")?;
                }
                Err(json_err) => {
                    let trimmed = match std::str::from_utf8(&bytes) {
                        Ok(s) => s.trim(),
                        Err(_) => bail!(
                            "Input file '{}' is neither valid JSON ({json_err}) nor UTF-8 Base58",
                            path.display()
                        ),
                    };
                    match bs58::decode(trimmed).into_vec() {
                        Ok(decoded_bytes) => {
                            let proof: ProofOfDoubleSpend = serde_json::from_slice(&decoded_bytes)
                                .with_context(|| {
                                    format!(
                                        "Failed to parse decoded Base58 bytes as ProofOfDoubleSpend from '{}'",
                                        path.display()
                                    )
                                })?;
                            app.import_proof(proof, Some(&pwd))
                                .context("Failed to import proof into wallet")?;
                        }
                        Err(bs58_err) => {
                            bail!(
                                "Failed to parse input file '{}' as JSON ({json_err}) or Base58 ({bs58_err})",
                                path.display()
                            );
                        }
                    }
                }
            }
        }
    } else {
        bail!("Either `--in <PATH>` or `--bs58 <STRING>` must be provided.");
    }

    let conflicts = app
        .list_conflicts()
        .context("Failed to query conflicts after import")?;
    let out = ImportOutput {
        imported: true,
        conflicts_count: conflicts.len(),
    };

    ctx.output(&out, |o| {
        println!(
            "Successfully imported double-spend proof. Total conflicts in profile: {}",
            o.conflicts_count
        );
    })?;

    Ok(())
}

fn set_override(
    ctx: &CliContext,
    profile: &str,
    proof_id: &str,
    allow: bool,
    note: Option<String>,
) -> Result<()> {
    let (mut app, _profile_info, pwd) = ctx.unlock_profile(profile)?;
    app.set_conflict_local_override(proof_id, allow, note.clone(), Some(&pwd))
        .with_context(|| format!("Failed to set local override for conflict '{proof_id}'"))?;

    let out = OverrideOutput {
        proof_id: proof_id.to_string(),
        allow,
        note,
    };

    ctx.output(&out, |o| {
        println!(
            "Set local override for proof '{}': allow={}, note={}",
            o.proof_id,
            o.allow,
            o.note.as_deref().unwrap_or("<none>")
        );
    })?;

    Ok(())
}

fn endorse_resolution(
    ctx: &CliContext,
    profile: &str,
    proof_id: &str,
    notes: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let endorsement = app
        .create_resolution_endorsement(proof_id, notes)
        .with_context(|| {
            format!("Failed to create resolution endorsement for proof '{proof_id}'")
        })?;

    let out_file = if let Some(ref path) = out {
        let serialized = serde_json::to_string_pretty(&endorsement)
            .context("Failed to serialize ResolutionEndorsement to JSON")?;
        std::fs::write(path, serialized.as_bytes())
            .with_context(|| format!("Failed to write endorsement to '{}'", path.display()))?;
        Some(path.display().to_string())
    } else {
        None
    };

    ctx.output(&endorsement, |e| {
        println!("Created Resolution Endorsement: {}", e.endorsement_id);
        println!("  Proof ID: {}", e.proof_id);
        println!("  Victim ID: {}", e.victim_id);
        println!("  Timestamp: {}", e.resolution_timestamp);
        if let Some(ref n) = e.notes {
            println!("  Notes: {n}");
        }
        if let Some(ref path) = out_file {
            println!("  Saved to: {path}");
        }
    })?;

    Ok(())
}

fn import_endorsement(ctx: &CliContext, profile: &str, input: &Path) -> Result<()> {
    let (mut app, _profile_info, pwd) = ctx.unlock_profile(profile)?;
    let bytes = std::fs::read(input)
        .with_context(|| format!("Failed to read endorsement file '{}'", input.display()))?;
    let endorsement: ResolutionEndorsement = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "Failed to parse ResolutionEndorsement from '{}'",
            input.display()
        )
    })?;

    app.import_resolution_endorsement(endorsement, Some(&pwd))
        .context("Failed to import resolution endorsement into wallet")?;

    let out = ImportEndorsementOutput { imported: true };
    ctx.output(&out, |_| {
        println!(
            "Successfully imported resolution endorsement from '{}'.",
            input.display()
        );
    })?;

    Ok(())
}

// =============================================================================
// Layer-2 Command Implementations
// =============================================================================

fn lock_request(
    ctx: &CliContext,
    profile: &str,
    local_id: &str,
    out: Option<PathBuf>,
) -> Result<()> {
    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let bytes = app
        .generate_l2_lock_request(local_id)
        .with_context(|| format!("Failed to generate L2 lock request for voucher '{local_id}'"))?;

    let out_file = if let Some(ref path) = out {
        std::fs::write(path, &bytes)
            .with_context(|| format!("Failed to write lock request to '{}'", path.display()))?;
        Some(path.display().to_string())
    } else {
        None
    };

    let json_val: serde_json::Value = serde_json::from_slice(&bytes)
        .context("Failed to parse generated lock request bytes as JSON")?;

    let result = LockRequestOutput {
        local_instance_id: local_id.to_string(),
        out_file,
        request: json_val,
    };

    ctx.output(&result, |o| {
        println!("Layer-2 Lock Request for voucher '{}':", o.local_instance_id);
        if let Some(ref file) = o.out_file {
            println!("  Saved to: {file}");
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&o.request) {
            println!("{pretty}");
        }
    })?;

    Ok(())
}

fn status_query(
    ctx: &CliContext,
    profile: &str,
    local_id: &str,
    out: Option<PathBuf>,
) -> Result<()> {
    let (app, _profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let bytes = app
        .generate_l2_status_query(local_id)
        .with_context(|| format!("Failed to generate L2 status query for voucher '{local_id}'"))?;

    let out_file = if let Some(ref path) = out {
        std::fs::write(path, &bytes)
            .with_context(|| format!("Failed to write status query to '{}'", path.display()))?;
        Some(path.display().to_string())
    } else {
        None
    };

    let json_val: serde_json::Value = serde_json::from_slice(&bytes)
        .context("Failed to parse generated status query bytes as JSON")?;

    let result = StatusQueryOutput {
        local_instance_id: local_id.to_string(),
        out_file,
        query: json_val,
    };

    ctx.output(&result, |o| {
        println!("Layer-2 Status Query for voucher '{}':", o.local_instance_id);
        if let Some(ref file) = o.out_file {
            println!("  Saved to: {file}");
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&o.query) {
            println!("{pretty}");
        }
    })?;

    Ok(())
}

fn apply_response(
    ctx: &CliContext,
    profile: &str,
    local_id: &str,
    input: &Path,
) -> Result<()> {
    let (mut app, _profile_info, pwd) = ctx.unlock_profile(profile)?;
    let bytes = std::fs::read(input)
        .with_context(|| format!("Failed to read L2 response file '{}'", input.display()))?;

    let outcome = app
        .process_l2_response(local_id.to_string(), &bytes, Some(&pwd))
        .with_context(|| format!("Failed to process L2 response for voucher '{local_id}'"))?;

    let out = ApplyResponseOutput {
        local_instance_id: local_id.to_string(),
        outcome,
    };

    ctx.output(&out, |o| {
        println!("Processed L2 response for voucher '{}':", o.local_instance_id);
        match &o.outcome {
            L2ProcessingOutcome::Found => println!("  Outcome: Found (locally confirmed)"),
            L2ProcessingOutcome::Provisional => {
                println!("  Outcome: Provisional (awaiting final quorum)");
            }
            L2ProcessingOutcome::Confirmed => {
                println!("  Outcome: Confirmed (final live-state quorum verified)");
            }
            L2ProcessingOutcome::Quarantined { reason } => {
                println!("  Outcome: Quarantined ({reason})");
            }
            L2ProcessingOutcome::SyncRequired { sync_point } => {
                println!("  Outcome: SyncRequired ({sync_point})");
            }
        }
    })?;

    Ok(())
}

fn list_intents(ctx: &CliContext, profile: &str) -> Result<()> {
    let (app, profile_info, _pwd) = ctx.unlock_profile(profile)?;
    let intents: Vec<L2SendIntent> = app
        .unresolved_l2_send_intents()
        .context("Failed to list unresolved L2 send intents")?;

    ctx.output(&intents, |list| {
        if list.is_empty() {
            println!(
                "No unresolved Layer-2 send intents for profile '{}'.",
                profile_info.profile_name
            );
        } else {
            println!(
                "Unresolved Layer-2 Send Intents for profile '{}' ({} found):",
                profile_info.profile_name,
                list.len()
            );
            for intent in list {
                println!(
                    "  • Local ID: {}\n    Network: {}, Shard: {}\n    Created At: {} ms\n    Root Valid Until: {} ms\n    Retained Original Observed: {}",
                    intent.local_instance_id,
                    intent.network,
                    intent.shard_id,
                    intent.created_at_ms,
                    intent.root_valid_until_ms,
                    intent.retained_original_observed
                );
            }
        }
    })?;

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn sync_l2(_ctx: &CliContext, _profile: &str, _local_id: &str, _url: &str) -> Result<()> {
    bail!("L2 sync over HTTP is not supported on wasm32 targets")
}

#[cfg(not(target_arch = "wasm32"))]
fn sync_l2(ctx: &CliContext, profile: &str, local_id: &str, url: &str) -> Result<()> {
    let (mut app, _profile_info, pwd) = ctx.unlock_profile(profile)?;
    let req_bytes = app
        .generate_l2_lock_request(local_id)
        .with_context(|| format!("Failed to generate L2 lock request for voucher '{local_id}'"))?;

    let (http_status, resp_bytes) = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to initialize tokio runtime for L2 sync")?;
        rt.block_on(async {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("Failed to build HTTP client")?;
            let res = client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(req_bytes)
                .send()
                .await
                .with_context(|| format!("Failed to send HTTP POST to '{url}'"))?;
            let status = res.status().as_u16();
            let bytes = res
                .bytes()
                .await
                .with_context(|| format!("Failed to read response body from '{url}'"))?
                .to_vec();
            Ok::<(u16, Vec<u8>), anyhow::Error>((status, bytes))
        })?
    };

    let outcome = app
        .process_l2_response(local_id.to_string(), &resp_bytes, Some(&pwd))
        .with_context(|| format!("Failed to process L2 response for voucher '{local_id}'"))?;

    let result = SyncOutput {
        local_instance_id: local_id.to_string(),
        url: url.to_string(),
        http_status,
        outcome,
    };

    ctx.output(&result, |o| {
        println!(
            "Synchronized voucher '{}' with Layer-2 gateway at '{}':",
            o.local_instance_id, o.url
        );
        println!("  HTTP Status: {}", o.http_status);
        match &o.outcome {
            L2ProcessingOutcome::Found => println!("  Outcome: Found (locally confirmed)"),
            L2ProcessingOutcome::Provisional => {
                println!("  Outcome: Provisional (awaiting final quorum)");
            }
            L2ProcessingOutcome::Confirmed => {
                println!("  Outcome: Confirmed (final live-state quorum verified)");
            }
            L2ProcessingOutcome::Quarantined { reason } => {
                println!("  Outcome: Quarantined ({reason})");
            }
            L2ProcessingOutcome::SyncRequired { sync_point } => {
                println!("  Outcome: SyncRequired ({sync_point})");
            }
        }
    })?;

    Ok(())
}
