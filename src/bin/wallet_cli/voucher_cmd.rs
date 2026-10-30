//! Voucher, balance, signing, and transfer CLI subcommands.
//!
//! Provides CLI handlers for inspecting voucher standards, aggregating wallet balances,
//! issuing and managing vouchers, detached-signature workflows (guarantor/notary),
//! and sending/receiving encrypted P2P transfer bundles.

use crate::context::CliContext;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use human_money_core::models::secure_container::{ContainerConfig, PrivacyMode};
use human_money_core::models::voucher::{NewVoucherData, ValueDefinition};
use human_money_core::wallet::instance::VoucherStatus;
use human_money_core::wallet::types::{
    InvolvedVoucherInfo, MultiTransferRequest, SourceTransfer, VoucherSummary,
};
use rust_decimal::Decimal;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Result DTOs for CLI JSON Output
// ---------------------------------------------------------------------------

/// Output emitted when a new voucher is successfully created.
#[derive(Debug, Clone, Serialize)]
pub struct CreatedVoucherInfo {
    pub local_instance_id: String,
    pub status: VoucherStatus,
    pub voucher_id: String,
    pub standard_uuid: String,
    pub nominal_value: ValueDefinition,
    pub is_test_voucher: bool,
}

/// Output emitted when an incomplete voucher is deleted.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteIncompleteResult {
    pub deleted: bool,
    pub local_instance_id: String,
}

/// Output emitted when a signing request bundle is written to disk.
#[derive(Debug, Clone, Serialize)]
pub struct SigningRequestResult {
    pub local_instance_id: String,
    pub out_file: String,
    pub bytes_len: usize,
}

/// Output emitted when a detached signature response is written to disk.
#[derive(Debug, Clone, Serialize)]
pub struct EndorseResult {
    pub voucher_id: String,
    pub signer_profile: String,
    pub role: String,
    pub out_file: String,
    pub bytes_len: usize,
}

/// Output emitted when a detached signature is attached to a local voucher.
#[derive(Debug, Clone, Serialize)]
pub struct AttachResult {
    pub local_instance_id: String,
    pub status: VoucherStatus,
}

/// Output emitted when a detached signature is removed from an uncirculated voucher.
#[derive(Debug, Clone, Serialize)]
pub struct RemoveSignatureResult {
    pub removed: bool,
    pub local_instance_id: String,
    pub signature_id: String,
}

/// Output emitted when an outbound transfer bundle is created.
#[derive(Debug, Clone, Serialize)]
pub struct SendResult {
    pub bundle_id: String,
    pub recipient_id: String,
    pub out_file: String,
    pub bytes_len: usize,
    pub involved_sources_details: Vec<InvolvedVoucherInfo>,
}

// ---------------------------------------------------------------------------
// CLI Argument Structs & Enums
// ---------------------------------------------------------------------------

/// Arguments for listing verified voucher standards discovered in `--standards-dir`.
#[derive(Args, Debug)]
pub struct StandardsArgs {
    /// Extra standard files to load and verify alongside discovered standards.
    #[arg(long)]
    pub standard_file: Vec<PathBuf>,
}

/// Arguments for viewing aggregated balances of a wallet profile.
#[derive(Args, Debug)]
pub struct BalanceArgs {
    /// Profile name or folder name to inspect balances for.
    #[arg(long, short = 'u')]
    pub profile: String,
}

/// Subcommands for creating, listing, inspecting, and deleting vouchers.
#[derive(Subcommand, Debug)]
pub enum VoucherCommand {
    /// List vouchers held by the profile with optional status and standard filters.
    List {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Filter by status (case-insensitive: active, incomplete, quarantined, archived, endorsed, expired).
        #[arg(long)]
        status: Option<String>,

        /// Filter by standard UUID, name, unit, or abbreviation.
        #[arg(long)]
        standard: Option<String>,
    },

    /// Show full details of a specific voucher by local instance ID.
    Show {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local instance ID of the voucher in the wallet.
        local_id: String,
    },

    /// Create a new voucher instance.
    Create {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Standard name, UUID, or path to standard .toml file.
        #[arg(long)]
        standard: String,

        /// Nominal amount of the voucher (e.g. 10 or 10.5).
        #[arg(long)]
        amount: String,

        /// Optional validity duration override (e.g. "P1Y", "P180D").
        #[arg(long)]
        validity: Option<String>,

        /// Optional description for the nominal value.
        #[arg(long)]
        description: Option<String>,

        /// Mark voucher as non-redeemable test voucher.
        #[arg(long)]
        test_voucher: bool,

        /// Extra standard files to load and verify alongside discovered standards.
        #[arg(long)]
        standard_file: Vec<PathBuf>,
    },

    /// Delete an incomplete voucher created by the user before it enters circulation.
    DeleteIncomplete {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local instance ID of the incomplete voucher.
        local_id: String,
    },
}

/// Subcommands for guarantor and notary detached-signature workflows.
#[derive(Subcommand, Debug)]
pub enum SignCommand {
    /// Create a signing request bundle to request a signature from a guarantor or notary.
    Request {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local instance ID or global voucher ID to request a signature for.
        #[arg(long)]
        voucher: String,

        /// Output path for the generated signing request container.
        #[arg(long)]
        out: PathBuf,

        /// Optional target recipient (did:key or local profile name).
        #[arg(long)]
        target: Option<String>,

        /// Emit container unencrypted in cleartext.
        #[arg(long)]
        cleartext: bool,
    },

    /// Inspect a received signing request container without importing it.
    Inspect {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Input container file path.
        #[arg(long = "in")]
        input: PathBuf,

        /// Optional container decryption password for symmetrically encrypted containers.
        #[arg(long)]
        container_password: Option<String>,
    },

    /// Endorse a received voucher signing request (adds detached guarantor/notary signature).
    Endorse {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Input container file path containing the signing request.
        #[arg(long = "in")]
        input: PathBuf,

        /// Output path for the detached signature response container.
        #[arg(long)]
        out: PathBuf,

        /// Signature role (e.g. "guarantor", "notary"). Defaults to "guarantor".
        #[arg(long, default_value = "guarantor")]
        role: String,

        /// Include signer public profile details in the signature.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        include_details: bool,

        /// Output response container in cleartext without asymmetric encryption.
        #[arg(long)]
        cleartext: bool,

        /// Optional container decryption password for opening the request.
        #[arg(long)]
        container_password: Option<String>,
    },

    /// Attach a received detached signature container to a local voucher.
    Attach {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Input file containing the detached signature container.
        #[arg(long = "in")]
        input: PathBuf,

        /// Standard name, UUID, or path to standard .toml file for validation.
        #[arg(long)]
        standard: String,

        /// Optional container decryption password.
        #[arg(long)]
        container_password: Option<String>,

        /// Extra standard files to load and verify alongside discovered standards.
        #[arg(long)]
        standard_file: Vec<PathBuf>,
    },

    /// Remove an additional signature from an incomplete voucher prior to circulation.
    Remove {
        /// Profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Local instance ID or global voucher ID.
        #[arg(long)]
        voucher: String,

        /// ID of the signature to remove.
        #[arg(long)]
        signature_id: String,
    },
}

/// Subcommands for sending and receiving encrypted P2P transfer bundles.
#[derive(Subcommand, Debug)]
pub enum TxCommand {
    /// Send voucher(s) by creating an encrypted transfer bundle.
    Send {
        /// Sender profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Recipient target: 'did:key:...' identifier or local profile name.
        #[arg(long)]
        to: String,

        /// Output file path to write the transfer bundle bytes to.
        #[arg(long)]
        out: PathBuf,

        /// Voucher standard name, UUID, or path to standard .toml file (required if --source is omitted).
        #[arg(long)]
        standard: Option<String>,

        /// Transfer amount (required if --source is omitted).
        #[arg(long)]
        amount: Option<String>,

        /// Explicit source transfer spec in format '<local_instance_id>:<amount>'. Can be passed multiple times.
        #[arg(long)]
        source: Vec<String>,

        /// Optional human-readable memo or note attached to the transfer.
        #[arg(long)]
        notes: Option<String>,

        /// Optional password to resolve local profile DID if recipient is a local profile.
        #[arg(long)]
        recipient_password: Option<String>,

        /// Force or disable privacy mode (only applicable for flexible standards).
        #[arg(long)]
        privacy_mode: Option<bool>,

        /// Create bundle with Layer-2 lock intents for the specified network (e.g. 1 = mainnet, 2 = testnet).
        #[arg(long)]
        with_l2_intents: Option<u8>,

        /// Extra standard files to load and verify alongside discovered standards.
        #[arg(long)]
        standard_file: Vec<PathBuf>,
    },

    /// Receive and process an incoming transfer bundle.
    Receive {
        /// Receiver profile name or folder name.
        #[arg(long, short = 'u')]
        profile: String,

        /// Input file path containing the transfer bundle.
        #[arg(long = "in")]
        input: PathBuf,

        /// Force accept tolerance bundle even if time or validation warnings exist.
        #[arg(long)]
        force_accept_tolerance: bool,

        /// Extra standard files to load and verify alongside discovered standards.
        #[arg(long)]
        standard_file: Vec<PathBuf>,
    },
}

// ---------------------------------------------------------------------------
// Subcommand Handlers
// ---------------------------------------------------------------------------

/// Handles the `standards` subcommand: lists all verified voucher standards.
pub fn handle_standards(ctx: &CliContext, args: StandardsArgs) -> Result<()> {
    let standards = ctx.load_standards(&args.standard_file)?;
    ctx.output(&standards, |list| {
        if list.is_empty() {
            println!("No verified voucher standards found.");
            return;
        }
        println!(
            "{:<36} {:<20} {:<8} {:<10} {:<6} PATH",
            "UUID", "NAME", "ABBR", "UNIT", "DEC"
        );
        println!("{}", "-".repeat(95));
        for s in list {
            println!(
                "{:<36} {:<20} {:<8} {:<10} {:<6} {}",
                s.uuid,
                s.name,
                s.abbreviation,
                s.unit,
                s.decimals,
                s.path.display()
            );
        }
    })
}

/// Handles the `balance` subcommand: displays aggregated balances across active vouchers.
pub fn handle_balance(ctx: &CliContext, args: BalanceArgs) -> Result<()> {
    let (app, profile_info, _pwd) = ctx.unlock_profile(&args.profile)?;
    let balances = app.with_wallet_and_identity(|w, id| {
        w.get_total_balance_by_currency(Some(id))
    })?;

    ctx.output(&balances, |list| {
        println!("Balances for profile '{}':", profile_info.profile_name);
        if list.is_empty() {
            println!("  (no active voucher balances)");
            return;
        }
        println!(
            "  {:<25} {:<15} {:<15} TEST?",
            "STANDARD", "AMOUNT", "UNIT"
        );
        println!("  {}", "-".repeat(65));
        for b in list {
            println!(
                "  {:<25} {:<15} {:<15} {}",
                b.display_standard_name,
                b.total_amount,
                b.display_currency,
                if b.is_test_voucher { "yes" } else { "no" }
            );
        }
    })
}

/// Handles the `voucher` subcommand tree (list, show, create, delete-incomplete).
pub fn handle_voucher(ctx: &CliContext, cmd: VoucherCommand) -> Result<()> {
    match cmd {
        VoucherCommand::List {
            profile,
            status,
            standard,
        } => {
            let (app, profile_info, _pwd) = ctx.unlock_profile(&profile)?;

            let standard_filter = if let Some(ref std_str) = standard {
                let uuid = ctx
                    .resolve_standard(std_str, &[])
                    .map(|s| s.uuid)
                    .unwrap_or_else(|_| std_str.clone());
                Some(vec![uuid])
            } else {
                None
            };

            let summaries = app.with_wallet_and_identity(|w, id| {
                w.list_vouchers(Some(id), standard_filter.as_deref(), None, None)
            })?;

            if let Some(ref status_req) = status {
                let s_lower = status_req.to_lowercase();
                if !matches!(
                    s_lower.as_str(),
                    "active" | "incomplete" | "quarantined" | "archived" | "endorsed" | "expired"
                ) {
                    bail!(
                        "Invalid status filter '{}'. Valid statuses: active, incomplete, quarantined, archived, endorsed, expired",
                        status_req
                    );
                }
            }

            let filtered: Vec<VoucherSummary> = if let Some(ref status_req) = status {
                let s_lower = status_req.to_lowercase();
                summaries
                    .into_iter()
                    .filter(|s| match s_lower.as_str() {
                        "active" => matches!(s.status, VoucherStatus::Active),
                        "incomplete" => matches!(s.status, VoucherStatus::Incomplete { .. }),
                        "quarantined" => matches!(s.status, VoucherStatus::Quarantined { .. }),
                        "archived" => matches!(s.status, VoucherStatus::Archived),
                        "endorsed" => matches!(s.status, VoucherStatus::Endorsed { .. }),
                        "expired" => matches!(s.status, VoucherStatus::Expired),
                        _ => false,
                    })
                    .collect()
            } else {
                summaries
            };

            ctx.output(&filtered, |list| {
                println!("Vouchers for profile '{}':", profile_info.profile_name);
                if list.is_empty() {
                    println!("  (no vouchers match the filter)");
                    return;
                }
                println!(
                    "  {:<16} {:<18} {:<12} {:<12} {:<18} {:<6} VALID UNTIL",
                    "LOCAL ID", "STATUS", "AMOUNT", "UNIT", "STANDARD", "TEST"
                );
                println!("  {}", "-".repeat(95));
                for v in list {
                    let status_str = match &v.status {
                        VoucherStatus::Active => "Active".to_string(),
                        VoucherStatus::Incomplete { reasons } => {
                            format!("Incomplete ({})", reasons.len())
                        }
                        VoucherStatus::Archived => "Archived".to_string(),
                        VoucherStatus::Quarantined { .. } => "Quarantined".to_string(),
                        VoucherStatus::Endorsed { role } => format!("Endorsed ({role})"),
                        VoucherStatus::Expired => "Expired".to_string(),
                    };
                    println!(
                        "  {:<16} {:<18} {:<12} {:<12} {:<18} {:<6} {}",
                        &v.local_instance_id[..v.local_instance_id.len().min(14)],
                        status_str,
                        v.current_amount,
                        v.display_currency,
                        &v.display_standard_name[..v.display_standard_name.len().min(16)],
                        if v.is_test_voucher { "yes" } else { "no" },
                        v.valid_until
                    );
                }
            })?;
        }

        VoucherCommand::Show { profile, local_id } => {
            let (app, _profile_info, _pwd) = ctx.unlock_profile(&profile)?;
            let details = app
                .with_wallet(|w| w.get_voucher_details(&local_id))?
                .with_context(|| format!("Failed to find voucher with ID '{}'", local_id))?;

            ctx.output(&details, |d| {
                println!("Voucher Details for '{}':", d.local_instance_id);
                println!("  Voucher ID:    {}", d.voucher.voucher_id);
                println!("  Status:        {:?}", d.status);
                println!(
                    "  Standard:      {} ({})",
                    d.display_standard_name, d.voucher.voucher_standard.uuid
                );
                println!(
                    "  Nominal Value: {} {}",
                    d.voucher.nominal_value.amount, d.display_currency
                );
                println!("  Valid Until:   {}", d.voucher.valid_until);
                println!("  Test Voucher:  {}", d.is_test_voucher);

                let creator_name = format!(
                    "{} {}",
                    d.voucher.creator_profile.first_name.as_deref().unwrap_or(""),
                    d.voucher.creator_profile.last_name.as_deref().unwrap_or("")
                );
                let creator_name = creator_name.trim();
                let creator_display = if creator_name.is_empty() {
                    d.voucher
                        .creator_profile
                        .id
                        .as_deref()
                        .unwrap_or("<unknown>")
                } else {
                    creator_name
                };
                println!(
                    "  Creator:       {} ({:?})",
                    creator_display, d.voucher.creator_profile.id
                );

                println!("  Signatures ({}):", d.voucher.signatures.len());
                for s in &d.voucher.signatures {
                    println!("    - Role: {:<12} Signer: {}", s.role, s.signer_id);
                }
                println!("  Transactions ({}):", d.voucher.transactions.len());
                for (i, tx) in d.voucher.transactions.iter().enumerate() {
                    println!(
                        "    [{}] T_ID: {} Amount: {} Sender: {:?} Recipient: {}",
                        i,
                        &tx.t_id[..tx.t_id.len().min(12)],
                        tx.amount,
                        tx.sender_id.as_deref().unwrap_or("genesis"),
                        tx.recipient_id
                    );
                }
            })?;
        }

        VoucherCommand::Create {
            profile,
            standard,
            amount,
            validity,
            description,
            test_voucher,
            standard_file,
        } => {
            let std_def = ctx.resolve_standard(&standard, &standard_file)?;
            let (mut app, _profile_info, pwd) = ctx.unlock_profile(&profile)?;

            let creator_profile = app.with_wallet(|w| w.profile.to_public_profile())?;
            let new_voucher_data = NewVoucherData {
                validity_duration: validity.or_else(|| std_def.default_validity.clone()),
                non_redeemable_test_voucher: test_voucher,
                nominal_value: ValueDefinition {
                    unit: std_def.unit.clone(),
                    amount: amount.clone(),
                    abbreviation: Some(std_def.abbreviation.clone()),
                    description,
                },
                collateral: None,
                creator_profile,
            };

            let voucher = app
                .create_new_voucher(&std_def.toml_content, new_voucher_data, Some(&pwd))
                .with_context(|| {
                    format!("Failed to create voucher for standard '{}'", std_def.name)
                })?;

            let (local_instance_id, status) = app
                .with_wallet(|w| {
                    w.voucher_store
                        .vouchers
                        .iter()
                        .find(|(_, inst)| inst.voucher.voucher_id == voucher.voucher_id)
                        .map(|(lid, inst)| (lid.clone(), inst.status.clone()))
                })?
                .ok_or_else(|| {
                    anyhow!("Created voucher not found in local wallet storage")
                })?;

            let result = CreatedVoucherInfo {
                local_instance_id,
                status,
                voucher_id: voucher.voucher_id,
                standard_uuid: voucher.voucher_standard.uuid,
                nominal_value: voucher.nominal_value,
                is_test_voucher: voucher.non_redeemable_test_voucher,
            };

            ctx.output(&result, |info| {
                println!("Created voucher successfully:");
                println!("  Local Instance ID: {}", info.local_instance_id);
                println!("  Voucher ID:        {}", info.voucher_id);
                println!("  Status:            {:?}", info.status);
                println!("  Standard UUID:     {}", info.standard_uuid);
                println!(
                    "  Nominal Value:     {} {}",
                    info.nominal_value.amount, info.nominal_value.unit
                );
                println!("  Test Voucher:      {}", info.is_test_voucher);
            })?;
        }

        VoucherCommand::DeleteIncomplete { profile, local_id } => {
            let (mut app, _profile_info, pwd) = ctx.unlock_profile(&profile)?;
            app.delete_incomplete_voucher(&local_id, Some(&pwd))
                .with_context(|| {
                    format!("Failed to delete incomplete voucher '{}'", local_id)
                })?;

            let result = DeleteIncompleteResult {
                deleted: true,
                local_instance_id: local_id.clone(),
            };

            ctx.output(&result, |res| {
                println!("Deleted incomplete voucher '{}'.", res.local_instance_id);
            })?;
        }
    }
    Ok(())
}

/// Handles the `sign` subcommand tree (request, inspect, endorse, attach, remove).
pub fn handle_sign(ctx: &CliContext, cmd: SignCommand) -> Result<()> {
    match cmd {
        SignCommand::Request {
            profile,
            voucher,
            out,
            target,
            cleartext,
        } => {
            let (app, _profile_info, _pwd) = ctx.unlock_profile(&profile)?;

            let local_instance_id = app
                .with_wallet(|w| {
                    if w.voucher_store.vouchers.contains_key(&voucher) {
                        Some(voucher.clone())
                    } else {
                        w.voucher_store
                            .vouchers
                            .iter()
                            .find(|(_, inst)| inst.voucher.voucher_id == voucher)
                            .map(|(lid, _)| lid.clone())
                    }
                })?
                .ok_or_else(|| anyhow!("Voucher '{}' not found in wallet", voucher))?;

            let config = match target.as_deref() {
                Some(target_str) if !cleartext => {
                    let target_did = ctx.resolve_did_or_local_profile(target_str, None)?;
                    ContainerConfig::TargetDid(target_did, PrivacyMode::TrialDecryption)
                }
                _ => ContainerConfig::Cleartext,
            };

            let bytes = app
                .create_signing_request_bundle(&local_instance_id, config)
                .with_context(|| {
                    format!(
                        "Failed to create signing request for voucher '{}'",
                        local_instance_id
                    )
                })?;

            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&out, &bytes)
                .with_context(|| format!("Failed to write to '{}'", out.display()))?;

            let res = SigningRequestResult {
                local_instance_id,
                out_file: out.display().to_string(),
                bytes_len: bytes.len(),
            };

            ctx.output(&res, |r| {
                println!(
                    "Created signing request bundle for voucher '{}':",
                    r.local_instance_id
                );
                println!("  Output file: {}", r.out_file);
                println!("  Size:        {} bytes", r.bytes_len);
            })?;
        }

        SignCommand::Inspect {
            profile,
            input,
            container_password,
        } => {
            let (app, _profile_info, _pwd) = ctx.unlock_profile(&profile)?;
            let bytes = fs::read(&input).with_context(|| {
                format!("Failed to read input container from '{}'", input.display())
            })?;

            let voucher = app
                .open_voucher_signing_request(&bytes, container_password.as_deref())
                .with_context(|| {
                    format!("Failed to open signing request from '{}'", input.display())
                })?;

            ctx.output(&voucher, |v| {
                println!("Voucher Signing Request:");
                println!("  Voucher ID:    {}", v.voucher_id);
                println!(
                    "  Standard:      {} ({})",
                    v.voucher_standard.name, v.voucher_standard.uuid
                );
                println!(
                    "  Nominal Value: {} {}",
                    v.nominal_value.amount, v.nominal_value.unit
                );
                println!("  Valid Until:   {}", v.valid_until);

                let creator_name = format!(
                    "{} {}",
                    v.creator_profile.first_name.as_deref().unwrap_or(""),
                    v.creator_profile.last_name.as_deref().unwrap_or("")
                );
                let creator_name = creator_name.trim();
                let creator_display = if creator_name.is_empty() {
                    v.creator_profile.id.as_deref().unwrap_or("<unknown>")
                } else {
                    creator_name
                };
                println!(
                    "  Creator:       {} ({:?})",
                    creator_display, v.creator_profile.id
                );

                println!("  Signatures ({}):", v.signatures.len());
                for s in &v.signatures {
                    println!("    - Role: {:<12} Signer: {}", s.role, s.signer_id);
                }
            })?;
        }

        SignCommand::Endorse {
            profile,
            input,
            out,
            role,
            include_details,
            cleartext,
            container_password,
        } => {
            let (mut app, profile_info, pwd) = ctx.unlock_profile(&profile)?;
            let req_bytes = fs::read(&input).with_context(|| {
                format!("Failed to read request file '{}'", input.display())
            })?;

            let voucher = app
                .open_voucher_signing_request(&req_bytes, container_password.as_deref())
                .with_context(|| {
                    format!("Failed to open signing request from '{}'", input.display())
                })?;

            let creator_did = voucher
                .creator_profile
                .id
                .clone()
                .or_else(|| voucher.transactions.first().map(|tx| tx.recipient_id.clone()))
                .ok_or_else(|| {
                    anyhow!("Voucher for signing is missing creator identity (DID)")
                })?;

            let config = if cleartext {
                ContainerConfig::Cleartext
            } else {
                ContainerConfig::TargetDid(creator_did, PrivacyMode::TrialDecryption)
            };

            let resp_bytes = app
                .create_detached_signature_response_bundle(
                    &voucher,
                    &role,
                    include_details,
                    config,
                    Some(&pwd),
                )
                .with_context(|| {
                    format!(
                        "Failed to create detached signature response for voucher '{}'",
                        voucher.voucher_id
                    )
                })?;

            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&out, &resp_bytes).with_context(|| {
                format!("Failed to write endorsement to '{}'", out.display())
            })?;

            let res = EndorseResult {
                voucher_id: voucher.voucher_id,
                signer_profile: profile_info.profile_name,
                role,
                out_file: out.display().to_string(),
                bytes_len: resp_bytes.len(),
            };

            ctx.output(&res, |r| {
                println!("Endorsed voucher '{}' successfully:", r.voucher_id);
                println!("  Role:           {}", r.role);
                println!("  Signer Profile: {}", r.signer_profile);
                println!("  Output File:    {}", r.out_file);
                println!("  Size:           {} bytes", r.bytes_len);
            })?;
        }

        SignCommand::Attach {
            profile,
            input,
            standard,
            container_password,
            standard_file,
        } => {
            let std_def = ctx.resolve_standard(&standard, &standard_file)?;
            let bytes = fs::read(&input).with_context(|| {
                format!("Failed to read endorsement file '{}'", input.display())
            })?;

            let (mut app, _profile_info, pwd) = ctx.unlock_profile(&profile)?;
            let local_id = app
                .process_and_attach_signature(
                    &bytes,
                    &std_def.toml_content,
                    container_password.as_deref(),
                    Some(&pwd),
                )
                .with_context(|| {
                    format!("Failed to attach signature from '{}'", input.display())
                })?;

            let status = app
                .with_wallet(|w| {
                    w.voucher_store
                        .vouchers
                        .get(&local_id)
                        .map(|inst| inst.status.clone())
                })?
                .ok_or_else(|| {
                    anyhow!(
                        "Voucher '{}' not found in wallet store after attachment",
                        local_id
                    )
                })?;

            let res = AttachResult {
                local_instance_id: local_id,
                status,
            };

            ctx.output(&res, |r| {
                println!("Attached signature to voucher successfully:");
                println!("  Local Instance ID: {}", r.local_instance_id);
                println!("  Status:            {:?}", r.status);
            })?;
        }

        SignCommand::Remove {
            profile,
            voucher,
            signature_id,
        } => {
            let (mut app, _profile_info, pwd) = ctx.unlock_profile(&profile)?;

            let local_instance_id = app
                .with_wallet(|w| {
                    if w.voucher_store.vouchers.contains_key(&voucher) {
                        Some(voucher.clone())
                    } else {
                        w.voucher_store
                            .vouchers
                            .iter()
                            .find(|(_, inst)| inst.voucher.voucher_id == voucher)
                            .map(|(lid, _)| lid.clone())
                    }
                })?
                .ok_or_else(|| anyhow!("Voucher '{}' not found in wallet", voucher))?;

            app.remove_voucher_signature(&local_instance_id, &signature_id, Some(&pwd))
                .with_context(|| {
                    format!(
                        "Failed to remove signature '{}' from voucher '{}'",
                        signature_id, local_instance_id
                    )
                })?;

            let res = RemoveSignatureResult {
                removed: true,
                local_instance_id,
                signature_id,
            };

            ctx.output(&res, |r| {
                println!(
                    "Removed signature '{}' from voucher '{}'.",
                    r.signature_id, r.local_instance_id
                );
            })?;
        }
    }
    Ok(())
}

/// Handles the `tx` subcommand tree (send, receive).
pub fn handle_tx(ctx: &CliContext, cmd: TxCommand) -> Result<()> {
    match cmd {
        TxCommand::Send {
            profile,
            to,
            out,
            standard,
            amount,
            source,
            notes,
            recipient_password,
            privacy_mode,
            with_l2_intents,
            standard_file,
        } => {
            let (mut app, profile_info, pwd) = ctx.unlock_profile(&profile)?;
            let recipient_id =
                ctx.resolve_did_or_local_profile(&to, recipient_password.as_deref())?;

            let sources: Vec<SourceTransfer> = if !source.is_empty() {
                let mut list = Vec::new();
                for s in &source {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() != 2
                        || parts[0].trim().is_empty()
                        || parts[1].trim().is_empty()
                    {
                        bail!(
                            "Invalid --source specification '{}'. Expected format '<local_instance_id>:<amount>'",
                            s
                        );
                    }
                    let lid = parts[0].trim().to_string();
                    let amt = parts[1].trim();
                    if Decimal::from_str(amt).is_err() {
                        bail!("Invalid amount '{}' in --source '{}'", amt, s);
                    }
                    list.push(SourceTransfer {
                        local_instance_id: lid,
                        amount_to_send: amt.to_string(),
                    });
                }
                list
            } else {
                let (std_spec, amount_str) = match (&standard, &amount) {
                    (Some(s), Some(a)) => (s, a),
                    _ => bail!(
                        "Either --source <local_instance_id>:<amount>... OR both --standard and --amount must be provided"
                    ),
                };

                let target = Decimal::from_str(amount_str).with_context(|| {
                    format!("Invalid transfer amount '{}'", amount_str)
                })?;
                if target <= Decimal::ZERO {
                    bail!(
                        "Transfer amount must be strictly positive (got '{}')",
                        amount_str
                    );
                }

                let std_def = ctx.resolve_standard(std_spec, &standard_file)?;

                let summaries = app.with_wallet_and_identity(|w, id| {
                    w.list_vouchers(
                        Some(id),
                        Some(std::slice::from_ref(&std_def.uuid)),
                        Some(&[VoucherStatus::Active]),
                        None,
                    )
                })?;

                let mut candidates: Vec<(String, Decimal)> = Vec::new();
                for s in summaries {
                    if let Ok(d) = Decimal::from_str(&s.current_amount) {
                        if d > Decimal::ZERO {
                            candidates.push((s.local_instance_id, d));
                        }
                    }
                }

                // Greedy coin selection: sort descending by amount to pick largest vouchers first
                candidates.sort_by(|a, b| b.1.cmp(&a.1));

                let total_available: Decimal = candidates.iter().map(|c| c.1).sum();
                if total_available < target {
                    bail!(
                        "Insufficient funds in active '{}' vouchers: available {}, requested {}",
                        std_def.name,
                        total_available,
                        target
                    );
                }

                let mut remaining = target;
                let mut list = Vec::new();
                for (lid, amt) in candidates {
                    if remaining <= Decimal::ZERO {
                        break;
                    }
                    let to_take = if amt <= remaining {
                        amt
                    } else {
                        remaining
                    };
                    list.push(SourceTransfer {
                        local_instance_id: lid,
                        amount_to_send: to_take.to_string(),
                    });
                    remaining -= to_take;
                }
                list
            };

            let standards_map = ctx.load_standards_toml_map(&standard_file)?;
            let request = MultiTransferRequest {
                recipient_id: recipient_id.clone(),
                sources,
                notes,
                sender_profile_name: Some(profile_info.profile_name),
                use_privacy_mode: privacy_mode,
            };

            let create_res = match with_l2_intents {
                Some(net) => app
                    .create_transfer_bundle_with_l2_intents(
                        request,
                        &standards_map,
                        None,
                        Some(&pwd),
                        net,
                    )
                    .with_context(|| {
                        format!("Failed to create transfer bundle with L2 intents (network {net})")
                    })?,
                None => app
                    .create_transfer_bundle(request, &standards_map, None, Some(&pwd))
                    .context("Failed to create transfer bundle")?,
            };

            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&out, &create_res.bundle_bytes).with_context(|| {
                format!("Failed to write transfer bundle to '{}'", out.display())
            })?;

            let res = SendResult {
                bundle_id: create_res.bundle_id,
                recipient_id,
                out_file: out.display().to_string(),
                bytes_len: create_res.bundle_bytes.len(),
                involved_sources_details: create_res.involved_sources_details,
            };

            ctx.output(&res, |r| {
                println!("Created transfer bundle successfully:");
                println!("  Bundle ID:    {}", r.bundle_id);
                println!("  Recipient:    {}", r.recipient_id);
                println!("  Output File:  {}", r.out_file);
                println!("  Size:         {} bytes", r.bytes_len);
                println!("  Sources Used ({}):", r.involved_sources_details.len());
                for s in &r.involved_sources_details {
                    println!(
                        "    - ID: {} Standard: {} Amount: {} {}",
                        &s.local_instance_id[..s.local_instance_id.len().min(14)],
                        s.display_standard_name,
                        s.amount,
                        s.display_currency
                    );
                }
            })?;
        }

        TxCommand::Receive {
            profile,
            input,
            force_accept_tolerance,
            standard_file,
        } => {
            let bytes = fs::read(&input).with_context(|| {
                format!(
                    "Failed to read incoming bundle file '{}'",
                    input.display()
                )
            })?;

            let standards_map = ctx.load_standards_toml_map(&standard_file)?;
            let (mut app, _profile_info, pwd) = ctx.unlock_profile(&profile)?;

            let proc_result = app
                .receive_bundle(
                    &bytes,
                    &standards_map,
                    None,
                    Some(&pwd),
                    force_accept_tolerance,
                )
                .with_context(|| {
                    format!(
                        "Failed to process incoming bundle from '{}'",
                        input.display()
                    )
                })?;

            ctx.output(&proc_result, |r| {
                println!("Processed received bundle successfully:");
                println!("  Bundle ID:       {}", r.header.bundle_id);
                println!("  Sender ID:       {}", r.header.sender_id);
                println!("  Timestamp:       {}", r.header.timestamp);
                if let Some(ref name) = r.header.sender_profile_name {
                    println!("  Sender Name:     {}", name);
                }
                if let Some(ref note) = r.header.notes {
                    if !note.is_empty() {
                        println!("  Notes:           {}", note);
                    }
                }
                println!("  Involved Vouchers ({}):", r.involved_vouchers.len());
                for v in &r.involved_vouchers_details {
                    println!(
                        "    - Local ID: {} Voucher ID: {} Standard: {} Amount: {} {}",
                        &v.local_instance_id[..v.local_instance_id.len().min(14)],
                        &v.voucher_id[..v.voucher_id.len().min(14)],
                        v.display_standard_name,
                        v.amount,
                        v.display_currency
                    );
                }
                if !r.transfer_summary.summable_amounts.is_empty() {
                    println!("  Summable Amounts:");
                    for (unit, sum) in &r.transfer_summary.summable_amounts {
                        println!("    - {}: {}", unit, sum);
                    }
                }
                if !r.transfer_summary.countable_items.is_empty() {
                    println!("  Countable Items:");
                    for (unit, count) in &r.transfer_summary.countable_items {
                        println!("    - {}: {}", unit, count);
                    }
                }
                if !r.check_result.verifiable_conflicts.is_empty() {
                    println!(
                        "  WARNING: Verifiable double-spend conflicts detected: {}",
                        r.check_result.verifiable_conflicts.len()
                    );
                }
                if !r.check_result.unverifiable_warnings.is_empty() {
                    println!(
                        "  WARNING: Unverifiable warnings detected: {}",
                        r.check_result.unverifiable_warnings.len()
                    );
                }
            })?;
        }
    }
    Ok(())
}
