//! Fast in-memory multi-actor scenario runner CLI subcommands.
//!
//! Enables automated testing and orchestrating complex multi-wallet flows (e.g. multi-actor
//! onboarding, guarantor endorsements, split transfers, and staged offline double-spending)
//! in a single process (<200ms, only 1 Argon2 key derivation per actor).

use crate::context::CliContext;
use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use human_money_core::app_service::{AppService, ProfileInfo};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::secure_container::{ContainerConfig, PrivacyMode};
use human_money_core::models::voucher::{NewVoucherData, ValueDefinition};
use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use human_money_core::services::mnemonic::MnemonicLanguage;
use human_money_core::wallet::instance::VoucherStatus;
use human_money_core::wallet::types::{AggregatedBalance, MultiTransferRequest, SourceTransfer};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;

/// Scenario execution CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum ScenarioCommand {
    /// Execute a multi-wallet scenario playbook file.
    Run {
        /// Path to the JSON scenario playbook file.
        file: PathBuf,
    },

    /// Print documentation and an example JSON playbook schema for scenario files.
    Schema,
}

/// Root data structure of a scenario playbook file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub steps: Vec<ScenarioStep>,
}

/// Action step definition within a scenario playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ScenarioStep {
    /// Creates a brand new wallet profile in the storage directory.
    CreateProfile {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mnemonic: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gender: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_name: Option<String>,
    },

    /// Creates a newly minted voucher for an actor.
    CreateVoucher {
        profile: String,
        standard: String,
        amount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        validity: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        test_voucher: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        save_ref: Option<String>,
    },

    /// Executes the full 3-step detached signature endorsement roundtrip between creator and signer.
    EndorseVoucher {
        creator: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        voucher_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        standard: Option<String>,
        signer: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },

    /// Transfers funds from one actor to another using greedy coin selection.
    Transfer {
        from: String,
        to: String,
        standard: String,
        amount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bundle_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        out_file: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_receive: Option<bool>,
    },

    /// Ingests a transfer or signature bundle into a profile's wallet.
    ReceiveBundle {
        profile: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bundle_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        in_file: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        force_accept_tolerance: Option<bool>,
    },

    /// Flushes and drops an actor's lock, then creates an atomic point-in-time snapshot.
    SnapshotSave {
        profile: String,
        tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        overwrite: Option<bool>,
    },

    /// Flushes and drops an actor's lock, then restores the profile directory from a snapshot.
    SnapshotRestore {
        profile: String,
        tag: String,
    },
}

/// Execution report summarizing a scenario run.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioExecutionReport {
    pub scenario_file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub total_steps: usize,
    pub completed_steps: usize,
    pub total_duration_ms: u128,
    pub step_results: Vec<StepExecutionResult>,
    pub actors: Vec<ActorSummary>,
}

/// Status of an individual executed scenario step.
#[derive(Debug, Clone, Serialize)]
pub struct StepExecutionResult {
    pub step_index: usize,
    pub action: String,
    pub description: String,
    pub duration_ms: u128,
}

/// Final state summary for an actor at the conclusion of a scenario.
#[derive(Debug, Clone, Serialize)]
pub struct ActorSummary {
    pub profile_name: String,
    pub user_id: String,
    pub balances: Vec<AggregatedBalance>,
}

/// Schema documentation object printed by `wallet-cli scenario schema`.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioSchemaDoc {
    pub documentation: String,
    pub supported_actions: Vec<&'static str>,
    pub example: ScenarioFile,
}

/// An active in-memory actor with an unlocked `AppService`.
struct UnlockedActor {
    app: AppService,
    profile: ProfileInfo,
    password: String,
    user_id: String,
}

impl Drop for UnlockedActor {
    fn drop(&mut self) {
        // Ensure that dropping UnlockedActor automatically releases the on-disk lock
        self.app.logout();
    }
}

/// Cached credentials enabling lazy re-login after snapshot operations.
#[derive(Clone)]
struct ActorCredentials {
    profile: ProfileInfo,
    password: String,
    user_id: String,
}

/// Entry point dispatching scenario commands.
pub fn handle_scenario(ctx: &CliContext, cmd: ScenarioCommand) -> Result<()> {
    match cmd {
        ScenarioCommand::Run { file } => run_scenario(ctx, &file),
        ScenarioCommand::Schema => print_schema(ctx),
    }
}

/// Executes a scenario playbook file sequentially.
fn run_scenario(ctx: &CliContext, scenario_path: &Path) -> Result<()> {
    let raw_content = fs::read_to_string(scenario_path)
        .with_context(|| format!("Failed to read scenario file '{}'", scenario_path.display()))?;

    let scenario: ScenarioFile = serde_json::from_str(&raw_content)
        .with_context(|| format!("Failed to parse scenario JSON '{}'", scenario_path.display()))?;

    let start_overall = Instant::now();

    let mut actors: HashMap<String, UnlockedActor> = HashMap::new();
    let mut known_actors: HashMap<String, ActorCredentials> = HashMap::new();
    let mut voucher_refs: HashMap<String, String> = HashMap::new();
    let mut bundles: HashMap<String, Vec<u8>> = HashMap::new();

    let total_steps = scenario.steps.len();
    let mut step_results = Vec::new();

    for (idx, step) in scenario.steps.into_iter().enumerate() {
        let step_start = Instant::now();
        let action_name = step_action_name(&step);
        let step_desc = step_description(&step);

        execute_step(
            ctx,
            step,
            &mut actors,
            &mut known_actors,
            &mut voucher_refs,
            &mut bundles,
        )
        .with_context(|| format!("Step {} ('{}') failed", idx + 1, action_name))?;

        let duration_ms = step_start.elapsed().as_millis();
        step_results.push(StepExecutionResult {
            step_index: idx + 1,
            action: action_name.to_string(),
            description: step_desc,
            duration_ms,
        });
    }

    // Collect final state and balances for all registered actors
    let mut actor_summaries = Vec::new();
    let mut actor_keys: Vec<String> = known_actors.keys().cloned().collect();
    actor_keys.sort();

    for name in actor_keys {
        let actor = get_or_unlock_actor(&mut actors, &known_actors, ctx, &name)?;
        let balances = actor.app.with_wallet_and_identity(|wallet, identity| {
            wallet.get_total_balance_by_currency(Some(identity))
        })?;

        actor_summaries.push(ActorSummary {
            profile_name: actor.profile.profile_name.clone(),
            user_id: actor.user_id.clone(),
            balances,
        });
    }

    let report = ScenarioExecutionReport {
        scenario_file: scenario_path.to_path_buf(),
        description: scenario.description,
        total_steps,
        completed_steps: step_results.len(),
        total_duration_ms: start_overall.elapsed().as_millis(),
        step_results,
        actors: actor_summaries,
    };

    ctx.output(&report, |rep| {
        println!("=== Scenario Execution Report ===");
        if let Some(desc) = &rep.description {
            println!("Playbook: {desc}");
        }
        println!("File: {}", rep.scenario_file.display());
        println!(
            "Steps: {}/{} completed in {}ms\n",
            rep.completed_steps, rep.total_steps, rep.total_duration_ms
        );

        println!("{:<4} {:<18} {:<40} {:<10}", "#", "ACTION", "DETAILS", "DURATION");
        println!("{}", "-".repeat(76));
        for r in &rep.step_results {
            println!(
                "{:<4} {:<18} {:<40} {}ms",
                r.step_index,
                r.action,
                truncate_str(&r.description, 40),
                r.duration_ms
            );
        }

        println!("\n=== Final Actor Balances ===");
        for a in &rep.actors {
            println!("Actor: {} ({})", a.profile_name, a.user_id);
            if a.balances.is_empty() {
                println!("  Balances: <none>");
            } else {
                for b in &a.balances {
                    println!(
                        "  - {} {} ({})",
                        b.total_amount, b.display_currency, b.display_standard_name
                    );
                }
            }
        }
    })
}

/// Executes a single step of the scenario playbook.
fn execute_step(
    ctx: &CliContext,
    step: ScenarioStep,
    actors: &mut HashMap<String, UnlockedActor>,
    known_actors: &mut HashMap<String, ActorCredentials>,
    voucher_refs: &mut HashMap<String, String>,
    bundles: &mut HashMap<String, Vec<u8>>,
) -> Result<()> {
    match step {
        ScenarioStep::CreateProfile {
            name,
            prefix,
            password,
            mnemonic,
            gender,
            first_name,
            last_name,
        } => {
            let pwd = password
                .or_else(|| ctx.password.clone())
                .unwrap_or_else(|| "scenario-password".to_string());

            let phrase = match mnemonic {
                Some(m) => {
                    AppService::validate_mnemonic(&m, MnemonicLanguage::English)
                        .context("Invalid mnemonic provided")?;
                    m
                }
                None => AppService::generate_mnemonic(24, MnemonicLanguage::English)
                    .context("Failed to generate mnemonic")?,
            };

            let device_id = format!("{name}-device");
            let mut app = ctx.open_service()?;

            app.create_profile(
                &name,
                &phrase,
                None,
                prefix.as_deref(),
                &pwd,
                MnemonicLanguage::English,
                device_id,
            )?;

            if first_name.is_some() || last_name.is_some() || gender.is_some() {
                let mut pub_profile = PublicProfile::default();
                pub_profile.first_name = first_name;
                pub_profile.last_name = last_name;
                pub_profile.gender = gender;
                app.update_public_profile(pub_profile, Some(&pwd))?;
            }

            let user_id = app.with_wallet(|w| w.get_user_id().to_string())?;
            let profiles = app.list_profiles()?;
            let profile = profiles
                .into_iter()
                .find(|p| p.profile_name == name)
                .ok_or_else(|| anyhow!("Profile '{}' not found in profiles index after creation", name))?;

            known_actors.insert(
                name.clone(),
                ActorCredentials {
                    profile: profile.clone(),
                    password: pwd.clone(),
                    user_id: user_id.clone(),
                },
            );

            actors.insert(
                name,
                UnlockedActor {
                    app,
                    profile,
                    password: pwd,
                    user_id,
                },
            );

            Ok(())
        }

        ScenarioStep::CreateVoucher {
            profile,
            standard,
            amount,
            validity,
            description,
            test_voucher,
            save_ref,
        } => {
            let std_info = ctx.resolve_standard(&standard, &[])?;
            let (verified_standard, _) =
                VoucherStandardDefinition::from_toml(&std_info.toml_content)?;

            let actor = get_or_unlock_actor(actors, known_actors, ctx, &profile)?;
            let creator_profile = actor.app.with_wallet(|w| w.profile.to_public_profile())?;

            let voucher_data = NewVoucherData {
                validity_duration: validity.or(std_info.default_validity),
                non_redeemable_test_voucher: test_voucher.unwrap_or(false),
                nominal_value: ValueDefinition {
                    unit: verified_standard.immutable.blueprint.unit.clone(),
                    amount,
                    abbreviation: Some(verified_standard.immutable.identity.abbreviation.clone()),
                    description,
                },
                collateral: None,
                creator_profile,
            };

            let created = actor
                .app
                .create_new_voucher(&std_info.toml_content, voucher_data, Some(&actor.password))?;

            let local_id = actor
                .app
                .with_wallet(|w| {
                    w.voucher_store
                        .vouchers
                        .iter()
                        .find(|(_, inst)| inst.voucher.voucher_id == created.voucher_id)
                        .map(|(id, _)| id.clone())
                })?
                .ok_or_else(|| anyhow!("Created voucher not found in voucher store"))?;

            if let Some(r) = save_ref {
                voucher_refs.insert(r, local_id);
            }

            Ok(())
        }

        ScenarioStep::EndorseVoucher {
            creator,
            voucher_ref,
            standard,
            signer,
            role,
        } => {
            // 1. Resolve local voucher ID on creator
            let local_id = match &voucher_ref {
                Some(r) => voucher_refs
                    .get(r)
                    .cloned()
                    .ok_or_else(|| anyhow!("Voucher reference '{r}' not found in scenario refs"))?,
                None => {
                    let actor = get_or_unlock_actor(actors, known_actors, ctx, &creator)?;
                    actor
                        .app
                        .with_wallet(|w| {
                            w.voucher_store
                                .vouchers
                                .iter()
                                .filter(|(_, inst)| {
                                    matches!(
                                        inst.status,
                                        VoucherStatus::Incomplete { .. } | VoucherStatus::Active
                                    )
                                })
                                .last()
                                .map(|(id, _)| id.clone())
                        })?
                        .ok_or_else(|| {
                            anyhow!("No active or incomplete voucher found in creator '{}' wallet", creator)
                        })?
                }
            };

            // 2. Read signer identity and creator identity
            let signer_user_id = {
                let signer_actor = get_or_unlock_actor(actors, known_actors, ctx, &signer)?;
                signer_actor.user_id.clone()
            };

            let creator_user_id = {
                let creator_actor = get_or_unlock_actor(actors, known_actors, ctx, &creator)?;
                creator_actor.user_id.clone()
            };

            // 3. Creator generates signing request bundle
            let request_bytes = {
                let creator_actor = get_or_unlock_actor(actors, known_actors, ctx, &creator)?;
                let req_config =
                    ContainerConfig::TargetDid(signer_user_id, PrivacyMode::TrialDecryption);
                match creator_actor
                    .app
                    .create_signing_request_bundle(&local_id, req_config)
                {
                    Ok(b) => b,
                    Err(_) => creator_actor
                        .app
                        .create_signing_request_bundle(&local_id, ContainerConfig::Cleartext)?,
                }
            };

            // 4. Signer reviews and creates detached signature response bundle
            let endorsement_role = role.as_deref().unwrap_or("guarantor");
            let response_bytes = {
                let signer_actor = get_or_unlock_actor(actors, known_actors, ctx, &signer)?;
                let voucher_to_sign = signer_actor
                    .app
                    .open_voucher_signing_request(&request_bytes, None)?;
                let resp_config =
                    ContainerConfig::TargetDid(creator_user_id, PrivacyMode::TrialDecryption);

                match signer_actor.app.create_detached_signature_response_bundle(
                    &voucher_to_sign,
                    endorsement_role,
                    true,
                    resp_config,
                    Some(&signer_actor.password),
                ) {
                    Ok(b) => b,
                    Err(_) => signer_actor.app.create_detached_signature_response_bundle(
                        &voucher_to_sign,
                        endorsement_role,
                        true,
                        ContainerConfig::Cleartext,
                        Some(&signer_actor.password),
                    )?,
                }
            };

            // 5. Creator attaches detached signature
            let standard_toml = match standard {
                Some(s) => ctx.resolve_standard(&s, &[])?.toml_content,
                None => {
                    let uuid = {
                        let creator_actor = get_or_unlock_actor(actors, known_actors, ctx, &creator)?;
                        creator_actor
                            .app
                            .with_wallet(|w| {
                                w.voucher_store
                                    .vouchers
                                    .get(&local_id)
                                    .map(|inst| inst.voucher.voucher_standard.uuid.clone())
                            })?
                            .ok_or_else(|| anyhow!("Voucher '{}' not found in creator wallet", local_id))?
                    };
                    ctx.resolve_standard(&uuid, &[])?.toml_content
                }
            };

            let creator_actor = get_or_unlock_actor(actors, known_actors, ctx, &creator)?;
            let updated_id = creator_actor.app.process_and_attach_signature(
                &response_bytes,
                &standard_toml,
                None,
                Some(&creator_actor.password),
            )?;

            if let Some(r) = voucher_ref {
                voucher_refs.insert(r, updated_id);
            }

            Ok(())
        }

        ScenarioStep::Transfer {
            from,
            to,
            standard,
            amount,
            notes,
            bundle_ref,
            out_file,
            auto_receive,
        } => {
            // Resolve recipient
            let (recipient_id, is_local_actor) = if let Some(actor) = known_actors.get(&to) {
                (actor.user_id.clone(), true)
            } else if to.starts_with("did:key:") {
                (to.clone(), false)
            } else {
                match ctx.resolve_did_or_local_profile(&to, None) {
                    Ok(did) => (did, true),
                    Err(_) => (to.clone(), false),
                }
            };

            let std_info = ctx.resolve_standard(&standard, &[])?;
            let toml_map = ctx.load_standards_toml_map(&[])?;
            let needed = Decimal::from_str(&amount).context("Invalid transfer amount")?;

            // Greedy coin selection from sender's active vouchers
            let sources = {
                let from_actor = get_or_unlock_actor(actors, known_actors, ctx, &from)?;
                let summaries = from_actor.app.with_wallet_and_identity(|wallet, identity| {
                    wallet.list_vouchers(
                        Some(identity),
                        Some(std::slice::from_ref(&std_info.uuid)),
                        Some(&[VoucherStatus::Active]),
                        None,
                    )
                })?;

                let mut available = Vec::new();
                for s in summaries {
                    if let Ok(val) = Decimal::from_str(&s.current_amount) {
                        if val > Decimal::ZERO {
                            available.push((s.local_instance_id, val));
                        }
                    }
                }

                if available.is_empty() {
                    bail!(
                        "Profile '{}' has no active vouchers matching standard '{}'",
                        from,
                        std_info.name
                    );
                }

                let mut remaining = needed;
                let mut chosen = Vec::new();

                for (inst_id, cur_bal) in available {
                    if remaining <= Decimal::ZERO {
                        break;
                    }
                    let take = if !std_info.allow_partial_transfers {
                        cur_bal
                    } else {
                        cur_bal.min(remaining)
                    };
                    chosen.push(SourceTransfer {
                        local_instance_id: inst_id,
                        amount_to_send: take.to_string(),
                    });
                    remaining -= take;
                }

                if remaining > Decimal::ZERO {
                    bail!(
                        "Insufficient funds for profile '{}': needed {} {}, but only found {}",
                        from,
                        amount,
                        std_info.unit,
                        needed - remaining
                    );
                }
                chosen
            };

            let from_actor = get_or_unlock_actor(actors, known_actors, ctx, &from)?;
            let request = MultiTransferRequest {
                recipient_id,
                sources,
                notes,
                sender_profile_name: Some(from_actor.profile.profile_name.clone()),
                use_privacy_mode: None,
            };

            let bundle_res = from_actor.app.create_transfer_bundle(
                request,
                &toml_map,
                None,
                Some(&from_actor.password),
            )?;
            let bundle_bytes = bundle_res.bundle_bytes;

            if let Some(r) = bundle_ref {
                bundles.insert(r, bundle_bytes.clone());
            }

            if let Some(out) = out_file {
                fs::write(&out, &bundle_bytes)
                    .with_context(|| format!("Failed to write bundle to '{}'", out.display()))?;
            }

            let should_auto_receive = auto_receive.unwrap_or(true);
            if should_auto_receive && is_local_actor && known_actors.contains_key(&to) {
                let to_actor = get_or_unlock_actor(actors, known_actors, ctx, &to)?;
                to_actor.app.receive_bundle(
                    &bundle_bytes,
                    &toml_map,
                    None,
                    Some(&to_actor.password),
                    false,
                )?;
            }

            Ok(())
        }

        ScenarioStep::ReceiveBundle {
            profile,
            bundle_ref,
            in_file,
            force_accept_tolerance,
        } => {
            let bundle_bytes = match (bundle_ref, in_file) {
                (Some(r), _) => bundles
                    .get(&r)
                    .cloned()
                    .ok_or_else(|| anyhow!("Bundle reference '{r}' not found in scenario bundles"))?,
                (None, Some(p)) => fs::read(&p)
                    .with_context(|| format!("Failed to read bundle file '{}'", p.display()))?,
                (None, None) => bail!("ReceiveBundle requires either `bundle_ref` or `in_file`"),
            };

            let toml_map = ctx.load_standards_toml_map(&[])?;
            let actor = get_or_unlock_actor(actors, known_actors, ctx, &profile)?;

            actor.app.receive_bundle(
                &bundle_bytes,
                &toml_map,
                None,
                Some(&actor.password),
                force_accept_tolerance.unwrap_or(false),
            )?;

            Ok(())
        }

        ScenarioStep::SnapshotSave {
            profile,
            tag,
            overwrite,
        } => {
            let cred = known_actors
                .get(&profile)
                .ok_or_else(|| anyhow!("Profile '{}' is not registered among scenario actors", profile))?
                .clone();

            // CRITICAL LOCK RULE: Drop open AppService so .wallet.lock is freed and files flushed
            if let Some(active) = actors.remove(&profile) {
                drop(active);
            }

            crate::snapshot_cmd::save_snapshot_internal(
                &ctx.data_dir,
                &cred.profile,
                &tag,
                overwrite.unwrap_or(false),
            )?;

            Ok(())
        }

        ScenarioStep::SnapshotRestore { profile, tag } => {
            let cred = known_actors
                .get(&profile)
                .ok_or_else(|| anyhow!("Profile '{}' is not registered among scenario actors", profile))?
                .clone();

            // CRITICAL LOCK RULE: Drop open AppService before restoring disk state
            if let Some(active) = actors.remove(&profile) {
                drop(active);
            }

            crate::snapshot_cmd::restore_snapshot_internal(
                &ctx.data_dir,
                &cred.profile,
                &tag,
            )?;

            Ok(())
        }
    }
}

/// Helper resolving or lazily logging in an actor to an unlocked state.
fn get_or_unlock_actor<'a>(
    actors: &'a mut HashMap<String, UnlockedActor>,
    known_actors: &HashMap<String, ActorCredentials>,
    ctx: &CliContext,
    name: &str,
) -> Result<&'a mut UnlockedActor> {
    if !actors.contains_key(name) {
        let cred = if let Some(c) = known_actors.get(name) {
            c.clone()
        } else {
            let app = ctx.open_service()?;
            let prof = ctx.resolve_profile(&app, name)?;
            let pwd = ctx.require_password()?.to_string();
            let user_id = app.get_profile_id_with_password(&prof.folder_name, &pwd)?;
            ActorCredentials {
                profile: prof,
                password: pwd,
                user_id,
            }
        };

        let mut app = ctx.open_service()?;
        app.login(
            &cred.profile.folder_name,
            &cred.password,
            false,
            format!("{name}-device"),
        )?;

        actors.insert(
            name.to_string(),
            UnlockedActor {
                app,
                profile: cred.profile,
                password: cred.password,
                user_id: cred.user_id,
            },
        );
    }

    Ok(actors.get_mut(name).expect("Actor guaranteed to exist in map"))
}

fn step_action_name(step: &ScenarioStep) -> &'static str {
    match step {
        ScenarioStep::CreateProfile { .. } => "create_profile",
        ScenarioStep::CreateVoucher { .. } => "create_voucher",
        ScenarioStep::EndorseVoucher { .. } => "endorse_voucher",
        ScenarioStep::Transfer { .. } => "transfer",
        ScenarioStep::ReceiveBundle { .. } => "receive_bundle",
        ScenarioStep::SnapshotSave { .. } => "snapshot_save",
        ScenarioStep::SnapshotRestore { .. } => "snapshot_restore",
    }
}

fn step_description(step: &ScenarioStep) -> String {
    match step {
        ScenarioStep::CreateProfile { name, .. } => format!("Profile '{name}'"),
        ScenarioStep::CreateVoucher {
            profile,
            standard,
            amount,
            ..
        } => format!("'{profile}' minted {amount} {standard}"),
        ScenarioStep::EndorseVoucher {
            creator,
            signer,
            role,
            ..
        } => format!(
            "'{}' endorsed by '{}' as {}",
            creator,
            signer,
            role.as_deref().unwrap_or("guarantor")
        ),
        ScenarioStep::Transfer {
            from,
            to,
            standard,
            amount,
            ..
        } => format!("{amount} {standard} from '{from}' to '{to}'"),
        ScenarioStep::ReceiveBundle { profile, .. } => format!("Profile '{profile}' ingested bundle"),
        ScenarioStep::SnapshotSave { profile, tag, .. } => {
            format!("Profile '{profile}' snapshot '{tag}'")
        }
        ScenarioStep::SnapshotRestore { profile, tag } => {
            format!("Profile '{profile}' restored from '{tag}'")
        }
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

/// Emits scenario schema documentation and a complete runnable example JSON playbook.
fn print_schema(ctx: &CliContext) -> Result<()> {
    let example = ScenarioFile {
        description: Some("Multi-actor Minuto issuance, guarantor endorsement, and offline double-spend test".to_string()),
        steps: vec![
            ScenarioStep::CreateProfile {
                name: "Alice".to_string(),
                prefix: Some("issuer".to_string()),
                password: Some("alice-pass-123".to_string()),
                mnemonic: None,
                gender: Some("female".to_string()),
                first_name: Some("Alice".to_string()),
                last_name: Some("Smith".to_string()),
            },
            ScenarioStep::CreateProfile {
                name: "Bob".to_string(),
                prefix: Some("trader".to_string()),
                password: Some("bob-pass-123".to_string()),
                mnemonic: None,
                gender: Some("male".to_string()),
                first_name: Some("Bob".to_string()),
                last_name: Some("Jones".to_string()),
            },
            ScenarioStep::CreateProfile {
                name: "GuarantorCharlie".to_string(),
                prefix: Some("guarantor".to_string()),
                password: Some("charlie-pass-123".to_string()),
                mnemonic: None,
                gender: Some("male".to_string()),
                first_name: Some("Charlie".to_string()),
                last_name: Some("Brown".to_string()),
            },
            ScenarioStep::CreateVoucher {
                profile: "Alice".to_string(),
                standard: "minuto".to_string(),
                amount: "100.00".to_string(),
                validity: Some("3Y".to_string()),
                description: Some("Handcrafted furniture repair services".to_string()),
                test_voucher: Some(false),
                save_ref: Some("alice_voucher_1".to_string()),
            },
            ScenarioStep::EndorseVoucher {
                creator: "Alice".to_string(),
                voucher_ref: Some("alice_voucher_1".to_string()),
                standard: Some("minuto".to_string()),
                signer: "GuarantorCharlie".to_string(),
                role: Some("guarantor".to_string()),
            },
            ScenarioStep::SnapshotSave {
                profile: "Alice".to_string(),
                tag: "pre_double_spend".to_string(),
                overwrite: Some(true),
            },
            ScenarioStep::Transfer {
                from: "Alice".to_string(),
                to: "Bob".to_string(),
                standard: "minuto".to_string(),
                amount: "40.00".to_string(),
                notes: Some("First payment branch".to_string()),
                bundle_ref: Some("payment_to_bob".to_string()),
                out_file: None,
                auto_receive: Some(true),
            },
            ScenarioStep::SnapshotRestore {
                profile: "Alice".to_string(),
                tag: "pre_double_spend".to_string(),
            },
        ],
    };

    let doc = ScenarioSchemaDoc {
        documentation: "Scenario playbooks execute multi-wallet operations in a single fast in-memory process. Steps execute sequentially. Unlocked actor instances are cached and automatically release on-disk locks prior to snapshot save/restore operations.".to_string(),
        supported_actions: vec![
            "create_profile",
            "create_voucher",
            "endorse_voucher",
            "transfer",
            "receive_bundle",
            "snapshot_save",
            "snapshot_restore",
        ],
        example,
    };

    ctx.output(&doc, |d| {
        println!("=== Human Money Core — Multi-Actor Scenario Playbook Schema ===");
        println!("{}\n", d.documentation);
        println!("Supported Actions: {}", d.supported_actions.join(", "));
        println!("\nExample Playbook JSON:\n");
        if let Ok(pretty) = serde_json::to_string_pretty(&d.example) {
            println!("{pretty}");
        }
    })
}
