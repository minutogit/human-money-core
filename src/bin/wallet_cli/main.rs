//! Agent-native and developer-friendly CLI controller for `human_money_core` wallets.
//!
//! Operates directly on `AppService` and `FileStorage` so wallets prepared via CLI or
//! scenario playbooks can be opened seamlessly in the Tauri desktop wallet UI.

mod conflict_cmd;
mod context;
mod profile_cmd;
mod scenario_cmd;
mod snapshot_cmd;
mod voucher_cmd;

use anyhow::Result;
use clap::{Parser, Subcommand};
use context::{CliContext, emit_error_and_exit};
use std::path::PathBuf;

/// Command-line interface for operating `human_money_core` wallets, vouchers,
/// time-travel snapshots, and multi-actor test scenarios.
#[derive(Parser, Debug)]
#[command(name = "wallet-cli", author, version, about)]
struct Cli {
    /// Base wallet storage directory containing `profiles.json` and encrypted profile folders.
    /// Defaults to `HUMOCO_DATA_DIR` or `target/cli-wallets`.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Directory searched recursively for signed voucher standard `.toml` files.
    /// Defaults to `HUMOCO_STANDARDS_DIR` or `voucher_standards`.
    #[arg(long, global = true)]
    standards_dir: Option<PathBuf>,

    /// Wallet password (falls back to `HUMOCO_PASSWORD` environment variable).
    #[arg(long, short = 'p', global = true)]
    password: Option<String>,

    /// Device identifier bound into `WalletSeal` (falls back to `HUMOCO_DEVICE_ID` or `humoco-wallet-cli`).
    #[arg(long, global = true)]
    device_id: Option<String>,

    /// Automatically perform a `WalletSeal` device handover if the profile was last opened on another device/UI.
    #[arg(long, global = true)]
    auto_handover: bool,

    /// Emit deterministic, machine-readable JSON envelopes (`{"ok": true, "data": ...}`).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum TopCommand {
    /// Generate or validate BIP-39 mnemonic seed phrases.
    #[command(subcommand)]
    Mnemonic(profile_cmd::MnemonicCommand),

    /// Manage wallet profiles, identities, public metadata, and event history.
    #[command(subcommand)]
    Profile(profile_cmd::ProfileCommand),

    /// List verified voucher standards discovered in `--standards-dir`.
    Standards(voucher_cmd::StandardsArgs),

    /// Show aggregated wallet balances by currency/standard.
    Balance(voucher_cmd::BalanceArgs),

    /// Create, list, inspect, or delete vouchers in a wallet.
    #[command(subcommand)]
    Voucher(voucher_cmd::VoucherCommand),

    /// Guarantor and notary detached-signature workflows (request, inspect, endorse, attach, remove).
    #[command(subcommand)]
    Sign(voucher_cmd::SignCommand),

    /// Send and receive P2P encrypted voucher transfer bundles.
    #[command(subcommand)]
    Tx(voucher_cmd::TxCommand),

    /// Save and restore atomic profile state snapshots (ideal for offline double-spend UI testing).
    #[command(subcommand)]
    Snapshot(snapshot_cmd::SnapshotCommand),

    /// Execute fast multi-wallet scenario playbooks in a single in-memory process.
    #[command(subcommand)]
    Scenario(scenario_cmd::ScenarioCommand),

    /// Inspect, export, import, and resolve double-spend proofs and reputation records.
    #[command(subcommand)]
    Conflict(conflict_cmd::ConflictCommand),

    /// Generate Layer-2 lock/status payloads or synchronize directly with an L2 gateway.
    #[command(subcommand)]
    L2(conflict_cmd::L2Command),
}

fn main() {
    let cli = Cli::parse();
    let json_mode = cli.json;
    let ctx = CliContext::from_args(
        cli.data_dir,
        cli.standards_dir,
        cli.password,
        cli.device_id,
        cli.auto_handover,
        cli.json,
    );

    if let Err(err) = dispatch(&ctx, cli.command) {
        emit_error_and_exit(json_mode, &err);
    }
}

fn dispatch(ctx: &CliContext, command: TopCommand) -> Result<()> {
    match command {
        TopCommand::Mnemonic(cmd) => profile_cmd::handle_mnemonic(ctx, cmd),
        TopCommand::Profile(cmd) => profile_cmd::handle_profile(ctx, cmd),
        TopCommand::Standards(args) => voucher_cmd::handle_standards(ctx, args),
        TopCommand::Balance(args) => voucher_cmd::handle_balance(ctx, args),
        TopCommand::Voucher(cmd) => voucher_cmd::handle_voucher(ctx, cmd),
        TopCommand::Sign(cmd) => voucher_cmd::handle_sign(ctx, cmd),
        TopCommand::Tx(cmd) => voucher_cmd::handle_tx(ctx, cmd),
        TopCommand::Snapshot(cmd) => snapshot_cmd::handle_snapshot(ctx, cmd),
        TopCommand::Scenario(cmd) => scenario_cmd::handle_scenario(ctx, cmd),
        TopCommand::Conflict(cmd) => conflict_cmd::handle_conflict(ctx, cmd),
        TopCommand::L2(cmd) => conflict_cmd::handle_l2(ctx, cmd),
    }
}
