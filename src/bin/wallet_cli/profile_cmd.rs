//! Profile, mnemonic, identity, and wallet event CLI subcommands.
//!
//! Provides CLI interfaces for:
//! - Generating and validating BIP-39 seed phrases
//! - Managing encrypted wallet profiles (list, create, inspect, update, delete)
//! - Viewing chronological wallet audit events

use crate::context::CliContext;
use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use human_money_core::app_service::{AppService, ProfileInfo};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::seal::SyncStatus;
use human_money_core::models::voucher::Address;
use human_money_core::models::wallet_event::WalletEvent;
use human_money_core::services::mnemonic::MnemonicLanguage;
use human_money_core::wallet::instance::VoucherStatus;
use serde::Serialize;

/// Subcommands for BIP-39 mnemonic generation and validation.
#[derive(Subcommand, Debug)]
pub enum MnemonicCommand {
    /// Generate a fresh BIP-39 mnemonic seed phrase.
    Generate {
        /// Number of words for the mnemonic (e.g. 12 or 24).
        #[arg(long, default_value_t = 12)]
        words: u32,

        /// Wordlist language (e.g. "en" or "de").
        #[arg(long, default_value = "en")]
        lang: String,
    },

    /// Validate a BIP-39 mnemonic phrase.
    Validate {
        /// Mnemonic seed phrase to validate.
        #[arg(long)]
        phrase: String,

        /// Wordlist language (e.g. "en" or "de").
        #[arg(long, default_value = "en")]
        lang: String,
    },
}

/// Subcommands for managing wallet profiles, identities, and events.
#[derive(Subcommand, Debug)]
pub enum ProfileCommand {
    /// List all configured wallet profiles.
    List,

    /// Create a new encrypted profile and wallet.
    Create {
        /// Human-readable profile name.
        #[arg(long, short = 'n')]
        name: Option<String>,

        /// Profile name positional argument fallback.
        #[arg(value_name = "NAME")]
        name_pos: Option<String>,

        /// Optional user ID prefix for SAI (e.g. "0" for standard issuer).
        #[arg(long)]
        prefix: Option<String>,

        /// Existing mnemonic seed phrase (if omitted, a new phrase is generated).
        #[arg(long)]
        mnemonic: Option<String>,

        /// Optional BIP-39 passphrase.
        #[arg(long)]
        passphrase: Option<String>,

        /// Word count for auto-generated mnemonic (default: 12).
        #[arg(long, default_value_t = 12)]
        words: u32,

        /// Wordlist language (default: "en").
        #[arg(long, default_value = "en")]
        lang: String,

        /// Optional first name.
        #[arg(long)]
        first_name: Option<String>,

        /// Optional last name.
        #[arg(long)]
        last_name: Option<String>,

        /// Optional ISO 5218 gender ("0", "1", "2", "9").
        #[arg(long)]
        gender: Option<String>,

        /// Optional organization.
        #[arg(long)]
        organization: Option<String>,

        /// Optional community.
        #[arg(long)]
        community: Option<String>,

        /// Optional email address.
        #[arg(long)]
        email: Option<String>,

        /// Optional phone number.
        #[arg(long)]
        phone: Option<String>,

        /// Optional coordinates (e.g. "52.5200,13.4050").
        #[arg(long)]
        coordinates: Option<String>,

        /// Optional description of offered goods or services.
        #[arg(long)]
        service_offer: Option<String>,

        /// Optional description of needed goods or services.
        #[arg(long)]
        needs: Option<String>,
    },

    /// Display detailed profile status, identity, public profile, and integrity.
    Info {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: Option<String>,

        /// Profile name positional argument fallback.
        #[arg(value_name = "PROFILE")]
        profile_pos: Option<String>,
    },

    /// Update public profile metadata fields.
    Update {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: Option<String>,

        /// Profile name positional argument fallback.
        #[arg(value_name = "PROFILE")]
        profile_pos: Option<String>,

        /// First name.
        #[arg(long)]
        first_name: Option<String>,

        /// Last name.
        #[arg(long)]
        last_name: Option<String>,

        /// ISO 5218 gender code ("0", "1", "2", "9").
        #[arg(long)]
        gender: Option<String>,

        /// Organization.
        #[arg(long)]
        organization: Option<String>,

        /// Community.
        #[arg(long)]
        community: Option<String>,

        /// Email address.
        #[arg(long)]
        email: Option<String>,

        /// Phone number.
        #[arg(long)]
        phone: Option<String>,

        /// Coordinates ("lat,lon").
        #[arg(long)]
        coordinates: Option<String>,

        /// Website URL.
        #[arg(long)]
        url: Option<String>,

        /// Offered goods or services.
        #[arg(long)]
        service_offer: Option<String>,

        /// Needed goods or services.
        #[arg(long)]
        needs: Option<String>,

        /// Street.
        #[arg(long)]
        street: Option<String>,

        /// House number.
        #[arg(long)]
        house_number: Option<String>,

        /// Postal code / ZIP code.
        #[arg(long)]
        zip_code: Option<String>,

        /// City.
        #[arg(long)]
        city: Option<String>,

        /// Country.
        #[arg(long)]
        country: Option<String>,
    },

    /// Permanently delete a profile and all its files.
    Delete {
        /// Profile name or folder to delete.
        #[arg(long, short = 'u')]
        profile: Option<String>,

        /// Profile name positional argument fallback.
        #[arg(value_name = "PROFILE")]
        profile_pos: Option<String>,
    },

    /// Display wallet event audit history.
    Events {
        /// Profile name or folder.
        #[arg(long, short = 'u')]
        profile: Option<String>,

        /// Profile name positional argument fallback.
        #[arg(value_name = "PROFILE")]
        profile_pos: Option<String>,

        /// Event pagination offset.
        #[arg(long, default_value_t = 0)]
        offset: usize,

        /// Event pagination limit.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, Serialize)]
pub struct MnemonicGenerated {
    pub mnemonic: String,
    pub words: u32,
    pub language: String,
}

#[derive(Debug, Serialize)]
pub struct MnemonicValidated {
    pub valid: bool,
    pub language: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileCreated {
    pub profile_name: String,
    pub folder_name: String,
    pub user_id: String,
    pub mnemonic_generated: bool,
    pub mnemonic: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProfileDetails {
    pub profile_name: String,
    pub folder_name: String,
    pub user_id: String,
    pub public_profile: PublicProfile,
    pub seal_sync_status: SyncStatus,
    pub integrity: String,
    pub active_vouchers_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ProfileDeleted {
    pub deleted: bool,
    pub profile_name: String,
    pub folder_name: String,
}

/// Parses a language string into [`MnemonicLanguage`].
///
/// Supports "en"/"english" for English and "de"/"german" for German,
/// alongside standard European and Asian language codes.
pub fn parse_lang(lang: &str) -> Result<MnemonicLanguage> {
    match lang.trim().to_ascii_lowercase().as_str() {
        "en" | "english" => Ok(MnemonicLanguage::English),
        "de" | "german" => Ok(MnemonicLanguage::German),
        "fr" | "french" => Ok(MnemonicLanguage::French),
        "es" | "spanish" => Ok(MnemonicLanguage::Spanish),
        "it" | "italian" => Ok(MnemonicLanguage::Italian),
        "ja" | "japanese" => Ok(MnemonicLanguage::Japanese),
        "ko" | "korean" => Ok(MnemonicLanguage::Korean),
        "zh" | "zh-cn" | "chinese" => Ok(MnemonicLanguage::ChineseSimplified),
        "pt" | "portuguese" => Ok(MnemonicLanguage::Portuguese),
        "cs" | "czech" => Ok(MnemonicLanguage::Czech),
        other => bail!(
            "Unsupported mnemonic language '{other}'. Supported languages: en (English), de (German)"
        ),
    }
}

/// Dispatches all mnemonic commands.
pub fn handle_mnemonic(ctx: &CliContext, cmd: MnemonicCommand) -> Result<()> {
    match cmd {
        MnemonicCommand::Generate { words, lang } => {
            let lang_enum = parse_lang(&lang)?;
            let mnemonic = AppService::generate_mnemonic(words, lang_enum)
                .with_context(|| format!("Failed to generate {words}-word mnemonic in language '{lang}'"))?;

            let data = MnemonicGenerated {
                mnemonic: mnemonic.clone(),
                words,
                language: lang.clone(),
            };

            ctx.output(&data, |_| {
                println!("Mnemonic ({words} words, {lang}):\n{mnemonic}");
            })
        }
        MnemonicCommand::Validate { phrase, lang } => {
            let lang_enum = parse_lang(&lang)?;
            AppService::validate_mnemonic(phrase.trim(), lang_enum)
                .with_context(|| format!("Mnemonic validation failed for language '{lang}'"))?;

            let data = MnemonicValidated {
                valid: true,
                language: lang.clone(),
            };

            ctx.output(&data, |_| {
                println!("Mnemonic phrase is valid ({lang}).");
            })
        }
    }
}

/// Dispatches all profile commands.
pub fn handle_profile(ctx: &CliContext, cmd: ProfileCommand) -> Result<()> {
    match cmd {
        ProfileCommand::List => handle_list(ctx),
        ProfileCommand::Create {
            name,
            name_pos,
            prefix,
            mnemonic,
            passphrase,
            words,
            lang,
            first_name,
            last_name,
            gender,
            organization,
            community,
            email,
            phone,
            coordinates,
            service_offer,
            needs,
        } => handle_create(
            ctx,
            resolve_name_arg(name, name_pos)?,
            prefix,
            mnemonic,
            passphrase,
            words,
            lang,
            first_name,
            last_name,
            gender,
            organization,
            community,
            email,
            phone,
            coordinates,
            service_offer,
            needs,
        ),
        ProfileCommand::Info {
            profile,
            profile_pos,
        } => handle_info(ctx, resolve_profile_arg(profile, profile_pos)?),
        ProfileCommand::Update {
            profile,
            profile_pos,
            first_name,
            last_name,
            gender,
            organization,
            community,
            email,
            phone,
            coordinates,
            url,
            service_offer,
            needs,
            street,
            house_number,
            zip_code,
            city,
            country,
        } => handle_update(
            ctx,
            resolve_profile_arg(profile, profile_pos)?,
            first_name,
            last_name,
            gender,
            organization,
            community,
            email,
            phone,
            coordinates,
            url,
            service_offer,
            needs,
            street,
            house_number,
            zip_code,
            city,
            country,
        ),
        ProfileCommand::Delete {
            profile,
            profile_pos,
        } => handle_delete(ctx, resolve_profile_arg(profile, profile_pos)?),
        ProfileCommand::Events {
            profile,
            profile_pos,
            offset,
            limit,
        } => handle_events(ctx, resolve_profile_arg(profile, profile_pos)?, offset, limit),
    }
}

fn handle_list(ctx: &CliContext) -> Result<()> {
    let app = ctx.open_service()?;
    let profiles = app.list_profiles()?;

    ctx.output(&profiles, |list: &Vec<ProfileInfo>| {
        if list.is_empty() {
            println!("No profiles found in '{}'.", ctx.data_dir.display());
        } else {
            println!("Found {} profile(s):", list.len());
            for p in list {
                println!("  - {} ({})", p.profile_name, p.folder_name);
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_create(
    ctx: &CliContext,
    name: String,
    prefix: Option<String>,
    mnemonic: Option<String>,
    passphrase: Option<String>,
    words: u32,
    lang: String,
    first_name: Option<String>,
    last_name: Option<String>,
    gender: Option<String>,
    organization: Option<String>,
    community: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    coordinates: Option<String>,
    service_offer: Option<String>,
    needs: Option<String>,
) -> Result<()> {
    let password = ctx.require_password()?;
    let lang_enum = parse_lang(&lang)?;

    let (mnemonic_str, mnemonic_generated) = match mnemonic {
        Some(m) => (m, false),
        None => (
            AppService::generate_mnemonic(words, lang_enum)
                .with_context(|| format!("Failed to generate mnemonic for new profile '{name}'"))?,
            true,
        ),
    };

    let mut app = ctx.open_service()?;
    app.create_profile(
        &name,
        &mnemonic_str,
        passphrase.as_deref(),
        prefix.as_deref(),
        password,
        lang_enum,
        ctx.device_id.clone(),
    )?;

    let has_meta = first_name.is_some()
        || last_name.is_some()
        || gender.is_some()
        || organization.is_some()
        || community.is_some()
        || email.is_some()
        || phone.is_some()
        || coordinates.is_some()
        || service_offer.is_some()
        || needs.is_some();

    if has_meta {
        let mut pub_profile = app.with_wallet(|w| w.profile.to_public_profile())?;
        if let Some(v) = first_name {
            pub_profile.first_name = Some(v);
        }
        if let Some(v) = last_name {
            pub_profile.last_name = Some(v);
        }
        if let Some(v) = gender {
            pub_profile.gender = Some(v);
        }
        if let Some(v) = organization {
            pub_profile.organization = Some(v);
        }
        if let Some(v) = community {
            pub_profile.community = Some(v);
        }
        if let Some(v) = email {
            pub_profile.email = Some(v);
        }
        if let Some(v) = phone {
            pub_profile.phone = Some(v);
        }
        if let Some(v) = coordinates {
            pub_profile.coordinates = Some(v);
        }
        if let Some(v) = service_offer {
            pub_profile.service_offer = Some(v);
        }
        if let Some(v) = needs {
            pub_profile.needs = Some(v);
        }

        app.update_public_profile(pub_profile, Some(password))?;
    }

    let user_id = app.with_wallet(|w| w.profile.user_id.clone())?;
    let info = ctx.resolve_profile(&app, &name)?;

    let result = ProfileCreated {
        profile_name: name.clone(),
        folder_name: info.folder_name,
        user_id,
        mnemonic_generated,
        mnemonic: if mnemonic_generated {
            Some(mnemonic_str)
        } else {
            None
        },
    };

    app.logout();

    ctx.output(&result, |p| {
        println!("Profile '{}' created successfully.", p.profile_name);
        println!("  Folder Name: {}", p.folder_name);
        println!("  User ID:     {}", p.user_id);
        if let Some(ref m) = p.mnemonic {
            println!("  Mnemonic:    {}", m);
        }
    })
}

fn handle_info(ctx: &CliContext, profile_name: String) -> Result<()> {
    let (mut app, profile_info, pwd) = ctx.unlock_profile(&profile_name)?;
    let _ = app.unlock_session(&pwd, 300);

    let user_id = app.with_wallet(|w| w.profile.user_id.clone())?;
    let public_profile = app.with_wallet(|w| w.profile.to_public_profile())?;
    let active_vouchers_count = app.with_wallet(|w| {
        w.voucher_store
            .vouchers
            .values()
            .filter(|v| matches!(v.status, VoucherStatus::Active))
            .count()
    })?;

    let seal_sync_status = app.get_seal_sync_status()?;
    let integrity = format!("{:?}", app.check_integrity(Some(&pwd))?);

    let details = ProfileDetails {
        profile_name: profile_info.profile_name,
        folder_name: profile_info.folder_name,
        user_id,
        public_profile,
        seal_sync_status,
        integrity,
        active_vouchers_count,
    };

    app.logout();

    ctx.output(&details, |d| {
        println!("Profile:           {}", d.profile_name);
        println!("  Folder Name:     {}", d.folder_name);
        println!("  User ID:         {}", d.user_id);
        println!("  Integrity:       {}", d.integrity);
        println!("  Seal Sync:       {:?}", d.seal_sync_status);
        println!("  Active Vouchers: {}", d.active_vouchers_count);
        if let Some(ref first) = d.public_profile.first_name {
            println!("  First Name:      {}", first);
        }
        if let Some(ref last) = d.public_profile.last_name {
            println!("  Last Name:       {}", last);
        }
        if let Some(ref gender) = d.public_profile.gender {
            println!("  Gender:          {}", gender);
        }
        if let Some(ref org) = d.public_profile.organization {
            println!("  Organization:    {}", org);
        }
        if let Some(ref comm) = d.public_profile.community {
            println!("  Community:       {}", comm);
        }
        if let Some(ref email) = d.public_profile.email {
            println!("  Email:           {}", email);
        }
        if let Some(ref phone) = d.public_profile.phone {
            println!("  Phone:           {}", phone);
        }
        if let Some(ref coords) = d.public_profile.coordinates {
            println!("  Coordinates:     {}", coords);
        }
        if let Some(ref url) = d.public_profile.url {
            println!("  URL:             {}", url);
        }
        if let Some(ref offer) = d.public_profile.service_offer {
            println!("  Service Offer:   {}", offer);
        }
        if let Some(ref needs) = d.public_profile.needs {
            println!("  Needs:           {}", needs);
        }
        if let Some(ref addr) = d.public_profile.address {
            println!("  Address:         {}", addr.full_address);
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_update(
    ctx: &CliContext,
    profile_name: String,
    first_name: Option<String>,
    last_name: Option<String>,
    gender: Option<String>,
    organization: Option<String>,
    community: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    coordinates: Option<String>,
    url: Option<String>,
    service_offer: Option<String>,
    needs: Option<String>,
    street: Option<String>,
    house_number: Option<String>,
    zip_code: Option<String>,
    city: Option<String>,
    country: Option<String>,
) -> Result<()> {
    let (mut app, _profile_info, pwd) = ctx.unlock_profile(&profile_name)?;
    let mut updated = app.with_wallet(|w| w.profile.to_public_profile())?;

    if let Some(v) = first_name {
        updated.first_name = Some(v);
    }
    if let Some(v) = last_name {
        updated.last_name = Some(v);
    }
    if let Some(v) = gender {
        updated.gender = Some(v);
    }
    if let Some(v) = organization {
        updated.organization = Some(v);
    }
    if let Some(v) = community {
        updated.community = Some(v);
    }
    if let Some(v) = email {
        updated.email = Some(v);
    }
    if let Some(v) = phone {
        updated.phone = Some(v);
    }
    if let Some(v) = coordinates {
        updated.coordinates = Some(v);
    }
    if let Some(v) = url {
        updated.url = Some(v);
    }
    if let Some(v) = service_offer {
        updated.service_offer = Some(v);
    }
    if let Some(v) = needs {
        updated.needs = Some(v);
    }

    let has_address_flags = street.is_some()
        || house_number.is_some()
        || zip_code.is_some()
        || city.is_some()
        || country.is_some();

    if has_address_flags {
        let mut addr = updated.address.take().unwrap_or_default();
        if let Some(v) = street {
            addr.street = v;
        }
        if let Some(v) = house_number {
            addr.house_number = v;
        }
        if let Some(v) = zip_code {
            addr.zip_code = v;
        }
        if let Some(v) = city {
            addr.city = v;
        }
        if let Some(v) = country {
            addr.country = v;
        }
        addr.full_address = format_address(&addr);
        updated.address = Some(addr);
    }

    app.update_public_profile(updated.clone(), Some(&pwd))?;
    app.logout();

    ctx.output(&updated, |p| {
        println!("Public profile for '{profile_name}' updated successfully:");
        if let Some(ref first) = p.first_name {
            println!("  First Name:    {}", first);
        }
        if let Some(ref last) = p.last_name {
            println!("  Last Name:     {}", last);
        }
        if let Some(ref gender) = p.gender {
            println!("  Gender:        {}", gender);
        }
        if let Some(ref org) = p.organization {
            println!("  Organization:  {}", org);
        }
        if let Some(ref comm) = p.community {
            println!("  Community:     {}", comm);
        }
        if let Some(ref email) = p.email {
            println!("  Email:         {}", email);
        }
        if let Some(ref phone) = p.phone {
            println!("  Phone:         {}", phone);
        }
        if let Some(ref coords) = p.coordinates {
            println!("  Coordinates:   {}", coords);
        }
        if let Some(ref url) = p.url {
            println!("  URL:           {}", url);
        }
        if let Some(ref offer) = p.service_offer {
            println!("  Service Offer: {}", offer);
        }
        if let Some(ref needs) = p.needs {
            println!("  Needs:         {}", needs);
        }
        if let Some(ref addr) = p.address {
            println!("  Address:       {}", addr.full_address);
        }
    })
}

fn handle_delete(ctx: &CliContext, profile_name: String) -> Result<()> {
    let mut app = ctx.open_service()?;
    let info = ctx.resolve_profile(&app, &profile_name)?;
    let password = ctx.require_password()?;

    app.delete_profile(&info.folder_name, password)?;

    let out = ProfileDeleted {
        deleted: true,
        profile_name: info.profile_name,
        folder_name: info.folder_name,
    };

    ctx.output(&out, |d| {
        println!("Profile '{}' ({}) was successfully deleted.", d.profile_name, d.folder_name);
    })
}

fn handle_events(
    ctx: &CliContext,
    profile_name: String,
    offset: usize,
    limit: usize,
) -> Result<()> {
    let (mut app, info, pwd) = ctx.unlock_profile(&profile_name)?;
    let events = app.get_event_history(offset, limit, Some(&pwd))?;
    app.logout();

    ctx.output(&events, |evts: &Vec<WalletEvent>| {
        if evts.is_empty() {
            println!("No events recorded for profile '{}'.", info.profile_name);
        } else {
            println!(
                "Event history for profile '{}' ({} events):",
                info.profile_name,
                evts.len()
            );
            for evt in evts {
                println!(
                    "  [{}] {:?} | {} {} | voucher: {} | local_id: {}",
                    evt.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    evt.event_type,
                    evt.bff_data.amount,
                    evt.bff_data.display_currency,
                    evt.voucher_id,
                    evt.local_instance_id,
                );
            }
        }
    })
}

fn resolve_profile_arg(profile: Option<String>, profile_pos: Option<String>) -> Result<String> {
    profile
        .or(profile_pos)
        .ok_or_else(|| anyhow!("Profile name is required. Specify via `--profile <NAME>` or as positional argument."))
}

fn resolve_name_arg(name: Option<String>, name_pos: Option<String>) -> Result<String> {
    name
        .or(name_pos)
        .ok_or_else(|| anyhow!("Profile name is required. Specify via `--name <NAME>` or as positional argument."))
}

fn format_address(addr: &Address) -> String {
    let street_line = format!("{} {}", addr.street, addr.house_number).trim().to_string();
    let city_line = format!("{} {}", addr.zip_code, addr.city).trim().to_string();
    let parts: Vec<&str> = [street_line.as_str(), city_line.as_str(), addr.country.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    parts.join(", ")
}
