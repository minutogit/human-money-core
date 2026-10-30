//! Shared execution context, JSON/human output formatting, profile resolution,
//! and voucher standard discovery for `wallet-cli`.

use anyhow::{Context, Result, anyhow, bail};
use human_money_core::app_service::{AppService, ProfileInfo};
use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Default directory for CLI wallets when neither `--data-dir` nor `HUMOCO_DATA_DIR` is set.
pub const DEFAULT_DATA_DIR: &str = "target/cli-wallets";

/// Default directory for signed voucher standard `.toml` files.
pub const DEFAULT_STANDARDS_DIR: &str = "voucher_standards";

/// Default device identifier bound into `WalletSeal` operations from the CLI.
pub const DEFAULT_DEVICE_ID: &str = "humoco-wallet-cli";

/// Parsed metadata and raw TOML content of a verified voucher standard.
#[derive(Debug, Clone, Serialize)]
pub struct LoadedStandard {
    pub uuid: String,
    pub name: String,
    pub abbreviation: String,
    pub unit: String,
    pub decimals: u8,
    pub allow_partial_transfers: bool,
    pub default_validity: Option<String>,
    pub min_signatures: u32,
    pub path: PathBuf,
    #[serde(skip_serializing)]
    pub toml_content: String,
}

/// Shared runtime configuration passed to all CLI command handlers.
#[derive(Debug, Clone)]
pub struct CliContext {
    pub data_dir: PathBuf,
    pub standards_dir: PathBuf,
    pub password: Option<String>,
    pub device_id: String,
    pub auto_handover: bool,
    pub json: bool,
}

/// RAII wrapper around an unlocked [`AppService`] that guarantees `logout()`
/// (releasing `.wallet.lock`) is executed whenever the handle goes out of scope.
pub struct UnlockedService(pub AppService);

impl std::ops::Deref for UnlockedService {
    type Target = AppService;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for UnlockedService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for UnlockedService {
    fn drop(&mut self) {
        self.0.logout();
    }
}

#[derive(Serialize)]
struct JsonSuccessEnvelope<'a, T: Serialize> {
    ok: bool,
    data: &'a T,
}

#[derive(Serialize)]
struct JsonErrorEnvelope {
    ok: bool,
    error: JsonErrorBody,
}

#[derive(Serialize)]
struct JsonErrorBody {
    message: String,
    causes: Vec<String>,
}

impl CliContext {
    /// Constructs a [`CliContext`] from CLI flags with environment variable fallbacks.
    pub fn from_args(
        data_dir: Option<PathBuf>,
        standards_dir: Option<PathBuf>,
        password: Option<String>,
        device_id: Option<String>,
        auto_handover: bool,
        json: bool,
    ) -> Self {
        let resolved_data_dir = data_dir
            .or_else(|| std::env::var("HUMOCO_DATA_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));

        let resolved_standards_dir = standards_dir
            .or_else(|| std::env::var("HUMOCO_STANDARDS_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STANDARDS_DIR));

        let resolved_password = password.or_else(|| std::env::var("HUMOCO_PASSWORD").ok());

        let resolved_device_id = device_id
            .or_else(|| std::env::var("HUMOCO_DEVICE_ID").ok())
            .unwrap_or_else(|| DEFAULT_DEVICE_ID.to_string());

        Self {
            data_dir: resolved_data_dir,
            standards_dir: resolved_standards_dir,
            password: resolved_password,
            device_id: resolved_device_id,
            auto_handover,
            json,
        }
    }

    /// Returns the configured wallet password or a clear actionable error.
    pub fn require_password(&self) -> Result<&str> {
        self.password.as_deref().ok_or_else(|| {
            anyhow!(
                "Wallet password required. Pass `--password <PW>` or set `HUMOCO_PASSWORD`."
            )
        })
    }

    /// Initializes a locked [`AppService`] rooted at `self.data_dir`.
    pub fn open_service(&self) -> Result<AppService> {
        AppService::new(&self.data_dir).map_err(|e| {
            anyhow!(
                "Failed to initialize AppService at '{}': {e}",
                self.data_dir.display()
            )
        })
    }

    /// Resolves a profile by exact `profile_name`, case-insensitive `profile_name`, or `folder_name`.
    pub fn resolve_profile(&self, app: &AppService, name_or_folder: &str) -> Result<ProfileInfo> {
        let profiles = app
            .list_profiles()
            .map_err(|e| anyhow!("Failed to list profiles: {e}"))?;

        if let Some(found) = profiles.iter().find(|p| p.profile_name == name_or_folder) {
            return Ok(found.clone());
        }
        if let Some(found) = profiles
            .iter()
            .find(|p| p.profile_name.eq_ignore_ascii_case(name_or_folder))
        {
            return Ok(found.clone());
        }
        if let Some(found) = profiles.iter().find(|p| p.folder_name == name_or_folder) {
            return Ok(found.clone());
        }

        let available: Vec<String> = profiles
            .iter()
            .map(|p| format!("'{}' ({})", p.profile_name, p.folder_name))
            .collect();
        if available.is_empty() {
            bail!(
                "Profile '{}' not found in '{}' (no profiles exist yet).",
                name_or_folder,
                self.data_dir.display()
            );
        } else {
            bail!(
                "Profile '{}' not found. Available profiles: {}",
                name_or_folder,
                available.join(", ")
            );
        }
    }

    /// Opens [`AppService`], resolves `name_or_folder`, and unlocks the wallet.
    ///
    /// Returns an [`UnlockedService`] RAII guard that automatically calls `logout()` on drop
    /// so `.wallet.lock` is never left behind after CLI commands finish or error out.
    /// If `--auto-handover` is enabled and login fails due to a `WalletSeal` device mismatch,
    /// automatically executes `handover_to_this_device`.
    pub fn unlock_profile(
        &self,
        name_or_folder: &str,
    ) -> Result<(UnlockedService, ProfileInfo, String)> {
        let mut app = self.open_service()?;
        let profile = self.resolve_profile(&app, name_or_folder)?;
        let password = self.require_password()?.to_string();

        match app.login(
            &profile.folder_name,
            &password,
            false,
            self.device_id.clone(),
        ) {
            Ok(()) => Ok((UnlockedService(app), profile, password)),
            Err(login_err) => {
                let err_msg = login_err.to_string();
                let is_device_mismatch = err_msg.contains("DeviceMismatch")
                    || err_msg.contains("device")
                    || err_msg.contains("handover");

                if self.auto_handover && is_device_mismatch {
                    app.handover_to_this_device(
                        &profile.folder_name,
                        &password,
                        self.device_id.clone(),
                    )
                    .map_err(|e| {
                        anyhow!(
                            "Login failed ({err_msg}) and automatic device handover also failed: {e}"
                        )
                    })?;
                    Ok((UnlockedService(app), profile, password))
                } else if is_device_mismatch {
                    bail!(
                        "Login blocked by WalletSeal device binding ({err_msg}). Pass `--auto-handover` (or matching `--device-id`) to bind this profile to the CLI."
                    );
                } else {
                    bail!("Failed to unlock profile '{}': {err_msg}", profile.profile_name);
                }
            }
        }
    }

    /// Resolves a target recipient specification:
    /// - If `target` contains `"did:key:"`, returns it directly as a DID.
    /// - Otherwise treats `target` as a local profile name in `self.data_dir` and resolves its `user_id`
    ///   using `password_override` or `self.password`.
    pub fn resolve_did_or_local_profile(
        &self,
        target: &str,
        recipient_password: Option<&str>,
    ) -> Result<String> {
        if target.contains("did:key:") {
            return Ok(target.to_string());
        }

        let app = self.open_service()?;
        let profile = self.resolve_profile(&app, target).with_context(|| {
            format!(
                "Recipient '{}' is neither a 'did:key:...' identifier nor a known local profile",
                target
            )
        })?;
        let pwd = recipient_password
            .or(self.password.as_deref())
            .ok_or_else(|| {
                anyhow!(
                    "To resolve local profile '{}' to a DID, pass `--recipient-password` or `--password`",
                    target
                )
            })?;

        app.get_profile_id_with_password(&profile.folder_name, pwd)
            .map_err(|e| {
                anyhow!(
                    "Failed to read DID for local profile '{}': {e}",
                    profile.profile_name
                )
            })
    }

    /// Recursively discovers and verifies all signed `.toml` voucher standards in `self.standards_dir`.
    /// Unsigned template files (such as `standard_template.toml`) are silently skipped.
    pub fn load_standards(&self, extra_files: &[PathBuf]) -> Result<Vec<LoadedStandard>> {
        let mut files = Vec::new();
        if self.standards_dir.exists() {
            collect_toml_files(&self.standards_dir, &mut files)?;
        }
        for extra in extra_files {
            if !extra.exists() {
                bail!("Standard file '{}' does not exist", extra.display());
            }
            files.push(extra.clone());
        }
        files.sort();
        files.dedup();

        let mut loaded = Vec::new();
        let mut seen_uuids = HashMap::new();

        for path in files {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read '{}'", path.display()))?;

            // Skip unsigned templates when scanning directories, but fail explicitly for extra_files.
            let is_explicit = extra_files.iter().any(|p| p == &path);
            match VoucherStandardDefinition::from_toml(&content) {
                Ok((def, _hash)) => {
                    let uuid = def.immutable.identity.uuid.clone();
                    if seen_uuids.contains_key(&uuid) {
                        continue;
                    }
                    seen_uuids.insert(uuid.clone(), path.clone());
                    let default_validity = def
                        .immutable
                        .issuance
                        .validity_duration_range
                        .first()
                        .cloned()
                        .or_else(|| {
                            let min_v = &def.immutable.issuance.issuance_minimum_validity_duration;
                            (!min_v.is_empty()).then(|| min_v.clone())
                        });
                    let min_signatures = def
                        .immutable
                        .issuance
                        .additional_signatures_range
                        .first()
                        .copied()
                        .unwrap_or(0);

                    loaded.push(LoadedStandard {
                        uuid,
                        name: def.immutable.identity.name,
                        abbreviation: def.immutable.identity.abbreviation,
                        unit: def.immutable.blueprint.unit,
                        decimals: def.immutable.features.amount_decimal_places,
                        allow_partial_transfers: def.immutable.features.allow_partial_transfers,
                        default_validity,
                        min_signatures,
                        path,
                        toml_content: content,
                    });
                }
                Err(e) => {
                    if is_explicit {
                        bail!(
                            "Invalid or unsigned voucher standard '{}': {e}",
                            path.display()
                        );
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Builds the `HashMap<uuid, toml_content>` required by `AppService` transfer/receive operations.
    pub fn load_standards_toml_map(
        &self,
        extra_files: &[PathBuf],
    ) -> Result<HashMap<String, String>> {
        let list = self.load_standards(extra_files)?;
        Ok(list
            .into_iter()
            .map(|s| (s.uuid, s.toml_content))
            .collect())
    }

    /// Resolves a single voucher standard by `.toml` file path, exact UUID, unit/abbreviation, or substring match.
    pub fn resolve_standard(&self, spec: &str, extra_files: &[PathBuf]) -> Result<LoadedStandard> {
        let candidate_path = Path::new(spec);
        if candidate_path.exists() && candidate_path.is_file() {
            let mut extras = extra_files.to_vec();
            extras.push(candidate_path.to_path_buf());
            let all = self.load_standards(&extras)?;
            if let Some(found) = all.into_iter().find(|s| s.path == candidate_path) {
                return Ok(found);
            }
        }

        let standards = self.load_standards(extra_files)?;
        if let Some(s) = standards
            .iter()
            .find(|s| s.uuid.eq_ignore_ascii_case(spec))
        {
            return Ok(s.clone());
        }
        if let Some(s) = standards.iter().find(|s| {
            s.abbreviation.eq_ignore_ascii_case(spec)
                || s.unit.eq_ignore_ascii_case(spec)
                || s.name.eq_ignore_ascii_case(spec)
        }) {
            return Ok(s.clone());
        }
        let spec_lower = spec.to_lowercase();
        let fuzzy: Vec<&LoadedStandard> = standards
            .iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&spec_lower)
                    || s.uuid.to_lowercase().contains(&spec_lower)
                    || s.path.to_string_lossy().to_lowercase().contains(&spec_lower)
            })
            .collect();
        if fuzzy.len() == 1 {
            return Ok(fuzzy[0].clone());
        }

        let available: Vec<String> = standards
            .iter()
            .map(|s| format!("{} ({})", s.name, s.uuid))
            .collect();
        bail!(
            "Voucher standard '{}' not found. Available standards: {}",
            spec,
            if available.is_empty() {
                "<none found in standards_dir>".to_string()
            } else {
                available.join(", ")
            }
        )
    }

    /// Emits structured JSON when `--json` is active, or delegates to `human_printer` otherwise.
    pub fn output<T, F>(&self, data: &T, human_printer: F) -> Result<()>
    where
        T: Serialize,
        F: FnOnce(&T),
    {
        if self.json {
            let envelope = JsonSuccessEnvelope { ok: true, data };
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        } else {
            human_printer(data);
        }
        Ok(())
    }
}

/// Emits a structured error to stdout (in `--json` mode) or stderr (in human mode) and exits with code 1.
pub fn emit_error_and_exit(json: bool, err: &anyhow::Error) -> ! {
    if json {
        let causes: Vec<String> = err.chain().skip(1).map(|c| c.to_string()).collect();
        let envelope = JsonErrorEnvelope {
            ok: false,
            error: JsonErrorBody {
                message: err.to_string(),
                causes,
            },
        };
        if let Ok(serialized) = serde_json::to_string_pretty(&envelope) {
            println!("{serialized}");
        } else {
            println!(r#"{{"ok":false,"error":{{"message":"Internal serialization error"}}}}"#);
        }
    } else {
        eprintln!("Error: {err:#}");
    }
    std::process::exit(1);
}

fn collect_toml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)
        .with_context(|| format!("Failed to read standards directory '{}'", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            out.push(path);
        }
    }
    Ok(())
}
