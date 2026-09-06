//! # src/services/voucher_validation/pipeline.rs
//!
//! Centralized standard caching and linear validation pipeline for incoming bundles.
//!
//! **`StandardRegistry`** — pure lookup structure / cache for verified standards per call/batch.
//! **`ValidationPipeline`** — executes the 4 audited checks in strict linearized order on an
//! already-decrypted `TransactionBundle`, reusing the result of `open_and_verify_bundle`
//! and avoiding repeated TOML deserialization and repeated signature verifications of the
//! same standard.
//!
//! ## Audited order
//! 1. Standard-Definition & Nominalwerte (`ValidationError::*` — identity, hash, nominal, duration, rules, signatures)
//! 2. Zeitgrenzen & Epoch-Zonen (`verify_not_far_in_future` / Epoch-Zone)
//! 3. Privacy-Modus & Empfänger-Identität (`validate_privacy_mode` + `verify_incoming_voucher_security` recipient/privacy-guard checks)
//! 4. SST-Witness & Shard-Struktur (`verify_sst_witness` & `validate_shard_structure`)

use std::collections::HashMap;

use crate::error::{StandardDefinitionError, ValidationError, VoucherCoreError};
use crate::models::profile::{TransactionBundle, UserIdentity};
use crate::models::voucher::ANONYMOUS_ID;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto::{decrypt_recipient_payload, get_hash};
use crate::services::utils::{to_canonical_json, verify_not_far_in_future};

// ---------------------------------------------------------------------------
// StandardRegistry
// ---------------------------------------------------------------------------

/// Pure lookup/cache for verified standards per call or batch.
///
/// Constructed **once** per incoming bundle from the caller-supplied
/// `HashMap<uuid, toml>` via [`StandardRegistry::from_toml_map`] — each TOML
/// is deserialized and its issuer signature verified **exactly once** per
/// distinct `uuid` in the batch. Subsequent per-voucher lookups reuse the
/// cached `VoucherStandardDefinition` without re-parsing or re-verifying.
///
/// For call sites that already hold verified definitions (e.g.
/// `Wallet::process_encrypted_transaction_bundle`'s
/// `HashMap<String, VoucherStandardDefinition>`), use
/// [`StandardRegistry::from_verified_map`] / [`StandardRegistry::from_verified_ref`]
/// which wraps the map without re-verification.
#[derive(Debug, Clone, Default)]
pub struct StandardRegistry {
    verified: HashMap<String, VoucherStandardDefinition>,
}

impl StandardRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            verified: HashMap::new(),
        }
    }

    /// Builds a registry from a `uuid -> TOML` map, parsing and verifying each
    /// standard **once**.
    ///
    /// Duplicate `uuid` keys are naturally deduplicated by the `HashMap`.
    pub fn from_toml_map(
        toml_map: &HashMap<String, String>,
    ) -> Result<Self, VoucherCoreError> {
        let mut verified = HashMap::with_capacity(toml_map.len());
        for (uuid, toml_str) in toml_map {
            let (def, _) = VoucherStandardDefinition::from_toml(toml_str)?;
            verified.insert(uuid.clone(), def);
        }
        Ok(Self { verified })
    }

    /// Wraps an already-verified map (cloned) without re-verification.
    pub fn from_verified_map(map: HashMap<String, VoucherStandardDefinition>) -> Self {
        Self { verified: map }
    }

    /// Wraps a reference to an already-verified map (cloned) without re-verification.
    pub fn from_verified_ref(map: &HashMap<String, VoucherStandardDefinition>) -> Self {
        Self {
            verified: map.clone(),
        }
    }

    /// Returns the verified definition for `uuid`, if present.
    pub fn get(&self, uuid: &str) -> Option<&VoucherStandardDefinition> {
        self.verified.get(uuid)
    }

    /// Inserts a pre-verified definition.
    pub fn insert(&mut self, uuid: String, def: VoucherStandardDefinition) {
        self.verified.insert(uuid, def);
    }

    /// Number of cached standards.
    pub fn len(&self) -> usize {
        self.verified.len()
    }

    /// True if no standards are cached.
    pub fn is_empty(&self) -> bool {
        self.verified.is_empty()
    }

    /// Iterates over cached entries.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &VoucherStandardDefinition)> {
        self.verified.iter()
    }
}

// ---------------------------------------------------------------------------
// ValidationPipeline
// ---------------------------------------------------------------------------

/// Linear validation pipeline for incoming bundles.
///
/// All four checks are executed in the exact audited order on the **already
/// decrypted** `TransactionBundle` (result of `open_and_verify_bundle` is
/// reused, no second decryption).
pub struct ValidationPipeline;

impl ValidationPipeline {
    /// Validates an incoming `TransactionBundle` against the cached registry
    /// and the recipient identity, in the exact 4-step audited order.
    ///
    /// * `bundle` — already decrypted and container/bundle-signature-verified
    ///               `TransactionBundle` (reuse `open_and_verify_bundle` result).
    /// * `identity` — recipient identity (own `user_id` + `signing_key` for
    ///                privacy-guard decryption).
    /// * `registry` — verified standards cache (avoids repeated TOML parsing
    ///                and repeated issuer-signature verification per `uuid`).
    /// * `epoch_start_time` / `epoch` / `force_accept` — epoch-zone parameters;
    ///                when `epoch_start_time` is `None` or `epoch == 0` the
    ///                epoch-zone sub-check is skipped. `force_accept`
    ///                corresponds to the `force_accept_tolerance_bundle` flag
    ///                (zones 1/2 become soft-overrideable, zone 3 stays hard).
    pub fn validate_incoming_bundle(
        bundle: &TransactionBundle,
        identity: &UserIdentity,
        registry: &StandardRegistry,
        epoch_start_time: Option<&str>,
        epoch: u32,
        force_accept: bool,
    ) -> Result<(), VoucherCoreError> {
        Self::step1_standard_and_nominal(bundle, registry)?;
        Self::step2_time_and_epoch(bundle, epoch_start_time, epoch, force_accept)?;
        Self::step3_privacy_and_recipient(bundle, identity, registry)?;
        Self::step4_sst_witness_and_shard(bundle, identity, registry)?;
        Ok(())
    }

    /// Step 1: Standard-Definition & Nominalwerte.
    ///
    /// Checks per voucher:
    /// - standard existence & `StandardNotFound`
    /// - `StandardUuidMismatch` / `StandardHashMismatch` (signature is trusted
    ///   via `registry` — no per-voucher re-verification)
    /// - nominal unit, voucher hash, anti-spoofing, date order, validity
    ///   duration, transaction types, custom CEL rules, and additional
    ///   signatures (all `ValidationError::*`).
    fn step1_standard_and_nominal(
        bundle: &TransactionBundle,
        registry: &StandardRegistry,
    ) -> Result<(), VoucherCoreError> {
        for voucher in &bundle.vouchers {
            let uuid = &voucher.voucher_standard.uuid;
            let std = registry.get(uuid).ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::StandardNotFound {
                    uuid: uuid.clone(),
                })
            })?;

            // Standard identity (without re-verifying issuer signature — registry
            // already verified it once per uuid)
            if voucher.voucher_standard.uuid != std.immutable.identity.uuid {
                return Err(ValidationError::StandardUuidMismatch {
                    expected: std.immutable.identity.uuid.clone(),
                    found: voucher.voucher_standard.uuid.clone(),
                }
                .into());
            }
            let expected_hash = get_hash(to_canonical_json(&std.immutable)?);
            if voucher.voucher_standard.standard_definition_hash != expected_hash {
                return Err(VoucherCoreError::Standard(
                    StandardDefinitionError::StandardHashMismatch,
                ));
            }

            // Deduplicated common structural checks (Nominal, Hash, Anti-Spoofing,
            // Date Logic, Validity Duration, Transaction Types, Rules,
            // Signatures, Privacy Mode, Transactions) — shared kernel with
            // `validate_voucher_against_standard`.
            crate::services::voucher_validation::validate_voucher_structure(voucher, std)?;
        }
        Ok(())
    }

    /// Step 2: Zeitgrenzen & Epoch-Zonen.
    ///
    /// - `verify_not_far_in_future` for the bundle's max transaction time
    ///   (last `t_time` across vouchers) and for every additional signature.
    /// - Epoch-Zone on `bundle_max_dt < epoch_start_time` with 15 min / 24 h /
    ///   28 d thresholds (hard vs. soft).
    fn step2_time_and_epoch(
        bundle: &TransactionBundle,
        epoch_start_time: Option<&str>,
        epoch: u32,
        force_accept: bool,
    ) -> Result<(), VoucherCoreError> {
        // Derive max transaction time across bundle
        let mut max_tx_dt: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut max_tx_time = String::new();
        let mut max_tx_id = String::new();

        for voucher in &bundle.vouchers {
            if let Some(last_tx) = voucher.transactions.last() {
                let tx_dt = chrono::DateTime::parse_from_rfc3339(&last_tx.t_time)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .map_err(|e| {
                        crate::Error::Wallet(
                            crate::error::WalletError::InvalidTimestamp {
                                reason: format!(
                                    "Failed to parse transaction time: {}",
                                    e
                                ),
                            },
                        )
                    })?;
                match max_tx_dt {
                    None => {
                        max_tx_dt = Some(tx_dt);
                        max_tx_time = last_tx.t_time.clone();
                        max_tx_id = last_tx.t_id.clone();
                    }
                    Some(m) if tx_dt > m => {
                        max_tx_dt = Some(tx_dt);
                        max_tx_time = last_tx.t_time.clone();
                        max_tx_id = last_tx.t_id.clone();
                    }
                    _ => {}
                }
            }
        }

        if !max_tx_time.is_empty() {
            verify_not_far_in_future(&max_tx_time, "Transaction", &max_tx_id)?;
        }

        for voucher in &bundle.vouchers {
            for sig in &voucher.signatures {
                verify_not_far_in_future(
                    &sig.signature_time,
                    "Signature",
                    &sig.signature_id,
                )?;
            }
        }

        // Epoch-Zone (only when wallet has a non-genesis epoch)
        if let Some(epoch_start) = epoch_start_time {
            if epoch > 0 {
                if let Some(bundle_max_dt) = max_tx_dt {
                    if let Ok(epoch_dt) =
                        chrono::DateTime::parse_from_rfc3339(epoch_start)
                    {
                        let epoch_utc = epoch_dt.with_timezone(&chrono::Utc);
                        if bundle_max_dt < epoch_utc {
                            let delta = epoch_utc - bundle_max_dt;
                            const ZONE_1_LIMIT_MINUTES: i64 = 15;
                            const ZONE_2_LIMIT_HOURS: i64 = 24;
                            const ZONE_3_LIMIT_DAYS: i64 = 28;

                            if delta > chrono::Duration::days(ZONE_3_LIMIT_DAYS) {
                                return Err(
                                    crate::Error::BundlePredatesCurrentEpoch,
                                );
                            } else if delta
                                > chrono::Duration::hours(ZONE_2_LIMIT_HOURS)
                            {
                                if !force_accept {
                                    return Err(
                                        crate::Error::BundleInExtendedRecoveryToleranceZone,
                                    );
                                }
                            } else if delta
                                > chrono::Duration::minutes(ZONE_1_LIMIT_MINUTES)
                                && !force_accept
                            {
                                return Err(
                                    crate::Error::BundleInRecoveryToleranceZone,
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Step 3: Privacy-Modus & Empfänger-Identität.
    ///
    /// - `validate_privacy_mode` per voucher.
    /// - Recipient match (including `ANONYMOUS_ID` with mandatory successful
    ///   privacy-guard decryption).
    /// - R5 fail-closed: `trap_data` without `privacy_guard` is rejected.
    /// - Privacy-guard strict decryption & `sender_permanent_did` binding.
    fn step3_privacy_and_recipient(
        bundle: &TransactionBundle,
        identity: &UserIdentity,
        registry: &StandardRegistry,
    ) -> Result<(), VoucherCoreError> {
        for voucher in &bundle.vouchers {
            // Privacy mode gate
            let std = registry.get(&voucher.voucher_standard.uuid).ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::StandardNotFound {
                    uuid: voucher.voucher_standard.uuid.clone(),
                })
            })?;
            crate::services::voucher_validation::chain::validate_privacy_mode(
                voucher,
                &std.immutable.features.privacy_mode,
            )?;

            let last_tx = voucher.transactions.last().ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::ReceivedVoucherHasNoTransactions)
            })?;

            let own_user_id = &identity.user_id;

            if last_tx.recipient_id != *own_user_id
                && last_tx.recipient_id != ANONYMOUS_ID
            {
                return Err(VoucherCoreError::BundleRecipientMismatch {
                    expected: own_user_id.clone(),
                    found: last_tx.recipient_id.clone(),
                });
            }

            if last_tx.recipient_id == ANONYMOUS_ID {
                let owns = if let Some(guard_base64) = &last_tx.privacy_guard {
                    decrypt_recipient_payload(
                        guard_base64,
                        &identity.signing_key,
                        &identity.user_id,
                    )
                    .is_ok()
                } else {
                    false
                };
                if !owns {
                    return Err(VoucherCoreError::BundleRecipientMismatch {
                        expected: own_user_id.clone(),
                        found: "anonymous_but_payload_decryption_failed"
                            .to_string(),
                    });
                }
            }

            // R5: trap without guard is fail-closed
            if last_tx.trap_data.is_some() && last_tx.privacy_guard.is_none() {
                return Err(VoucherCoreError::Validation(
                    ValidationError::TrapWithoutPrivacyGuard,
                ));
            }

            if let Some(guard_base64) = &last_tx.privacy_guard {
                let decrypted_payload_bytes =
                    decrypt_recipient_payload(
                        guard_base64,
                        &identity.signing_key,
                        &identity.user_id,
                    )
                    .map_err(|e| {
                        VoucherCoreError::Validation(
                            ValidationError::PrivacyGuardDecryptionFailed(format!(
                                "Decryption failed: {}",
                                e
                            )),
                        )
                    })?;

                let payload = serde_json::from_slice::<
                    crate::models::voucher::RecipientPayload,
                >(&decrypted_payload_bytes)
                    .map_err(|e| {
                        VoucherCoreError::Validation(
                            ValidationError::PrivacyGuardDecryptionFailed(format!(
                                "JSON parsing failed: {}",
                                e
                            )),
                        )
                    })?;

                if payload.sender_permanent_did != bundle.sender_id {
                    return Err(ValidationError::MismatchedPrivacySenderId {
                        declared: payload.sender_permanent_did,
                        actual: bundle.sender_id.clone(),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Step 4: SST-Witness & Shard-Struktur.
    ///
    /// - `validate_shard_structure` for every non-init transaction carrying `trap_data`.
    /// - `verify_sst_witness` for the private handover witness (decrypted
    ///   `RecipientPayload`) against the public trap shard.
    /// - Full transaction chain validation (`verify_transactions`) — funds,
    ///   prev_hash, time-order, anchor separation, etc. Placed here (after
    ///   privacy) to preserve the original `validate_privacy_mode` → `verify_transactions`
    ///   ordering while keeping the audited 4-step linearization.
    fn step4_sst_witness_and_shard(
        bundle: &TransactionBundle,
        identity: &UserIdentity,
        registry: &StandardRegistry,
    ) -> Result<(), VoucherCoreError> {
        for voucher in &bundle.vouchers {
            // Full chain validation (includes time-order, funds, prev_hash, P2PKH anchors,
            // split separation and — via `verify_transactions` — shard pre-checks).
            // Performed here after privacy (step 3) and before the explicit
            // witness gate, matching the original validate_voucher_against_standard order.
            let std = registry.get(&voucher.voucher_standard.uuid).ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::StandardNotFound {
                    uuid: voucher.voucher_standard.uuid.clone(),
                })
            })?;
            crate::services::voucher_validation::chain::verify_transactions(voucher, std)?;
            // Shard structure gate for non-init transactions
            for (idx, tx) in voucher.transactions.iter().enumerate() {
                if let Some(trap) = &tx.trap_data {
                    // Init may carry trivial placeholder "none"/"none" — that case
                    // fails validate_shard_structure by design and is skipped here
                    // only for the genesis row (idx == 0 with trivial shards).
                    let is_init_row = idx == 0 && tx.t_type == "init";
                    if is_init_row {
                        let is_trivial = (trap.trap_r.is_empty()
                            || trap.trap_r == "none")
                            && (trap.trap_s.is_empty() || trap.trap_s == "none")
                            && (trap.ds_tag.is_empty() || trap.ds_tag == "none");
                        if is_trivial {
                            continue;
                        }
                    }
                    crate::services::trap_manager::validate_shard_structure(
                        &trap.trap_r,
                        &trap.trap_s,
                    )?;
                }
            }

            // SST witness verification for the handover (last transaction)
            if let Some(last_tx) = voucher.transactions.last() {
                if let Some(trap) = &last_tx.trap_data {
                    if let Some(guard_base64) = &last_tx.privacy_guard {
                        let decrypted_payload_bytes = decrypt_recipient_payload(
                            guard_base64,
                            &identity.signing_key,
                            &identity.user_id,
                        )
                        .map_err(|e| {
                            VoucherCoreError::Validation(
                                ValidationError::PrivacyGuardDecryptionFailed(format!(
                                    "Decryption failed: {}",
                                    e
                                )),
                            )
                        })?;

                        let payload = serde_json::from_slice::<
                            crate::models::voucher::RecipientPayload,
                        >(
                            &decrypted_payload_bytes,
                        )
                        .map_err(|e| {
                            VoucherCoreError::Validation(
                                ValidationError::PrivacyGuardDecryptionFailed(format!(
                                    "JSON parsing failed: {}",
                                    e
                                )),
                            )
                        })?;

                        // Witness completeness gate
                        let missing_witness = || ValidationError::IncompleteSstWitness;
                        let witness = crate::services::trap_manager::TrapWitness {
                            r_sig: payload
                                .trap_r_sig
                                .clone()
                                .ok_or_else(missing_witness)?,
                            s_sig: payload
                                .trap_s_sig
                                .clone()
                                .ok_or_else(missing_witness)?,
                            m_r: payload
                                .trap_m_r
                                .clone()
                                .ok_or_else(missing_witness)?,
                            m_s: payload
                                .trap_m_s
                                .clone()
                                .ok_or_else(missing_witness)?,
                        };
                        let eph_pub_bytes = match crate::services::crypto::decode_bs58_fixed::<32>(
                            last_tx.sender_ephemeral_pub.as_deref().ok_or_else(|| {
                                ValidationError::MissingSenderEphemeralPubForSst
                            })?,
                            "sender_ephemeral_pub",
                        ) {
                            Ok(arr) => arr,
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("must be 32 bytes")
                                    || msg.contains("exceeds maximum")
                                {
                                    return Err(ValidationError::SenderEphemeralPubWrongLength.into());
                                } else {
                                    return Err(ValidationError::InvalidSenderEphemeralPubEncoding.into());
                                }
                            }
                        };

                        crate::services::trap_manager::verify_sst_witness(
                            &witness,
                            trap,
                            &payload.sender_permanent_did,
                            &trap.ds_tag,
                            &eph_pub_bytes,
                            &last_tx.t_id,
                        )
                        .map_err(|e| ValidationError::SstWitnessVerificationFailed {
                            reason: e.to_string(),
                        })?;
                    }
                }
            }
        }
        Ok(())
    }
}
