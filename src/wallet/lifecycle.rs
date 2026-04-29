//! # src/wallet/lifecycle.rs
//!
//! Enthält alle Methoden, die sich mit dem "Lebenszyklus" des Wallets
//! (Erstellung, Laden, Speichern) und der Erstellung neuer Gutscheine befassen.

use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::models::{
    conflict::{CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore},
    profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore},
};
use crate::services::crypto_utils::create_user_id;
use crate::services::voucher_manager::NewVoucherData;
use crate::services::{voucher_manager, voucher_validation};
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage, StorageError};
use crate::wallet::Wallet;
use crate::wallet::instance::{ValidationFailureReason, VoucherStatus};

impl Wallet {
    /// Erstellt ein brandneues, leeres Wallet aus einer Mnemonic-Phrase.
    ///
    /// # ⚠️ CRITICAL SECURITY REQUIREMENT: `local_instance_id`
    /// The `local_instance_id` prevents users from accidentally cloning their wallet 
    /// folder to another device, which would cause state forks and double-spends.
    /// 
    /// **AS AN APP DEVELOPER, YOU MUST NOT STORE THIS ID IN THE WALLET DIRECTORY!**
    /// If you store the ID next to the wallet files, a user copying the folder will 
    /// also copy the ID, completely bypassing the cloning protection.
    /// 
    /// **Correct Usage:** Store this ID in the OS Keychain (e.g., via the `keyring` crate),
    /// or derive it deterministically from hardware (e.g., `/etc/machine-id`).
    pub fn new_from_mnemonic(
        mnemonic_phrase: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
        language: crate::services::mnemonic::MnemonicLanguage,
        local_instance_id: String,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (public_key, signing_key) =
            crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, passphrase, language)?;

        let user_id = create_user_id(&public_key, user_prefix)
            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };

        let profile = UserProfile {
            user_id,
            first_name: None,
            last_name: None,
            organization: None,
            community: None,
            address: None,
            gender: None,
            email: None,
            phone: None,
            coordinates: None,
            url: None,
            service_offer: None,
            needs: None,
            picture_url: None,
            l2_server_pubkey: None,
        };

        let voucher_store = VoucherStore::default();
        let bundle_meta_store = BundleMetadataStore::default();
        let known_fingerprints = KnownFingerprints::default();
        let own_fingerprints = OwnFingerprints::default();
        let proof_store = ProofStore::default();
        let fingerprint_metadata = CanonicalMetadataStore::default();

        let wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            known_fingerprints,
            own_fingerprints,
            proof_store,
            fingerprint_metadata,
            local_instance_id,
        };

        Ok((wallet, identity))
    }

    /// Lädt ein existierendes Wallet aus einem `Storage`-Backend.
    /// Gibt das Wallet und die entschlüsselte UserIdentity zurück.
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
        local_instance_id: String,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (profile, voucher_store, identity) = storage.load_wallet(auth)?;

        if let AuthMethod::Mnemonic(..) = auth {
            println!(
                "[Debug Wallet::load] Recovery successful! Decrypted identity with Mnemonic. User ID: {}",
                identity.user_id
            );
        }

        let bundle_meta_store = storage.load_bundle_metadata(&identity.user_id, auth)?;
        let known_fingerprints = storage.load_known_fingerprints(&identity.user_id, auth)?;
        let own_fingerprints = storage.load_own_fingerprints(&identity.user_id, auth)?;
        let proof_store = storage.load_proofs(&identity.user_id, auth)?;
        let fingerprint_metadata = storage.load_fingerprint_metadata(&identity.user_id, auth)?;

        // Sicherheitsüberprüfung, um sicherzustellen, dass die entschlüsselte Identität
        // mit den Profildaten übereinstimmt.
        if profile.user_id != identity.user_id {
            return Err(StorageError::AuthenticationFailed.into());
        }

        let mut wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            known_fingerprints,
            own_fingerprints,
            proof_store,
            fingerprint_metadata,
            local_instance_id,
        };

        wallet.rebuild_derived_stores()?;
        Ok((wallet, identity))
    }

    /// Speichert den aktuellen Zustand des Wallets in einem `Storage`-Backend.
    pub fn save<S: Storage>(
        &self,
        storage: &mut S,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError> {
        storage.save_wallet(&self.profile, &self.voucher_store, identity, auth)?;
        storage.save_bundle_metadata(&identity.user_id, auth, &self.bundle_meta_store)?;
        storage.save_known_fingerprints(&identity.user_id, auth, &self.known_fingerprints)?;
        storage.save_own_fingerprints(&identity.user_id, auth, &self.own_fingerprints)?;
        storage.save_proofs(&identity.user_id, auth, &self.proof_store)?;
        storage.save_fingerprint_metadata(&identity.user_id, auth, &self.fingerprint_metadata)?;
        Ok(())
    }

    /// Setzt das Passwort für ein Wallet in einem `Storage`-Backend zurück.
    pub fn reset_password<S: Storage>(
        storage: &mut S,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
        storage.reset_password(identity, new_password)
    }

    /// Erstellt einen brandneuen Gutschein und fügt ihn direkt zum Wallet hinzu.
    ///
    /// Diese Methode orchestriert die Erstellung eines neuen Gutscheins basierend auf
    /// einem Standard, signiert ihn mit der Identität des Erstellers und speichert
    /// ihn sofort im `VoucherStore` mit dem Status `Active`.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Erstellers, enthält den Signierschlüssel.
    /// * `standard_definition` - Die Regeln und Vorlagen des Gutschein-Standards.
    /// * `data` - Die spezifischen Daten für den neuen Gutschein (z.B. Betrag).
    ///
    /// # Returns
    /// Ein `Result` mit dem vollständig erstellten `Voucher` bei Erfolg.
    pub fn create_new_voucher(
        &mut self,
        identity: &UserIdentity,
        // Die Signatur wird erweitert, um die verifizierten Daten zu erhalten
        verified_standard: &VoucherStandardDefinition,
        standard_hash: &str,
        lang_preference: &str,
        data: NewVoucherData,
    ) -> Result<crate::models::voucher::Voucher, VoucherCoreError> {
        let new_voucher = voucher_manager::create_voucher(
            data,
            verified_standard,
            standard_hash,
            &identity.signing_key,
            lang_preference,
        )?;

        // KORREKTE LOGIK ZUR ZUSTANDSVERWALTUNG:
        // 1. Berechne die korrekte lokale ID basierend auf der `init`-Transaktion.
        let local_id = Self::calculate_local_instance_id(&new_voucher, &identity.user_id)?;

        // 2. Bestimme den initialen Status durch eine sofortige Validierung.
        let initial_status = match voucher_validation::validate_voucher_against_standard(
            &new_voucher,
            verified_standard,
        ) {
            Ok(_) => VoucherStatus::Active,
            // Wenn Geschäftsregeln (z.B. fehlende Signaturen) verletzt sind, ist der Status `Incomplete`.
            Err(VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))) => {
                VoucherStatus::Incomplete {
                    reasons: vec![ValidationFailureReason::BusinessRule {
                        message: msg,
                    }],
                }
            }
            // Jeder andere Validierungsfehler bei der Erstellung ist ein fataler Fehler.
            Err(e) => return Err(e),
        };

        // 3. Füge die Instanz mit der korrekten ID und dem korrekten Status hinzu.
        self.add_voucher_instance(local_id, new_voucher.clone(), initial_status);

        // 4. WICHTIG: Baue die abgeleiteten Stores (Fingerprints, Metadaten) neu auf.
        self.rebuild_derived_stores()?;

        Ok(new_voucher)
    }

    /// Erzwingt die Bindung des Wallets an das aktuelle Gerät (Handover).
    /// Erhöht die Epoche und setzt die neue instance_id im Siegel.
    pub fn force_device_handover<S: Storage>(
        &mut self,
        storage: &mut S,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<crate::models::seal::WalletSeal, VoucherCoreError> {
        // 1. Altes Siegel laden
        let record = storage.load_seal(&identity.user_id, auth)
            .map_err(VoucherCoreError::Storage)?
            .ok_or_else(|| VoucherCoreError::RequiresSealRecovery)?;

        // 2. Neues Siegel mit erhöhter Epoche und neuer instance_id erstellen
        // Wir nutzen dafür SealManager::recover_seal_epoch, da es genau das tut (Epoch + 1)
        let state_hash = {
            let canonical = crate::services::utils::to_canonical_json(&self.own_fingerprints)?;
            crate::services::crypto_utils::get_hash(canonical.as_bytes())
        };

        let new_seal = SealManager::recover_seal_epoch(
            Some(&record.seal),
            &identity.user_id,
            identity,
            &state_hash,
            &self.local_instance_id,
        )?;

        // 3. Speichern
        let new_record = crate::models::seal::LocalSealRecord {
            seal: new_seal.clone(),
            sync_status: crate::models::seal::SyncStatus::PendingUpload,
            is_locked_due_to_fork: false,
        };

        storage.save_seal(&identity.user_id, auth, &new_record)
            .map_err(VoucherCoreError::Storage)?;

        Ok(new_seal)
    }
}
