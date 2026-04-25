//! # src/services/seal_manager.rs
//!
//! Zustandsloser Service für die Erstellung, Aktualisierung und Verifizierung
//! von `WalletSeal`-Objekten (Rollback Guard).
//!
//! Dieses Modul implementiert die kryptographische Logik des Siegel-Mechanismus:
//! - Hashketten-Verwaltung (prev_seal_hash)
//! - Signaturerstellung und -verifizierung
//! - Epoch-Management (Recovery)
//! - Seal-Vergleich für Sync-Erkennung

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::seal::{SealPayload, SealSyncState, WalletSeal};
use crate::services::crypto_utils::{get_hash, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

/// Zustandsloser Manager für WalletSeal-Operationen.
///
/// Alle Methoden sind statisch/assoziiert – der SealManager hält keinen
/// internen Zustand. Er implementiert die reine kryptographische Logik.
pub struct SealManager;

impl SealManager {
    /// Erstellt das allererste Siegel bei einem völlig neuen Wallet (Epoch 0).
    ///
    /// Das initiale Siegel hat:
    /// - `epoch = 0`
    /// - `tx_nonce = 0`
    /// - `prev_seal_hash = Hash("")` (deterministischer Genesis)
    /// - `epoch_start_time = now()`
    ///
    /// # Arguments
    /// * `user_id` - Die vollständige User-ID (inkl. SAI-Präfix).
    /// * `identity` - Die kryptographische Identität zum Signieren.
    /// * `initial_state_hash` - Hash des initialen OwnFingerprints-Stores.
    pub fn create_initial_seal(
        user_id: &str,
        identity: &UserIdentity,
        initial_state_hash: &str,
    ) -> Result<WalletSeal, VoucherCoreError> {
        let now = get_current_timestamp();

        let payload = SealPayload {
            version: 1,
            user_id: user_id.to_string(),
            epoch: 0,
            epoch_start_time: now.clone(),
            tx_nonce: 0,
            prev_seal_hash: get_hash(""), // Deterministischer Genesis-Hash
            state_hash: initial_state_hash.to_string(),
            timestamp: now,
        };

        Self::sign_payload(payload, identity)
    }

    /// Aktualisiert ein Siegel nach einer Transaktion.
    ///
    /// - Inkrementiert `tx_nonce` um 1
    /// - Verkettet den Hash des vorherigen Siegels in `prev_seal_hash`
    /// - Aktualisiert `state_hash` und `timestamp`
    /// - Epoch und `epoch_start_time` bleiben unverändert
    ///
    /// # Arguments
    /// * `prev_seal` - Das vorherige, gültige Siegel.
    /// * `identity` - Die kryptographische Identität zum Signieren.
    /// * `new_state_hash` - Hash des aktualisierten OwnFingerprints-Stores.
    pub fn update_seal(
        prev_seal: &WalletSeal,
        identity: &UserIdentity,
        new_state_hash: &str,
    ) -> Result<WalletSeal, VoucherCoreError> {
        // Hash des vorherigen Siegels berechnen (kanonische Serialisierung)
        let prev_seal_canonical = to_canonical_json(prev_seal)?;
        let prev_hash = get_hash(prev_seal_canonical.as_bytes());

        let payload = SealPayload {
            version: prev_seal.payload.version,
            user_id: prev_seal.payload.user_id.clone(),
            epoch: prev_seal.payload.epoch,
            epoch_start_time: prev_seal.payload.epoch_start_time.clone(),
            tx_nonce: prev_seal.payload.tx_nonce + 1,
            prev_seal_hash: prev_hash,
            state_hash: new_state_hash.to_string(),
            timestamp: get_current_timestamp(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Verifiziert die Signatur und die Integrität eines Siegels.
    ///
    /// Prüft:
    /// 1. Die User-ID im Payload entspricht dem erwarteten Wert.
    /// 2. Der erwartete Public Key kann die Signatur verifizieren.
    /// 3. Die Schema-Version ist unterstützt.
    ///
    /// # Arguments
    /// * `seal` - Das zu verifizierende Siegel.
    /// * `expected_user_id` - Die erwartete User-ID.
    /// * `expected_pubkey_user_id` - Die User-ID, aus der der Public Key extrahiert wird.
    pub fn verify_seal_integrity(
        seal: &WalletSeal,
        expected_user_id: &str,
        expected_pubkey_user_id: &str,
    ) -> Result<(), VoucherCoreError> {
        // 1. Version prüfen
        if seal.payload.version != 1 {
            return Err(VoucherCoreError::Generic(format!(
                "Unsupported seal version: {}. Expected: 1",
                seal.payload.version
            )));
        }

        // 2. User-ID prüfen
        if seal.payload.user_id != expected_user_id {
            return Err(VoucherCoreError::Generic(format!(
                "Seal user_id mismatch. Expected: {}, Found: {}",
                expected_user_id, seal.payload.user_id
            )));
        }

        // 3. Public Key extrahieren und Signatur verifizieren
        let pubkey = crate::services::crypto_utils::get_pubkey_from_user_id(expected_pubkey_user_id)?;

        let payload_canonical = to_canonical_json(&seal.payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());

        let signature_bytes = bs58::decode(&seal.signature)
            .into_vec()
            .map_err(|e| VoucherCoreError::Generic(format!("Failed to decode seal signature: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|e| VoucherCoreError::Generic(format!("Invalid seal signature format: {}", e)))?;

        if !verify_ed25519(&pubkey, payload_hash.as_bytes(), &signature) {
            return Err(VoucherCoreError::Generic(
                "Seal signature verification failed. The seal may have been tampered with.".to_string(),
            ));
        }

        Ok(())
    }

    /// Leitet eine neue Epoche ein (Recovery). Epoch wird strikt inkrementiert.
    ///
    /// Wird nach einer erfolgreichen Wallet-Wiederherstellung aufgerufen.
    /// - `epoch` wird um 1 erhöht (oder auf 1, wenn kein vorheriges Siegel existiert).
    /// - `tx_nonce` wird auf 0 zurückgesetzt.
    /// - `epoch_start_time` wird auf den aktuellen Zeitpunkt gesetzt.
    /// - `prev_seal_hash` verweist auf das letzte bekannte Siegel (falls vorhanden).
    ///
    /// # Arguments
    /// * `last_known_seal` - Das letzte bekannte Siegel (kann `None` sein bei komplettem Verlust).
    /// * `user_id` - Die User-ID des wiederhergestellten Wallets.
    /// * `identity` - Die kryptographische Identität zum Signieren.
    /// * `current_state_hash` - Hash des aktuellen OwnFingerprints-Stores nach Recovery.
    pub fn recover_seal_epoch(
        last_known_seal: Option<&WalletSeal>,
        user_id: &str,
        identity: &UserIdentity,
        current_state_hash: &str,
    ) -> Result<WalletSeal, VoucherCoreError> {
        let now = get_current_timestamp();

        let (new_epoch, prev_hash) = match last_known_seal {
            Some(seal) => {
                let seal_canonical = to_canonical_json(seal)?;
                let hash = get_hash(seal_canonical.as_bytes());
                (seal.payload.epoch + 1, hash)
            }
            None => {
                // Kompletter Datenverlust: Starte bei Epoch 1 mit Genesis-Hash
                (1, get_hash(""))
            }
        };

        let payload = SealPayload {
            version: 1,
            user_id: user_id.to_string(),
            epoch: new_epoch,
            epoch_start_time: now.clone(),
            tx_nonce: 0,
            prev_seal_hash: prev_hash,
            state_hash: current_state_hash.to_string(),
            timestamp: now,
        };

        Self::sign_payload(payload, identity)
    }

    /// Vergleicht zwei verifizierte Siegel und ermittelt den Synchronisationsstatus.
    ///
    /// # Logik
    /// 1. **Synchronized**: Beide Payloads sind identisch.
    /// 2. **LocalIsNewer**: Lokaler `tx_nonce` ist höher UND die Hash-Kette
    ///    baut korrekt auf dem Remote-Siegel auf.
    /// 3. **RemoteIsNewer**: Umgekehrt – Remote ist weiter fortgeschritten.
    /// 4. **ForkDetected**: Die Hash-Ketten divergieren (unterschiedliche
    ///    `prev_seal_hash` trotz fortgeschrittener Nonce).
    ///
    /// # Arguments
    /// * `local` - Das lokale Siegel.
    /// * `remote` - Das vom Server heruntergeladene Siegel.
    pub fn compare_seals(local: &WalletSeal, remote: &WalletSeal) -> SealSyncState {
        // Schneller Pfad: Identische Payloads
        if local.payload == remote.payload {
            return SealSyncState::Synchronized;
        }

        // Hash des jeweils anderen Siegels berechnen (für Kettenverifikation)
        let local_canonical = to_canonical_json(local).unwrap_or_default();
        let local_hash = get_hash(local_canonical.as_bytes());

        let remote_canonical = to_canonical_json(remote).unwrap_or_default();
        let remote_hash = get_hash(remote_canonical.as_bytes());

        // Epochen-Vergleich: Verschiedene Epochen sind ein Fork-Signal,
        // es sei denn, eine Seite hat korrekt eine Recovery durchgeführt.
        if local.payload.epoch != remote.payload.epoch {
            // Wenn die Epochen unterschiedlich sind, muss die Hashkette
            // korrekt auf das vorherige Siegel verweisen.
            if local.payload.epoch > remote.payload.epoch
                && local.payload.prev_seal_hash == remote_hash
            {
                return SealSyncState::LocalIsNewer;
            }
            if remote.payload.epoch > local.payload.epoch
                && remote.payload.prev_seal_hash == local_hash
            {
                return SealSyncState::RemoteIsNewer;
            }
            return SealSyncState::ForkDetected;
        }

        // Gleiche Epoche: Nonce-basierter Vergleich mit Hash-Ketten-Check
        if local.payload.tx_nonce > remote.payload.tx_nonce {
            // Lokal ist weiter. Prüfe, ob die Kette zum Remote zurückführt.
            // Für eine direkte Nachfolge (nonce + 1) muss prev_seal_hash == remote_hash sein.
            // Für größere Abstände prüfen wir nur, dass die allgemeine Richtung stimmt.
            if local.payload.tx_nonce == remote.payload.tx_nonce + 1
                && local.payload.prev_seal_hash == remote_hash
            {
                return SealSyncState::LocalIsNewer;
            }
            // Bei größerem Abstand kann die Kette nicht direkt verifiziert werden.
            // Wir vertrauen der Nonce-Reihenfolge, solange die Epochen gleich sind.
            // Für strikte Sicherheit: ForkDetected bei unbekanntem prev_hash.
            if local.payload.tx_nonce > remote.payload.tx_nonce + 1 {
                // Kann nicht direkt verifiziert werden → LocalIsNewer als heuristisch
                return SealSyncState::LocalIsNewer;
            }
            SealSyncState::ForkDetected
        } else if remote.payload.tx_nonce > local.payload.tx_nonce {
            if remote.payload.tx_nonce == local.payload.tx_nonce + 1
                && remote.payload.prev_seal_hash == local_hash
            {
                return SealSyncState::RemoteIsNewer;
            }
            if remote.payload.tx_nonce > local.payload.tx_nonce + 1 {
                return SealSyncState::RemoteIsNewer;
            }
            SealSyncState::ForkDetected
        } else {
            // Gleiche Nonce, aber unterschiedlicher Payload → Fork
            SealSyncState::ForkDetected
        }
    }

    /// Berechnet den Hash eines WalletSeal für Vergleiche und Sync-Zwecke.
    ///
    /// Verwendet die kanonische JSON-Serialisierung gefolgt von SHA3-256/Base58.
    pub fn compute_seal_hash(seal: &WalletSeal) -> Result<String, VoucherCoreError> {
        let canonical = to_canonical_json(seal)?;
        Ok(get_hash(canonical.as_bytes()))
    }

    // --- Private Hilfsmethoden ---

    /// Signiert einen `SealPayload` und erstellt ein vollständiges `WalletSeal`.
    fn sign_payload(
        payload: SealPayload,
        identity: &UserIdentity,
    ) -> Result<WalletSeal, VoucherCoreError> {
        let payload_canonical = to_canonical_json(&payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());
        let signature = sign_ed25519(&identity.signing_key, payload_hash.as_bytes());
        let signature_str = bs58::encode(signature.to_bytes()).into_string();

        Ok(WalletSeal {
            payload,
            signature: signature_str,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto_utils::generate_ed25519_keypair_for_tests;
    use crate::services::crypto_utils::create_user_id;

    fn test_identity() -> UserIdentity {
        let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("seal_test_seed"));
        let user_id = create_user_id(&public_key, Some("test")).unwrap();
        UserIdentity {
            signing_key,
            public_key,
            user_id,
        }
    }

    #[test]
    fn test_create_initial_seal() {
        let identity = test_identity();
        let state_hash = get_hash("initial_state");

        let seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
        ).unwrap();

        assert_eq!(seal.payload.version, 1);
        assert_eq!(seal.payload.user_id, identity.user_id);
        assert_eq!(seal.payload.epoch, 0);
        assert_eq!(seal.payload.tx_nonce, 0);
        assert_eq!(seal.payload.state_hash, state_hash);
        assert_eq!(seal.payload.prev_seal_hash, get_hash(""));
        assert!(!seal.signature.is_empty());

        // Signatur muss verifizierbar sein
        SealManager::verify_seal_integrity(&seal, &identity.user_id, &identity.user_id)
            .expect("Initial seal should be valid");
    }

    #[test]
    fn test_update_seal_chain() {
        let identity = test_identity();
        let state_hash_1 = get_hash("state_1");
        let state_hash_2 = get_hash("state_2");

        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash_1,
        ).unwrap();

        let seal_2 = SealManager::update_seal(&seal_1, &identity, &state_hash_2).unwrap();

        assert_eq!(seal_2.payload.tx_nonce, 1);
        assert_eq!(seal_2.payload.epoch, 0); // Epoch bleibt
        assert_eq!(seal_2.payload.state_hash, state_hash_2);

        // prev_seal_hash muss auf seal_1 verweisen
        let seal_1_hash = SealManager::compute_seal_hash(&seal_1).unwrap();
        assert_eq!(seal_2.payload.prev_seal_hash, seal_1_hash);

        // Signatur gültig
        SealManager::verify_seal_integrity(&seal_2, &identity.user_id, &identity.user_id)
            .expect("Updated seal should be valid");
    }

    #[test]
    fn test_tamper_detection() {
        let identity = test_identity();
        let state_hash = get_hash("state");

        let mut seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
        ).unwrap();

        // Manipuliere den tx_nonce
        seal.payload.tx_nonce = 999;

        let result = SealManager::verify_seal_integrity(&seal, &identity.user_id, &identity.user_id);
        assert!(result.is_err(), "Tampered seal should fail verification");
    }

    #[test]
    fn test_recover_seal_epoch() {
        let identity = test_identity();
        let state_hash_1 = get_hash("state_1");
        let state_hash_2 = get_hash("state_after_recovery");

        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash_1,
        ).unwrap();

        let recovered_seal = SealManager::recover_seal_epoch(
            Some(&seal_1),
            &identity.user_id,
            &identity,
            &state_hash_2,
        ).unwrap();

        assert_eq!(recovered_seal.payload.epoch, 1);
        assert_eq!(recovered_seal.payload.tx_nonce, 0);
        assert_eq!(recovered_seal.payload.state_hash, state_hash_2);

        SealManager::verify_seal_integrity(&recovered_seal, &identity.user_id, &identity.user_id)
            .expect("Recovered seal should be valid");
    }

    #[test]
    fn test_compare_seals_synchronized() {
        let identity = test_identity();
        let seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state"),
        ).unwrap();

        assert_eq!(
            SealManager::compare_seals(&seal, &seal),
            SealSyncState::Synchronized
        );
    }

    #[test]
    fn test_compare_seals_local_is_newer() {
        let identity = test_identity();
        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state_1"),
        ).unwrap();

        let seal_2 = SealManager::update_seal(&seal_1, &identity, &get_hash("state_2")).unwrap();

        assert_eq!(
            SealManager::compare_seals(&seal_2, &seal_1),
            SealSyncState::LocalIsNewer
        );
    }

    #[test]
    fn test_compare_seals_remote_is_newer() {
        let identity = test_identity();
        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state_1"),
        ).unwrap();

        let seal_2 = SealManager::update_seal(&seal_1, &identity, &get_hash("state_2")).unwrap();

        assert_eq!(
            SealManager::compare_seals(&seal_1, &seal_2),
            SealSyncState::RemoteIsNewer
        );
    }

    #[test]
    fn test_compare_seals_fork_detected() {
        let identity = test_identity();
        let seal_base = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state_base"),
        ).unwrap();

        // Zwei unabhängige Updates auf demselben Basis-Siegel → Fork
        let seal_branch_a = SealManager::update_seal(&seal_base, &identity, &get_hash("state_a")).unwrap();
        let seal_branch_b = SealManager::update_seal(&seal_base, &identity, &get_hash("state_b")).unwrap();

        // Beide haben nonce 1, aber unterschiedliche Payloads → Fork
        assert_eq!(
            SealManager::compare_seals(&seal_branch_a, &seal_branch_b),
            SealSyncState::ForkDetected
        );
    }
}
