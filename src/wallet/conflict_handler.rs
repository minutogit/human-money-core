//! # src/wallet/conflict_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für die
//! Double-Spend-Erkennung und -Verwaltung zuständig sind.

use super::{DoubleSpendCheckResult, Wallet};
use crate::archive::VoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::VoucherStore;
use crate::models::{
    conflict::{
        FingerprintMetadata, ProofOfDoubleSpend, ResolutionEndorsement, TransactionFingerprint,
    },
    profile::{TransactionBundleHeader, UserIdentity},
    voucher::Voucher,
};
use crate::services::conflict_manager;
use crate::services::crypto_utils::get_short_hash_from_user_id;
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::wallet::instance::VoucherStatus;
use ed25519_dalek::{Signature, Verifier};
use std::collections::HashMap;

/// Methoden zur Verwaltung des Fingerprint-Speichers und der Double-Spending-Logik.
impl Wallet {
    /// Durchsucht alle eigenen Gutscheine und aktualisiert den `own_fingerprints`-Store.
    /// WICHTIG: Diese Funktion bewahrt die bereits importierten `foreign_fingerprints`.
    pub fn scan_and_rebuild_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        let (own, mut known) = conflict_manager::scan_and_rebuild_fingerprints(
            &self.voucher_store,
            &self.profile.user_id,
        )?;
        // Bewahre die existierenden `foreign_fingerprints`, da diese nicht aus dem
        // lokalen `voucher_store` rekonstruiert werden können.
        known.foreign_fingerprints =
            std::mem::take(&mut self.known_fingerprints.foreign_fingerprints);
        self.own_fingerprints = own;
        self.known_fingerprints = known;
        Ok(())
    }

    /// Führt eine vollständige Double-Spend-Prüfung durch.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        conflict_manager::check_for_double_spend(&self.own_fingerprints, &self.known_fingerprints)
    }

    /// Entfernt alle abgelaufenen Fingerprints aus dem Speicher.
    pub fn cleanup_expired_fingerprints(&mut self) {
        conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints)
    }

    /// Serialisiert die eigenen Fingerprints für den Export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.own_fingerprints)
    }

    /// Importiert und merged fremde Fingerprints in den Speicher.
    pub fn import_foreign_fingerprints(&mut self, data: &[u8]) -> Result<usize, VoucherCoreError> {
        conflict_manager::import_foreign_fingerprints(&mut self.known_fingerprints, data)
    }

    /// Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
    ///
    /// Diese Methode iteriert durch den `proof_store` und erstellt für jeden
    /// `ProofOfDoubleSpend` eine vereinfachte `ProofOfDoubleSpendSummary`.
    /// Der Status (`is_resolved`, `has_l2_verdict`) wird dabei dynamisch ermittelt.
    pub fn list_conflicts(&self) -> Vec<ProofOfDoubleSpendSummary> {
        self.proof_store
            .proofs
            .values()
            .map(|proof| ProofOfDoubleSpendSummary {
                proof_id: proof.proof_id.clone(),
                offender_id: proof.offender_id.clone(),
                fork_point_prev_hash: proof.fork_point_prev_hash.clone(),
                report_timestamp: proof.report_timestamp.clone(),
                is_resolved: proof.resolutions.as_ref().map_or(false, |v| !v.is_empty()),
                has_l2_verdict: proof.layer2_verdict.is_some(),
            })
            .collect()
    }

    /// Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
    ///
    /// # Arguments
    /// * `proof_id` - Die deterministische ID des zu suchenden Beweises.
    pub fn get_proof_of_double_spend(
        &self,
        proof_id: &str,
    ) -> Result<ProofOfDoubleSpend, VoucherCoreError> {
        self.proof_store
            .proofs
            .get(proof_id)
            .cloned()
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!("Proof with ID '{}' not found.", proof_id))
            })
    }

    /// Erstellt eine signierte Beilegungserklärung (`ResolutionEndorsement`) für einen Konflikt.
    ///
    /// Diese Methode verändert den Wallet-Zustand nicht, sondern erzeugt nur das
    /// signierte Objekt, das dann an andere Parteien gesendet werden kann.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Wallet-Besitzers (des Opfers), der die Beilegung signiert.
    /// * `proof_id` - Die ID des Konflikts, der beigelegt wird.
    /// * `notes` - Eine optionale, menschenlesbare Notiz.
    pub fn create_resolution_endorsement(
        &self,
        identity: &UserIdentity,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, VoucherCoreError> {
        // Sicherstellen, dass der Beweis existiert, bevor eine Beilegung erstellt wird.
        if !self.proof_store.proofs.contains_key(proof_id) {
            return Err(VoucherCoreError::Generic(format!(
                "Cannot create endorsement: Proof with ID '{}' not found.",
                proof_id
            )));
        }
        conflict_manager::create_and_sign_resolution_endorsement(proof_id, identity, notes)
    }

    /// Fügt eine (extern erhaltene) Beilegungserklärung zu einem bestehenden Konfliktbeweis hinzu.
    pub fn add_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
    ) -> Result<(), VoucherCoreError> {
        let proof = self
            .proof_store
            .proofs
            .get_mut(&endorsement.proof_id)
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Cannot add endorsement: Proof with ID '{}' not found.",
                    endorsement.proof_id
                ))
            })?;
        let resolutions = proof.resolutions.get_or_insert_with(Vec::new);
        if !resolutions
            .iter()
            .any(|e| e.endorsement_id == endorsement.endorsement_id)
        {
            resolutions.push(endorsement);
        }
        Ok(())
    }

    // --- NEU HINZUGEFÜGT AUS MOD.RS ---

    /// Verifiziert einen Konflikt und erstellt einen Beweis. Interne Methode.
    pub(super) fn verify_and_create_proof(
        &self,
        identity: &UserIdentity,
        fingerprints: &[TransactionFingerprint],
        archive: &dyn VoucherArchive,
    ) -> Result<Option<crate::models::conflict::ProofOfDoubleSpend>, VoucherCoreError> {
        let mut conflicting_transactions = Vec::new();

        // 1. Finde die vollständigen Transaktionen zu den Fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            }
        }

        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        // 2. Extrahiere Kerndaten und verifiziere Signaturen.
        let offender_id = conflicting_transactions[0]
            .sender_id
            .clone()
            .unwrap_or("anonymous".to_string());
        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();

        let mut verified_tx_count = 0;
        for tx in &conflicting_transactions {
            if tx.sender_id != Some(offender_id.clone()) || tx.prev_hash != fork_point_prev_hash {
                return Ok(None);
            }

            let signed_data = tx.t_id.as_bytes();

            // Use layer2_signature (technical/ephemeral proof) for conflict proof
            let signature_str = match &tx.layer2_signature {
                Some(s) => s,
                None => continue, // Missing L2 signature
            };
            let signature_bytes = bs58::decode(signature_str).into_vec()?;

            // The signature is ALWAYS signed by the ephemeral key (L2)
            let verification_key = if let Some(pub_str) = &tx.sender_ephemeral_pub {
                let pub_bytes = bs58::decode(pub_str).into_vec().map_err(|_| {
                    VoucherCoreError::Crypto("Invalid base58 in sender_ephemeral_pub".to_string())
                })?;
                let array: [u8; 32] = pub_bytes.try_into().map_err(|_| {
                    VoucherCoreError::Crypto(
                        "Invalid key length in sender_ephemeral_pub".to_string(),
                    )
                })?;
                ed25519_dalek::VerifyingKey::from_bytes(&array)
                    .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Ed25519 key: {}", e)))?
            } else {
                continue; // Missing Key is still a skip for backward compatibility or public mode?
                // Actually, if it's a conflict proof, both MUST have L2 signatures.
            };

            // Konvertiere Signature Bytes zu Signature Object
            let sig_arr: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| VoucherCoreError::Crypto("Invalid signature length".to_string()))?;
            let signature = Signature::from_bytes(&sig_arr);

            if verification_key.verify(signed_data, &signature).is_ok() {
                verified_tx_count += 1;
            }
        }

        // 3. Wenn mindestens zwei Signaturen gültig sind, ist der Betrug bewiesen.
        if verified_tx_count < 2 {
            return Ok(None);
        }

        let voucher = self
            .find_voucher_for_transaction(&conflicting_transactions[0].t_id, archive)?
            .ok_or_else(|| VoucherCoreError::VoucherNotFound("for proof creation".to_string()))?;
        let voucher_valid_until = voucher.valid_until.clone();

        // 4. Rufe den Service auf, um das Beweis-Objekt zu erstellen.
        let mut proof = conflict_manager::create_proof_of_double_spend(
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            identity,
        )?;

        // Falls wir den Beweis bereits kennen und ein L2-Urteil haben, übernehmen!
        if let Some(existing_proof) = self.proof_store.proofs.get(&proof.proof_id) {
            proof.layer2_verdict = existing_proof.layer2_verdict.clone();
            proof.resolutions = existing_proof.resolutions.clone();
        }

        Ok(Some(proof))
    }

    /// Interne Hilfsfunktion für Layer-2-Replay-Schutz.
    ///
    /// Prüft die Fingerprints der letzten Transaktionen aller eingehenden Gutscheine
    /// in einem Bundle gegen die gesamte bekannte Fingerprint-Historie des Wallets.
    ///
    /// # Errors
    /// Gibt `VoucherCoreError::TransactionFingerprintAlreadyKnown` zurück, wenn
    /// einer der Fingerprints bereits in `own_fingerprints` oder `known_fingerprints`
    /// (sowohl `local_history` als auch `foreign_fingerprints`) vorhanden ist UND
    /// die `t_id` ebenfalls übereinstimmt (Replay-Angriff).
    ///
    /// Ein Double-Spend (gleicher `fingerprint_hash`, aber NEUE `t_id`) wird
    /// *absichtlich durchgelassen*, damit er von der nachgelagerten
    /// Konfliktlösungslogik ("Earliest Wins") behandelt werden kann.
    pub(super) fn check_bundle_fingerprints_against_history(
        &self,
        vouchers: &[Voucher],
    ) -> Result<(), VoucherCoreError> {
        for voucher in vouchers {
            let last_tx = voucher.transactions.last().ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                    "Received voucher has no transactions.".to_string(),
                ))
            })?;

            // Berechne den relevanten Fingerprint (die "Kollisions-ID")
            let fingerprint =
                conflict_manager::create_fingerprint_for_transaction(last_tx, voucher)?;
            let fingerprint_hash = fingerprint.ds_tag;

            // --- KORRIGIERTE LOGIK: Unterscheide Replay vs. Double Spend ---

            // 1. Sammle alle bekannten t_ids für diesen Fingerprint-Hash
            let mut known_t_ids = std::collections::HashSet::new();

            if let Some(t_ids_vec) = self.own_fingerprints.history.get(&fingerprint_hash) {
                for fp in t_ids_vec {
                    known_t_ids.insert(&fp.t_id);
                }
            }
            if let Some(t_ids_vec) = self.known_fingerprints.local_history.get(&fingerprint_hash) {
                for fp in t_ids_vec {
                    known_t_ids.insert(&fp.t_id);
                }
            }
            if let Some(t_ids_vec) = self
                .known_fingerprints
                .foreign_fingerprints
                .get(&fingerprint_hash)
            {
                for fp in t_ids_vec {
                    known_t_ids.insert(&fp.t_id);
                }
            }

            // 2. Prüfe, ob der Fingerprint-Hash überhaupt bekannt ist.
            if !known_t_ids.is_empty() {
                // Der Fingerprint-Hash ist bekannt.
                // 3. Prüfe, ob die *spezifische t_id* auch bekannt ist.
                let incoming_t_id = &last_tx.t_id;

                if known_t_ids.contains(incoming_t_id) {
                    // --- FALL A (Echter Replay) ---
                    // Wir haben DIESE EXAKTE Transaktion (gleicher Hash, gleiche t_id)
                    // schon einmal gesehen. Das ist ein Replay-Angriff.
                    return Err(VoucherCoreError::TransactionFingerprintAlreadyKnown {
                        fingerprint_hash,
                    });
                }
                // --- FALL B (Double Spend) ---
                // Der Hash ist bekannt, aber die t_id ist NEU.
                // Dies ist ein Double Spend. Wir lassen ihn passieren, damit
                // die "Earliest Wins"-Heuristik ihn fangen kann.
            }
        }

        Ok(())
    }

    /// Wählt Fingerprints für die Weiterleitung in einem Bundle aus, basierend auf der Heuristik.
    ///
    /// # Logic
    /// 1. Markiert alle Fingerprints des zu sendenden Gutscheins als implizit bekannt für den Empfänger.
    /// 2. Iteriert von `depth = 0` aufwärts durch alle bekannten Fingerprints.
    /// 3. Wählt bis zu `MAX_FINGERPRINTS_TO_SEND` Kandidaten aus, die:
    ///    - die aktuelle `depth` haben.
    ///    - dem Empfänger noch nicht bekannt sind.
    /// 4. Aktualisiert die Metadaten (`known_by_peers`) für jeden ausgewählten Fingerprint.
    ///
    /// # Returns
    /// Ein Tupel aus (`Vec<TransactionFingerprint>`, `HashMap<String, u8>`) für das Bundle.
    pub fn select_fingerprints_for_bundle(
        &mut self,
        recipient_id: &str,
        vouchers_in_bundle: &[Voucher],
    ) -> Result<(Vec<TransactionFingerprint>, HashMap<String, u8>), VoucherCoreError> {
        const MAX_FINGERPRINTS_TO_SEND: usize = 150;

        // NEU: Verwende den speichereffizienten Kurz-Hash (gibt [u8; 4] zurück)
        let recipient_short_hash = get_short_hash_from_user_id(recipient_id);

        let mut selected_fingerprints = Vec::new();
        let mut selected_depths = HashMap::new();

        // Schritt 1: Implizit bekannte Fingerprints des aktuellen Transfers markieren
        for voucher in vouchers_in_bundle {
            for tx in &voucher.transactions {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;
                if let Some(meta) = self.fingerprint_metadata.get_mut(&fingerprint.ds_tag) {
                    meta.known_by_peers.insert(recipient_short_hash);
                }
            }
        }

        // Schritt 2: Heuristik zur Auswahl weiterer Fingerprints anwenden
        let mut all_known_fingerprints: Vec<TransactionFingerprint> = self
            .own_fingerprints
            .history
            .values()
            .flatten()
            .chain(self.known_fingerprints.local_history.values().flatten())
            .chain(
                self.known_fingerprints
                    .foreign_fingerprints
                    .values()
                    .flatten(),
            )
            .cloned()
            .collect();

        // Um eine deterministische (wenngleich nicht perfekt zufällige) Auswahl zu gewährleisten, sortieren wir.
        all_known_fingerprints.sort_by(|a, b| a.ds_tag.cmp(&b.ds_tag));

        let mut current_depth = 0;
        while selected_fingerprints.len() < MAX_FINGERPRINTS_TO_SEND {
            let mut candidates_at_depth: Vec<_> = all_known_fingerprints
                .iter()
                .filter(|fp| {
                    if let Some(meta) = self.fingerprint_metadata.get(&fp.ds_tag) {
                        // Kriterien: Korrekte Tiefe UND Empfänger kennt ihn noch nicht
                        meta.depth == current_depth
                            && !meta.known_by_peers.contains(&recipient_short_hash)
                    } else {
                        false
                    }
                })
                .collect();

            if candidates_at_depth.is_empty() && current_depth > 20 {
                // Abbruchbedingung
                break;
            }

            let space_left = MAX_FINGERPRINTS_TO_SEND - selected_fingerprints.len();
            candidates_at_depth.truncate(space_left);

            for fp in candidates_at_depth {
                // Metadaten aktualisieren: Empfänger als "wissend" markieren
                if let Some(meta) = self.fingerprint_metadata.get_mut(&fp.ds_tag) {
                    meta.known_by_peers.insert(recipient_short_hash);
                    selected_fingerprints.push(fp.clone());
                    selected_depths.insert(fp.ds_tag.clone(), meta.depth);
                }
            }
            current_depth += 1;
        }

        Ok((selected_fingerprints, selected_depths))
    }

    /// Verarbeitet empfangene Fingerprints (aktiv und implizit) und aktualisiert die Metadaten.
    pub(super) fn process_received_fingerprints(
        &mut self,
        bundle_header: &TransactionBundleHeader,
        vouchers: &[Voucher],
        forwarded_fingerprints: &[TransactionFingerprint],
        fingerprint_depths: &HashMap<String, u8>,
    ) -> Result<(), VoucherCoreError> {
        // NEU: Verwende den speichereffizienten Kurz-Hash (gibt [u8; 4] zurück)
        let sender_short_hash = get_short_hash_from_user_id(&bundle_header.sender_id);

        // Phase 1: Aktiver Austausch (aus dem Bundle) - Min-Merge-Regel
        for fp in forwarded_fingerprints {
            let received_depth = fingerprint_depths
                .get(&fp.ds_tag)
                .cloned()
                .unwrap_or(u8::MAX);
            let new_depth = received_depth.saturating_add(1);
            let meta = self
                .fingerprint_metadata
                .entry(fp.ds_tag.clone())
                .or_default();
            // Min-Merge: Behalte den kleineren (besseren) depth-Wert
            if new_depth < meta.depth || meta.depth == 0 {
                // 0 ist der Default-Wert
                meta.depth = new_depth;
            }
            meta.known_by_peers.insert(sender_short_hash);
        }

        // Phase 2: Implizite Bestätigung (aus der Gutscheinkette)
        for voucher in vouchers {
            let tx_count = voucher.transactions.len();
            for (i, tx) in voucher.transactions.iter().enumerate() {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;

                // Kettentiefe initialisieren: neueste = 0, vorletzte = 1, etc.
                let depth_in_chain = (tx_count - 1 - i) as u8;

                let meta = self
                    .fingerprint_metadata
                    .entry(fingerprint.ds_tag.clone())
                    .or_insert_with(FingerprintMetadata::default);

                // Nur initialisieren, wenn der Wert noch nicht durch aktiven Austausch gesetzt wurde
                // KORREKTUR: Die Tiefe aus der Kette ist immer die aktuellste Information und sollte bestehende Werte überschreiben.
                meta.depth = depth_in_chain;
                meta.known_by_peers.insert(sender_short_hash);
            }
        }
        Ok(())
    }
}

/// Gekapselte Offline-Konfliktlösung via "Earliest Wins"-Heuristik.
pub(super) fn resolve_conflict_offline(
    voucher_store: &mut VoucherStore,
    fingerprints: &[crate::models::conflict::TransactionFingerprint],
) {
    let tx_ids: std::collections::HashSet<_> = fingerprints.iter().map(|fp| &fp.t_id).collect();

    // --- 1. Lese-Phase: Finde den Gewinner, ohne den Store zu verändern ---
    let conflicting_txs: Vec<_> = voucher_store
        .vouchers
        .values()
        .flat_map(|inst| &inst.voucher.transactions)
        .filter(|tx| tx_ids.contains(&tx.t_id))
        .collect();

    let mut winner_tx: Option<&crate::models::voucher::Transaction> = None;
    let mut earliest_time = u128::MAX;

    for tx in &conflicting_txs {
        if let Some(fp) = fingerprints.iter().find(|f| f.t_id == tx.t_id) {
            if let Ok(decrypted_nanos) =
                conflict_manager::decrypt_transaction_timestamp(tx, fp.encrypted_timestamp)
            {
                if decrypted_nanos < earliest_time {
                    earliest_time = decrypted_nanos;
                    winner_tx = Some(tx);
                }
            }
        }
    }

    // --- 2. Schreib-Phase: Aktualisiere den Status basierend auf der Gewinner-ID ---
    // Die `conflicting_txs`-Liste ist nun nicht mehr im Scope, die unveränderliche Ausleihe ist beendet.
    if let Some(winner_id) = winner_tx.map(|tx| tx.t_id.clone()) {
        for instance in voucher_store.vouchers.values_mut() {
            // Finde heraus, ob diese Instanz eine der Konflikt-Transaktionen enthält.
            if let Some(tx) = instance
                .voucher
                .transactions
                .iter()
                .find(|tx| tx_ids.contains(&tx.t_id))
            {
                instance.status = if tx.t_id == winner_id {
                    VoucherStatus::Active
                } else {
                    VoucherStatus::Quarantined {
                        reason: "Lost offline race".to_string(),
                    }
                };
            }
        }
    }
}
