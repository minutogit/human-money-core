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
        // Bewahre die existierenden Historien, da diese nicht (vollständig) aus dem
        // lokalen `voucher_store` rekonstruiert werden können (z.B. nach Archivierung).
        known.foreign_fingerprints =
            std::mem::take(&mut self.known_fingerprints.foreign_fingerprints);
        
        // NEU: Auch local_history bewahren/mergen
        let old_local_history = std::mem::take(&mut self.known_fingerprints.local_history);
        for (hash, fps) in old_local_history {
            let entry = known.local_history.entry(hash).or_default();
            for fp in fps {
                if !entry.iter().any(|e| e.t_id == fp.t_id) {
                    entry.push(fp);
                }
            }
        }

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
    /// `ProofStoreEntry` eine vereinfachte `ProofOfDoubleSpendSummary`.
    /// Der Status (`is_resolved`, `has_l2_verdict`) wird dabei dynamisch ermittelt.
    pub fn list_conflicts(&self) -> Vec<ProofOfDoubleSpendSummary> {
        self.proof_store
            .proofs
            .values()
            .map(|entry| {
                let proof = &entry.proof;
                ProofOfDoubleSpendSummary {
                    proof_id: proof.proof_id.clone(),
                    offender_id: proof.offender_id.clone(),
                    fork_point_prev_hash: proof.fork_point_prev_hash.clone(),
                    report_timestamp: proof.report_timestamp.clone(),
                    is_resolved: proof.resolutions.as_ref().map_or(false, |v| !v.is_empty()),
                    has_l2_verdict: proof.layer2_verdict.is_some(),
                    local_override: entry.local_override,
                    local_note: entry.local_note.clone(),
                    conflict_role: entry.conflict_role,
                    affected_voucher_name: proof.affected_voucher_name.clone(),
                    voucher_standard_uuid: proof.voucher_standard_uuid.clone(),
                }
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
            .map(|entry| entry.proof.clone())
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
        let entry = self
            .proof_store
            .proofs
            .get_mut(&endorsement.proof_id)
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Cannot add endorsement: Proof with ID '{}' not found.",
                    endorsement.proof_id
                ))
            })?;
        let resolutions = entry.proof.resolutions.get_or_insert_with(Vec::new);
        if !resolutions
            .iter()
            .any(|e| e.endorsement_id == endorsement.endorsement_id)
        {
            resolutions.push(endorsement);
        }
        Ok(())
    }

    /// Setzt den lokalen Override für einen Konflikt.
    /// Dies erlaubt es dem Nutzer, einem Täter trotz eines Beweises lokal wieder zu vertrauen.
    pub fn set_conflict_local_override(
        &mut self,
        proof_id: &str,
        value: bool,
        note: Option<String>,
    ) -> Result<(), VoucherCoreError> {
        let entry = self.proof_store.proofs.get_mut(proof_id).ok_or_else(|| {
            VoucherCoreError::Generic(format!("Proof with ID '{}' not found.", proof_id))
        })?;
        entry.local_override = value;
        entry.local_note = note;
        Ok(())
    }

    /// Importiert einen externen Beweis in den ProofStore.
    ///
    /// # Immunitäts-Regel (MVP):
    /// Wenn der Beweis lokal bereits existiert, wird der Import ignoriert.
    /// Dies verhindert, dass externe Daten lokale Entscheidungen (Overrides) überschreiben.
    pub fn import_proof(&mut self, proof: ProofOfDoubleSpend) -> Result<(), VoucherCoreError> {
        if self.proof_store.proofs.contains_key(&proof.proof_id) {
            // Bereits bekannt -> Ignorieren (Immunität lokaler Entscheidungen)
            return Ok(());
        }

        // --- Bestimmung der Rolle (Opfer vs. Zeuge) ---
        // REFINEMENT: Wir sind nur ein Opfer, wenn wir KEINEN aktiven Gutschein für diesen
        // Konflikt-Tag haben, aber mindestens einer existiert (der nun in Quarantäne ist).
        let mut has_active = false;
        let mut has_quarantined = false;
        
        for tx in &proof.conflicting_transactions {
            if let Some(instance) = self.find_local_voucher_by_tx_id(&tx.t_id) {
                if matches!(instance.status, VoucherStatus::Active) {
                    has_active = true;
                } else if matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    has_quarantined = true;
                }
            }
        }
        
        let conflict_role = if has_quarantined && !has_active {
            crate::models::conflict::ConflictRole::Victim
        } else {
            crate::models::conflict::ConflictRole::Witness
        };

        let entry = crate::models::conflict::ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role,
        };

        self.proof_store.proofs.insert(entry.proof.proof_id.clone(), entry);
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
        let mut missing_t_ids = Vec::new();

        // 1. Finde die vollständigen Transaktionen zu den Fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            } else {
                missing_t_ids.push(fp.t_id.clone());
            }
        }

        if conflicting_transactions.is_empty() {
            return Ok(None);
        }

        // 2. Extrahiere Kerndaten von der ERSTEN gefundenen Transaktion.
        let offender_id = conflicting_transactions[0]
            .sender_id
            .clone()
            .unwrap_or("anonymous".to_string());
        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();
        
        for t_id in missing_t_ids {
            let mut synthetic_tx = crate::models::voucher::Transaction::default();
            synthetic_tx.t_id = t_id;
            synthetic_tx.sender_id = Some(offender_id.clone());
            synthetic_tx.prev_hash = fork_point_prev_hash.clone();
            synthetic_tx.t_type = "soft_placeholder".to_string();
            synthetic_tx.amount = "0.00 (Synthetic)".to_string();
            conflicting_transactions.push(synthetic_tx);
        }

        // 5. Versuche L2-Verifikation für alle verfügbaren Transaktionen.
        let mut _verified_tx_count = 0;
        let mut voucher_valid_until = "unknown".to_string();
        let mut affected_voucher_name = None;
        let mut voucher_standard_uuid = None;

        if let Some(voucher) = self.find_voucher_for_transaction(&conflicting_transactions[0].t_id, archive)? {
            voucher_valid_until = voucher.valid_until.clone();
            affected_voucher_name = Some(voucher.voucher_standard.name.clone());
            voucher_standard_uuid = Some(voucher.voucher_standard.uuid.clone());

            if let Ok(layer2_voucher_id) = crate::services::l2_gateway::extract_layer2_voucher_id(&voucher) {
                for (_i, tx) in conflicting_transactions.iter().filter(|t| t.t_type != "soft_placeholder").enumerate() {
                    match crate::services::voucher_validation::verify_transaction_integrity_and_signature(
                        tx,
                        &layer2_voucher_id,
                    ) {
                        Ok(()) => {
                            _verified_tx_count += 1;
                        }
                        Err(_e) => {
                        }
                    }
                }
            }
        }


        // 6. Erstelle das Beweis-Objekt. 
        // WICHTIG: Wir erstellen den Beweis JETZT IMMER, wenn wir >= 2 Kandidaten haben,
        // auch wenn sie nicht kryptographisch voll verifiziert werden konnten ("Soft Proof").
        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        let mut proof = conflict_manager::create_proof_of_double_spend(
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            identity,
        )?;

        // Metadaten setzen
        proof.affected_voucher_name = affected_voucher_name;
        proof.voucher_standard_uuid = voucher_standard_uuid;

        // Falls wir den Beweis bereits kennen und ein L2-Urteil oder Resolutions haben, übernehmen!
        if let Some(existing_entry) = self.proof_store.proofs.get(&proof.proof_id) {
            proof.layer2_verdict = existing_entry.proof.layer2_verdict.clone();
            proof.resolutions = existing_entry.proof.resolutions.clone();
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
    /// 2. Priorisiert negative "VIP"-Fingerprints (Betrugserkennung).
    /// 3. Iteriert aufwärts durch alle bekannten positiven Fingerprints.
    /// 4. Wählt bis zu `MAX_FINGERPRINTS_TO_SEND` Kandidaten aus.
    ///
    /// # Returns
    /// Ein Tupel aus (`Vec<TransactionFingerprint>`, `HashMap<String, i8>`) für das Bundle.
    pub fn select_fingerprints_for_bundle(
        &mut self,
        recipient_id: &str,
        vouchers_in_bundle: &[Voucher],
    ) -> Result<(Vec<TransactionFingerprint>, HashMap<String, i8>), VoucherCoreError> {
        const MAX_FINGERPRINTS_TO_SEND: usize = 150;

        // Verwende den speichereffizienten Kurz-Hash (gibt [u8; 4] zurück)
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

        // Schritt 2: Alle bekannten Fingerprints sammeln
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

        // Sortierung: Berechnung der "Effektiven Tiefe" für organische Verdrängung
        all_known_fingerprints.sort_by(|a, b| {
            let depth_a = self.fingerprint_metadata.get(&a.ds_tag).map(|m| m.depth).unwrap_or(0);
            let depth_b = self.fingerprint_metadata.get(&b.ds_tag).map(|m| m.depth).unwrap_or(0);
            
            // Berechnung: VIPs erhalten einen 2-Hops Vorsprung.
            // Wir casten auf i16, damit wir bei (1 - 2) = -1 keinen Underflow riskieren.
            let eff_a = if depth_a < 0 { (depth_a.abs() as i16) - 2 } else { depth_a as i16 };
            let eff_b = if depth_b < 0 { (depth_b.abs() as i16) - 2 } else { depth_b as i16 };
            
            eff_a.cmp(&eff_b).then_with(|| a.ds_tag.cmp(&b.ds_tag))
        });

        for fp in all_known_fingerprints {
            if selected_fingerprints.len() >= MAX_FINGERPRINTS_TO_SEND {
                break;
            }

            if let Some(meta) = self.fingerprint_metadata.get_mut(&fp.ds_tag) {
                // Nur wenn der Empfänger ihn noch nicht kennt
                if !meta.known_by_peers.contains(&recipient_short_hash) {
                    meta.known_by_peers.insert(recipient_short_hash);
                    selected_fingerprints.push(fp.clone());
                    selected_depths.insert(fp.ds_tag.clone(), meta.depth);
                }
            }
        }

        Ok((selected_fingerprints, selected_depths))
    }

    /// Verarbeitet empfangene Fingerprints (aktiv und implizit) und aktualisiert die Metadaten.
    pub(super) fn process_received_fingerprints(
        &mut self,
        bundle_header: &TransactionBundleHeader,
        vouchers: &[Voucher],
        forwarded_fingerprints: &[TransactionFingerprint],
        fingerprint_depths: &HashMap<String, i8>,
    ) -> Result<(), VoucherCoreError> {
        // Verwende den speichereffizienten Kurz-Hash
        let sender_short_hash = get_short_hash_from_user_id(&bundle_header.sender_id);

        // Phase 1: Aktiver Austausch (aus dem Bundle)
        // Wir gruppieren die Fingerprints nach ds_tag, um Symmetrie-Prüfung bei VIPs durchzuführen.
        let mut ds_groups: HashMap<String, Vec<(&TransactionFingerprint, i8)>> = HashMap::new();
        for fp in forwarded_fingerprints {
            if let Some(&depth) = fingerprint_depths.get(&fp.ds_tag) {
                ds_groups.entry(fp.ds_tag.clone()).or_default().push((fp, depth));
            }
        }

        for (ds_tag, group) in ds_groups {
            if group.is_empty() { continue; }
            
            let mut received_depth = group[0].1;

            // --- Symmetrie-Prüfung für VIP-Fingerprints ---
            if received_depth < 0 {
                // Ein negativer VIP-Fingerprint muss immer im Partner-Duo kommen (Symmetrie).
                // Und beide müssen exakt dieselbe depth aufweisen.
                let is_symmetric = group.len() >= 2 && group.iter().all(|(_, d)| *d == received_depth);
                
                if !is_symmetric {
                    // Asymmetrischer VIP-Spam: Normalisieren auf positive Strafe (z.B. 1)
                    received_depth = 1;
                }
            }

            // --- Loop-Protection & Alterung ---
            let meta = self.fingerprint_metadata.entry(ds_tag.clone()).or_default();
            
            // Loop-Schutz: Wenn der Fingerprint bereits lokal als VIP bekannt ist, 
            // ignorieren wir weitere negative Updates aus dem Gossip, um Replay-Loops 
            // zu verhindern. Die lokale Alterung bzw. Erst-Entdeckung hat Vorrang.
            if meta.depth < 0 && received_depth < 0 {
                continue;
            } else if meta.depth > 0 && received_depth < 0 {
                // Übergang von normal zu VIP: Wir übernehmen den VIP-Status.
                let new_depth = received_depth.saturating_sub(1);
                meta.depth = new_depth;
            } else {
                // Min-Merge / Update für alle anderen Fälle (normal zu normal, neu zu VIP, etc.)
                let new_depth = if received_depth < 0 {
                    // VIP-Alterung: saturating_sub(1) macht es negativer (-1 -> -2 -> ... -> -128)
                    received_depth.saturating_sub(1)
                } else {
                    // Normale Alterung
                    received_depth.saturating_add(1)
                };

                if meta.depth == 0 || new_depth < meta.depth {
                    meta.depth = new_depth;
                }
            }
            meta.known_by_peers.insert(sender_short_hash);
        }

        // Phase 2: Implizite Bestätigung (aus der Gutscheinkette)
        for voucher in vouchers {
            let tx_count = voucher.transactions.len();
            for (i, tx) in voucher.transactions.iter().enumerate() {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;

                let depth_in_chain = (tx_count - 1 - i) as i8;

                let meta = self
                    .fingerprint_metadata
                    .entry(fingerprint.ds_tag.clone())
                    .or_insert_with(FingerprintMetadata::default);

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


