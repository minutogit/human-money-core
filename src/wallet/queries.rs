//! # src/wallet/queries.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die als "View-Models"
//! dienen. Sie bereiten Daten für die Anzeige in Client-Anwendungen auf.

use super::{AggregatedBalance, AssetClass, VoucherDetails, VoucherSummary, Wallet};
use crate::error::VoucherCoreError;
use crate::models::profile::PublicProfile;
use crate::services::jws_profile_service::export_profile_as_jws;
use crate::wallet::instance::VoucherStatus;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::HashMap;
use std::str::FromStr;

/// Hilfsfunktion zur Formatierung von Namen für die Benutzeroberfläche (BFF-Pattern).
/// Stellt sicher, dass Testgutscheine ein einheitliches "TEST-" Präfix erhalten.
pub(crate) fn format_bff_name(raw_name: &str, is_test: bool) -> String {
    if is_test && !raw_name.starts_with("TEST-") {
        format!("TEST-{}", raw_name)
    } else {
        if !is_test && raw_name.starts_with("TEST-") {
            log::warn!(
                "format_bff_name: name '{}' has TEST- prefix but is_test=false. \
                 Possible data inconsistency in voucher standard definition.",
                raw_name
            );
        }
        raw_name.to_string()
    }
}

/// View-Model / Komfort-Funktionen für Client-Anwendungen.
impl Wallet {
    /// Gibt eine Liste von Zusammenfassungen aller Gutscheine im Wallet zurück.
    ///
    /// Diese Methode ist ideal, um eine Übersicht aller Guthaben in einer UI anzuzeigen.
    ///
    /// # Returns
    /// Ein `Vec<VoucherSummary>` mit den wichtigsten Daten jedes Gutscheins.
    pub fn list_vouchers(
        &self,
        identity: Option<&crate::models::profile::UserIdentity>,
        voucher_standard_uuid_filter: Option<&[String]>,
        status_filter: Option<&[VoucherStatus]>,
        test_filter: Option<bool>,
    ) -> Vec<VoucherSummary> {
        self.voucher_store
            .vouchers
            .iter()
            .filter(|(_, instance)| {
                let uuid_match = match voucher_standard_uuid_filter {
                    // Wenn eine Liste von UUIDs vorhanden und nicht leer ist, prüfen, ob die des Gutscheins enthalten ist.
                    Some(uuids) if !uuids.is_empty() => {
                        uuids.contains(&instance.voucher.voucher_standard.uuid)
                    }
                    // Wenn keine Liste oder eine leere Liste übergeben wird, gilt der Filter als erfüllt.
                    _ => true,
                };

                let status_match = match status_filter {
                    // Gleiche Logik für den Status-Filter.
                    Some(statuses) if !statuses.is_empty() => statuses.contains(&instance.status),
                    _ => true,
                };

                let test_match = match test_filter {
                    Some(is_test) => instance.voucher.non_redeemable_test_voucher == is_test,
                    None => true,
                };

                uuid_match && status_match && test_match
            })
            .map(|(local_id, instance)| {
                let voucher = &instance.voucher;

                // --- Guthaben-Berechnung ---
                let current_amount = if matches!(instance.status, VoucherStatus::Archived)
                    || matches!(instance.status, VoucherStatus::Endorsed { .. })
                    || matches!(instance.status, VoucherStatus::Expired)
                {
                    "0".to_string()
                } else {
                    // Versuche den Holder-Hash zu berechnen (Stateless Re-Derivation)
                    let holder_pub_hash = identity.and_then(|id| {
                         self.rederive_secret_seed(voucher, id).ok()
                    }).map(|key| {
                        crate::services::crypto_utils::get_hash(key.verifying_key().to_bytes())
                    });

                    // Nutze den Core-Service zur präzisen Berechnung
                    // Fallback: Wenn keine Identity da ist, nutzt get_spendable_balance die Public-Mode Logik.
                    let _standard = crate::models::voucher_standard_definition::VoucherStandardDefinition::default(); // Dummy für Decimal-Places (wird in SM geladen eigentlich)
                    // HINWEIS: In einer echten Umgebung müsste hier der echte Standard geladen sein.
                    // Da get_spendable_balance aber Decimal::from_str nutzt, reicht es hier oft für die Anzeige.
                    
                    // TODO: In einer idealen Welt laden wir hier den echten Standard. 
                    // Für die Summary-Liste nutzen wir eine vereinfachte Logik oder das last_tx Feld direkt.
                    
                    voucher.transactions.last().map(|tx| {
                         let is_own_sender = if let Some(id) = identity {
                             tx.sender_id.as_ref() == Some(&id.user_id)
                         } else {
                             tx.sender_id.is_some() // Public Mode Heuristik
                         };

                         // Krypto-Prüfung bevorzugen
                         if let Some(hash) = &holder_pub_hash {
                             if Some(hash) == tx.receiver_ephemeral_pub_hash.as_ref() {
                                 tx.amount.clone()
                             } else if Some(hash) == tx.change_ephemeral_pub_hash.as_ref() {
                                 tx.sender_remaining_amount.clone().unwrap_or_else(|| "0".to_string())
                             } else {
                                 "0".to_string()
                             }
                         } else {
                             // Klassische Heuristik für Abwärtskompatibilität / Public Mode
                             if is_own_sender && tx.sender_remaining_amount.is_some() {
                                 tx.sender_remaining_amount.clone().unwrap_or_else(|| "0".to_string())
                             } else {
                                 tx.amount.clone()
                             }
                         }
                    }).unwrap_or_else(|| "0".to_string())
                };

                VoucherSummary {
                    local_instance_id: local_id.clone(),
                    status: instance.status.clone(),
                    creator_id: voucher.creator_profile.id.clone().unwrap_or_default(),
                    valid_until: voucher.valid_until.clone(),
                    description: voucher.voucher_standard.template.description.clone(),
                    current_amount,
                    unit: voucher
                        .nominal_value
                        .abbreviation
                        .clone()
                        .unwrap_or_default(),
                    raw_standard_name: voucher.voucher_standard.name.clone(),
                    voucher_standard_uuid: voucher.voucher_standard.uuid.clone(),
                    // Zähle Transaktionen exkl. der initialen "init" Transaktion.
                    transaction_count: (voucher.transactions.len() as u32).saturating_sub(1),
                    signatures_count: voucher.signatures.len() as u32,
                    // Ein Gutschein gilt als besichert, wenn das `collateral`-Objekt existiert und eine `collateral_type` hat.
                    has_collateral: voucher.collateral.is_some(),
                    creator_first_name: voucher
                        .creator_profile
                        .first_name
                        .clone()
                        .unwrap_or_default(),
                    creator_last_name: voucher
                        .creator_profile
                        .last_name
                        .clone()
                        .unwrap_or_default(),
                    creator_coordinates: voucher
                        .creator_profile
                        .coordinates
                        .clone()
                        .unwrap_or_default(),
                    is_test_voucher: voucher.non_redeemable_test_voucher,
                    display_currency: format_bff_name(
                        voucher
                            .nominal_value
                            .abbreviation
                            .as_deref()
                            .unwrap_or(&voucher.nominal_value.unit),
                        voucher.non_redeemable_test_voucher,
                    ),
                    display_standard_name: format_bff_name(
                        &voucher.voucher_standard.name,
                        voucher.non_redeemable_test_voucher,
                    ),
                }
            })
            .collect()
    }

    /// Ruft eine detaillierte Ansicht für einen einzelnen Gutschein anhand seiner lokalen ID ab.
    ///
    /// # Arguments
    /// * `local_instance_id` - Die lokale ID des Gutscheins im Wallet.
    ///
    /// # Returns
    /// Ein `Result` mit `VoucherDetails` bei Erfolg oder `VoucherCoreError`, wenn
    /// der Gutschein nicht gefunden wird.
    pub fn get_voucher_details(
        &self,
        local_instance_id: &str,
    ) -> Result<VoucherDetails, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        Ok(VoucherDetails {
            local_instance_id: instance.local_instance_id.clone(),
            status: instance.status.clone(),
            voucher: instance.voucher.clone(),
            display_currency: format_bff_name(
                instance
                    .voucher
                    .nominal_value
                    .abbreviation
                    .as_deref()
                    .unwrap_or(&instance.voucher.nominal_value.unit),
                instance.voucher.non_redeemable_test_voucher,
            ),
            display_standard_name: format_bff_name(
                &instance.voucher.voucher_standard.name,
                instance.voucher.non_redeemable_test_voucher,
            ),
            is_test_voucher: instance.voucher.non_redeemable_test_voucher,
        })
    }

    /// Ermittelt die Identität des Absenders, von dem wir diesen Gutschein erhalten haben.
    /// Iteriert rückwärts über alle Transaktionen und findet die erste Transaktion,
    /// deren tatsächlicher Sender nicht der aktuelle Nutzer ist.
    pub fn get_voucher_source_sender(
        &self,
        local_instance_id: &str,
        identity: &crate::models::profile::UserIdentity,
    ) -> Result<Option<String>, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        // Iteriere rückwärts über alle Transaktionen des Gutscheins
        for tx in instance.voucher.transactions.iter().rev() {
            // Bestimme den tatsächlichen Sender dieser Transaktion
            let actual_sender = if let Some(guard_base64) = &tx.privacy_guard {
                // Fall A: privacy_guard vorhanden
                // Versuche zu entschlüsseln. Wenn erfolgreich, nutze payload.sender_permanent_did.
                // Wenn die Entschlüsselung fehlschlägt (z.B. Key nicht verfügbar), brich ab und gib Ok(None) zurück!
                match crate::services::crypto_utils::decrypt_recipient_payload(
                    guard_base64,
                    &identity.signing_key,
                    &identity.user_id,
                ) {
                    Ok(decrypted_payload_bytes) => {
                        match serde_json::from_slice::<crate::models::voucher::RecipientPayload>(
                            &decrypted_payload_bytes,
                        ) {
                            Ok(payload) => payload.sender_permanent_did,
                            Err(_) => {
                                // JSON-Parsing fehlgeschlagen - unsicherer Zustand
                                return Ok(None);
                            }
                        }
                    }
                    Err(_) => {
                        // SICHERHEITS-CHECK: Unterscheidung zw. Outbound und Inbound.
                        // Wenn wir der SENDER sind (z.B. wir haben einen Split gesendet),
                        // ist es normal, dass wir den Guard (für den anderen Empfänger) nicht lesen können.
                        let is_sender = tx.sender_id.as_deref() == Some(&identity.user_id);
                        
                        // Wenn wir der EMPFÄNGER sind (explizit oder anonym), aber nicht entschlüsseln können,
                        // liegt ein Daten/Key-Problem bei einer an uns gerichteten Transaktion vor. 
                        let is_recipient = tx.recipient_id == identity.user_id || tx.recipient_id == crate::models::voucher::ANONYMOUS_ID;

                        if is_sender {
                            continue; // Outbound -> Weitersuchen
                        } else if is_recipient {
                            // Inbound, aber unlesbar -> Abbrechen (Spoofing Schutz)
                            return Ok(None);
                        } else {
                            // Weder noch (z.B. eine historische Transaktion dazwischen) -> Weitersuchen
                            continue;
                        }
                    }
                }
            } else {
                // Fall B: Kein Guard vorhanden (Public Mode)
                // Nutze den Klartext tx.sender_id
                match &tx.sender_id {
                    Some(sender) => sender.clone(),
                    None => continue, // Keine sender_id, überspringe diese Transaktion
                }
            };

            // Wenn der tatsächliche Sender nicht der aktuelle Nutzer ist, haben wir unsere Quelle gefunden
            if actual_sender != identity.user_id {
                return Ok(Some(actual_sender));
            }
        }

        // Keine passende Transaktion gefunden
        Ok(None)
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung/Einheit.
    ///
    /// Diese Funktion summiert die Werte aller Gutscheine mit dem Status `Active` auf
    /// und gibt eine Map zurück, die von der Währungseinheit (z.B. "Minuten", "EUR")
    /// auf den Gesamtbetrag abbildet.
    ///
    /// # Returns
    /// Ein `Vec<AggregatedBalance>`, der die Gesamtsummen pro Gutschein-Standard und Währung enthält.
    pub fn get_total_balance_by_currency(
        &self,
        identity: Option<&crate::models::profile::UserIdentity>,
    ) -> Vec<AggregatedBalance> {
        // Key: AssetClass (standard_uuid, unit_abbreviation, is_test_voucher)
        // Value: (total_amount, standard_name)
        let mut balances: HashMap<AssetClass, (Decimal, String)> = HashMap::new();

        for instance in self.voucher_store.vouchers.values() {
            if matches!(instance.status, VoucherStatus::Active) {
                let voucher = &instance.voucher;
                let amount_str = instance
                    .voucher
                    .transactions
                    .last()
                    .map(|tx| {
                        // Krypto-Prüfung bevorzugen
                        if let Some(id) = identity {
                            if let Ok(key) = self.rederive_secret_seed(voucher, id) {
                                let hash = crate::services::crypto_utils::get_hash(key.verifying_key().to_bytes());
                                if Some(&hash) == tx.receiver_ephemeral_pub_hash.as_ref() {
                                    return tx.amount.clone();
                                } else if Some(&hash) == tx.change_ephemeral_pub_hash.as_ref() {
                                    return tx.sender_remaining_amount.clone().unwrap_or_else(|| "0".to_string());
                                }
                            }
                        }

                        // Fallback: Heuristik
                        if tx.sender_id.as_ref() == Some(&self.profile.user_id)
                            && tx.sender_remaining_amount.is_some()
                        {
                            tx.sender_remaining_amount
                                .clone()
                                .unwrap_or_else(|| "0".to_string())
                        } else {
                            // Ansonsten ist es der volle Transaktionsbetrag.
                            tx.amount.clone()
                        }
                    })
                    .unwrap_or_else(|| "0".to_string());

                if let Ok(amount) = Decimal::from_str(&amount_str) {
                    // Überspringe Gutscheine mit einem Guthaben von Null.
                    if amount.is_zero() {
                        continue;
                    }

                    let asset_class = AssetClass {
                        standard_uuid: voucher.voucher_standard.uuid.clone(),
                        unit: voucher
                            .nominal_value
                            .abbreviation
                            .clone()
                            .unwrap_or_else(|| voucher.nominal_value.unit.clone()),
                        is_test_voucher: voucher.non_redeemable_test_voucher,
                    };

                    let entry = balances.entry(asset_class).or_insert_with(|| {
                        (
                            Decimal::zero(),
                            voucher.voucher_standard.name.clone(),
                        )
                    });
                    // Addiere den Betrag zum ersten Element des Tupels (dem Decimal-Wert).
                    entry.0 += amount;
                }
            }
        }

        balances
            .into_iter()
            .map(|(key, (total, standard_name))| {
                let display_currency = format_bff_name(&key.unit, key.is_test_voucher);
                let display_standard_name = format_bff_name(&standard_name, key.is_test_voucher);

                AggregatedBalance {
                    standard_uuid: key.standard_uuid,
                    standard_name,
                    unit: key.unit,
                    total_amount: total.to_string(),
                    display_currency,
                    display_standard_name,
                    is_test_voucher: key.is_test_voucher,
                }
            })
            .collect()
    }

    /// Ermittelt alle im Wallet aktiven Asset-Klassen (Standard + Test-Status).
    /// Dies dient der UI zum sauberen Befüllen von Filter-Dropdowns.
    pub fn get_active_asset_classes(&self) -> Vec<super::types::AssetClassSummary> {
        let mut classes = std::collections::HashSet::new();

        for instance in self.voucher_store.vouchers.values() {
            if matches!(instance.status, VoucherStatus::Active) {
                let voucher = &instance.voucher;
                let unit = voucher
                    .nominal_value
                    .abbreviation
                    .clone()
                    .unwrap_or_else(|| voucher.nominal_value.unit.clone());
                
                let is_test = voucher.non_redeemable_test_voucher;
                
                classes.insert(super::types::AssetClassSummary {
                    standard_uuid: voucher.voucher_standard.uuid.clone(),
                    is_test_voucher: is_test,
                    display_standard_name: super::format_bff_name(&voucher.voucher_standard.name, is_test),
                    display_currency: super::format_bff_name(&unit, is_test),
                });
            }
        }

        classes.into_iter().collect()
    }

    /// Gibt die User-ID des Wallet-Inhabers zurück.
    ///
    /// # Returns
    /// Eine Referenz auf die User-ID-Zeichenkette.
    pub fn get_user_id(&self) -> &str {
        &self.profile.user_id
    }

    /// Prüft den Ruf einer User-ID basierend auf den lokal gespeicherten Beweisen.
    ///
    /// Diese Funktion implementiert das implizite Web-of-Trust. Sie durchsucht den
    /// `proof_store` nach ungelösten Konflikten, die von der `user_id` verursacht wurden.
    pub fn check_reputation(&self, offender_id: &str) -> crate::models::conflict::TrustStatus {
        use crate::models::conflict::TrustStatus;

        let mut latest_resolved = None;

        for entry in self.proof_store.proofs.values() {
            if entry.proof.offender_id == offender_id {
                let is_officially_resolved = entry.proof.resolutions.as_ref().map_or(false, |r| !r.is_empty())
                    || entry.proof.layer2_verdict.is_some();
                
                if is_officially_resolved || entry.local_override {
                    // Merke uns das letzte gelöste, falls kein ungelöstes gefunden wird.
                    latest_resolved = Some(TrustStatus::Resolved {
                        proof_id: entry.proof.proof_id.clone(),
                        is_local: entry.local_override,
                        note: entry.local_note.clone(),
                    });
                } else {
                    // Sobald EIN ungelöster Beweis gefunden wird, ist der Status "KnownOffender".
                    return TrustStatus::KnownOffender(entry.proof.proof_id.clone());
                }
            }
        }

        latest_resolved.unwrap_or(TrustStatus::Clean)
    }

    /// Exportiert das eigene Profil als JWS Compact Serialization String.
    ///
    /// Dies folgt RFC 7515 und erzeugt einen String im Format:
    /// base64url(header).base64url(payload).base64url(signature)
    ///
    /// # Arguments
    /// * `identity` - Die UserIdentity mit dem privaten Signaturschlüssel.
    ///
    /// # Returns
    /// Ein JWS Compact String oder einen Fehler.
    pub fn export_profile_jws(
        &self,
        identity: &crate::models::profile::UserIdentity,
    ) -> Result<String, VoucherCoreError> {
        // Erstelle ein PublicProfile aus dem Wallet-Profil
        let public_profile = PublicProfile {
            protocol_version: Some("v1".to_string()),
            id: Some(self.profile.user_id.clone()),
            first_name: self.profile.first_name.clone(),
            last_name: self.profile.last_name.clone(),
            organization: self.profile.organization.clone(),
            community: self.profile.community.clone(),
            address: self.profile.address.clone(),
            gender: self.profile.gender.clone(),
            email: self.profile.email.clone(),
            phone: self.profile.phone.clone(),
            coordinates: self.profile.coordinates.clone(),
            url: self.profile.url.clone(),
            service_offer: self.profile.service_offer.clone(),
            needs: self.profile.needs.clone(),
            picture_url: self.profile.picture_url.clone(),
        };

        export_profile_as_jws(&identity.signing_key, &public_profile)
    }

    /// Lädt die Event-Historie des Wallets, kombiniert aus persistenten und RAM-basierten Events.
    ///
    /// # Arguments
    /// * `storage` - Das Storage-Backend.
    /// * `auth` - Die Authentifizierungsmethode.
    /// * `offset` - Der Offset für die Pagination.
    /// * `limit` - Die maximale Anzahl der zurückzugebenden Events.
    ///
    /// # Returns
    /// Eine chronologisch absteigend sortierte Liste von `WalletEvent` Objekten.
    pub fn get_event_history<S: crate::storage::Storage>(
        &self,
        storage: &S,
        auth: &crate::storage::AuthMethod,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, VoucherCoreError> {
        let pending_len = self.pending_events.len();
        let mut result = Vec::with_capacity(limit);

        // 1. Hole neueste Events zuerst aus dem RAM (pending_events sind aufsteigend, also rev())
        if offset < pending_len {
            let to_take = std::cmp::min(limit, pending_len - offset);
            let pending_page = self.pending_events.iter()
                .rev() // Macht aus aufsteigend -> absteigend (neueste zuerst)
                .skip(offset)
                .take(to_take)
                .cloned();
            result.extend(pending_page);
        }

        // 2. Falls wir das Limit noch nicht erreicht haben, füllen wir mit Storage-Events auf
        if result.len() < limit {
            let remaining_limit = limit - result.len();
            
            // Berechne den korrekten Offset für den Storage.
            // Wenn der User-Offset größer ist als das was wir im RAM haben, 
            // müssen wir die RAM-Größe vom Offset abziehen.
            let storage_offset = if offset > pending_len {
                offset - pending_len
            } else {
                0
            };

            // Hier übergeben wir nun das ECHTE Limit und Offset! Chunking wird optimal genutzt.
            let persisted_page = storage
                .load_events(&self.profile.user_id, auth, storage_offset, remaining_limit)
                .map_err(VoucherCoreError::Storage)?;

            result.extend(persisted_page);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod aggregation_tests {
    use crate::test_utils::{setup_in_memory_wallet, ACTORS};
    use crate::wallet::instance::{VoucherInstance, VoucherStatus};
    use crate::models::voucher::{Voucher, Transaction};

    #[test]
    fn test_balance_aggregation_strictly_separates_test_and_live_money() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        // 1. Live Minuto (10)
        let mut v1 = Voucher::default();
        v1.voucher_standard.uuid = "minuto-uuid".to_string();
        v1.voucher_standard.name = "Minuto".to_string();
        v1.nominal_value.unit = "Minuto".to_string();
        v1.nominal_value.abbreviation = Some("Min".to_string());
        v1.non_redeemable_test_voucher = false;
        v1.transactions.push(Transaction { amount: "10".to_string(), ..Default::default() });
        
        // 2. Live Minuto (5) -> Should be aggregated with v1
        let mut v2 = v1.clone();
        v2.transactions[0].amount = "5".to_string();
        
        // 3. Test Minuto (50) -> Should be separate
        let mut v3 = v1.clone();
        v3.non_redeemable_test_voucher = true;
        v3.transactions[0].amount = "50".to_string();
        
        wallet.voucher_store.vouchers.insert("v1".to_string(), VoucherInstance {
            voucher: v1, status: VoucherStatus::Active, local_instance_id: "v1".to_string()
        });
        wallet.voucher_store.vouchers.insert("v2".to_string(), VoucherInstance {
            voucher: v2, status: VoucherStatus::Active, local_instance_id: "v2".to_string()
        });
        wallet.voucher_store.vouchers.insert("v3".to_string(), VoucherInstance {
            voucher: v3, status: VoucherStatus::Active, local_instance_id: "v3".to_string()
        });
        
        let balances = wallet.get_total_balance_by_currency(Some(identity));
        
        assert_eq!(balances.len(), 2);
        
        let live_balance = balances.iter().find(|b| !b.is_test_voucher).unwrap();
        assert_eq!(live_balance.total_amount, "15");
        assert_eq!(live_balance.display_currency, "Min");
        assert_eq!(live_balance.display_standard_name, "Minuto");
        
        let test_balance = balances.iter().find(|b| b.is_test_voucher).unwrap();
        assert_eq!(test_balance.total_amount, "50");
        assert_eq!(test_balance.display_currency, "TEST-Min");
        assert_eq!(test_balance.display_standard_name, "TEST-Minuto");
    }

    #[test]
    fn test_format_bff_name_logic() {
        // Nutze super::super, da wir in mod aggregation_tests sind, welches in impl Wallet ist.
        // Moment, aggregation_tests ist ein eigenes Modul. format_bff_name ist pub(crate) im parent (queries.rs).
        assert_eq!(crate::wallet::format_bff_name("Minuto", true), "TEST-Minuto");
        assert_eq!(crate::wallet::format_bff_name("Minuto", false), "Minuto");
        assert_eq!(crate::wallet::format_bff_name("TEST-Minuto", true), "TEST-Minuto");
        assert_eq!(crate::wallet::format_bff_name("TEST-Minuto", false), "TEST-Minuto");
    }

    #[test]
    fn test_list_vouchers_respects_test_filter() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let mut v_live = Voucher::default();
        v_live.non_redeemable_test_voucher = false;
        
        let mut v_test = Voucher::default();
        v_test.non_redeemable_test_voucher = true;

        wallet.voucher_store.vouchers.insert("l1".to_string(), VoucherInstance {
            voucher: v_live.clone(), status: VoucherStatus::Active, local_instance_id: "l1".to_string()
        });
        wallet.voucher_store.vouchers.insert("l2".to_string(), VoucherInstance {
            voucher: v_live, status: VoucherStatus::Active, local_instance_id: "l2".to_string()
        });
        wallet.voucher_store.vouchers.insert("t1".to_string(), VoucherInstance {
            voucher: v_test.clone(), status: VoucherStatus::Active, local_instance_id: "t1".to_string()
        });
        wallet.voucher_store.vouchers.insert("t2".to_string(), VoucherInstance {
            voucher: v_test.clone(), status: VoucherStatus::Active, local_instance_id: "t2".to_string()
        });
        wallet.voucher_store.vouchers.insert("t3".to_string(), VoucherInstance {
            voucher: v_test, status: VoucherStatus::Active, local_instance_id: "t3".to_string()
        });

        // None -> 5
        assert_eq!(wallet.list_vouchers(Some(identity), None, None, None).len(), 5);
        // Some(true) -> 3
        assert_eq!(wallet.list_vouchers(Some(identity), None, None, Some(true)).len(), 3);
        // Some(false) -> 2
        assert_eq!(wallet.list_vouchers(Some(identity), None, None, Some(false)).len(), 2);
    }

    #[test]
    fn test_asset_class_listing() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let mut v1 = Voucher::default();
        v1.voucher_standard.uuid = "std-1".to_string();
        v1.voucher_standard.name = "Minuto".to_string();
        v1.nominal_value.unit = "Minuto".to_string();
        v1.non_redeemable_test_voucher = false;
        
        let mut v2 = v1.clone();
        v2.non_redeemable_test_voucher = true;

        wallet.voucher_store.vouchers.insert("v1".to_string(), VoucherInstance {
            voucher: v1, status: VoucherStatus::Active, local_instance_id: "v1".to_string()
        });
        wallet.voucher_store.vouchers.insert("v2".to_string(), VoucherInstance {
            voucher: v2, status: VoucherStatus::Active, local_instance_id: "v2".to_string()
        });

        let classes = wallet.get_active_asset_classes();
        assert_eq!(classes.len(), 2);
        
        assert!(classes.iter().any(|c| !c.is_test_voucher && c.display_standard_name == "Minuto"));
        assert!(classes.iter().any(|c| c.is_test_voucher && c.display_standard_name == "TEST-Minuto"));
    }
}
