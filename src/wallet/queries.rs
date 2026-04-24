//! # src/wallet/queries.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die als "View-Models"
//! dienen. Sie bereiten Daten für die Anzeige in Client-Anwendungen auf.

use super::{AggregatedBalance, VoucherDetails, VoucherSummary, Wallet};
use crate::error::VoucherCoreError;
use crate::models::profile::PublicProfile;
use crate::services::jws_profile_service::export_profile_as_jws;
use crate::wallet::instance::VoucherStatus;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::HashMap;
use std::str::FromStr;

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
        voucher_standard_uuid_filter: Option<&[String]>,
        status_filter: Option<&[VoucherStatus]>,
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

                uuid_match && status_match
            })
            .map(|(local_id, instance)| {
                let voucher = &instance.voucher;

                // Der aktuelle Betrag steht in der letzten Transaktion.
                // Bei einem Split ist es `sender_remaining_amount`, sonst `amount`.
                // Ein archivierter oder bezeugter Gutschein hat für den Besitzer immer den Betrag 0.
                let current_amount = if matches!(instance.status, VoucherStatus::Archived)
                    || matches!(instance.status, VoucherStatus::Endorsed { .. })
                {
                    "0".to_string()
                } else {
                    voucher
                        .transactions
                        .last()
                        .map(|tx| {
                            // Prüfe auf ausgehende (Sent) Transaktion
                            if tx.sender_id.as_ref() == Some(&self.profile.user_id)
                                && tx.sender_remaining_amount.is_some()
                            {
                                tx.sender_remaining_amount
                                    .clone()
                                    .unwrap_or_else(|| "0".to_string())
                            } else {
                                tx.amount.clone()
                            }
                        })
                        .unwrap_or_else(|| "0".to_string())
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
                    voucher_standard_name: voucher.voucher_standard.name.clone(),
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
                    non_redeemable_test_voucher: voucher.non_redeemable_test_voucher,
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
                        // Wenn wir NICHT der Empfänger sind (z.B. wir haben einen Split gesendet),
                        // ist es normal, dass wir den Guard nicht lesen können.
                        if !tx.recipient_id.starts_with(&identity.user_id) {
                            continue;
                        } else {
                            // Wenn wir der Empfänger sind, aber nicht entschlüsseln können,
                            // liegt ein Daten/Key-Problem vor. Wir dürfen nicht weitersuchen,
                            // um keine falsche Herkunft anzuzeigen.
                            return Ok(None);
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
    pub fn get_total_balance_by_currency(&self) -> Vec<AggregatedBalance> {
        // Key: (standard_uuid, unit_abbreviation)
        // Value: (total_amount, standard_name, unit_abbreviation)
        let mut balances: HashMap<(String, String), (Decimal, String, String)> = HashMap::new();

        for instance in self.voucher_store.vouchers.values() {
            if matches!(instance.status, VoucherStatus::Active) {
                let voucher = &instance.voucher;
                let amount_str = instance
                    .voucher
                    .transactions
                    .last()
                    .map(|tx| {
                        // Wenn wir der Sender sind und ein Restbetrag existiert (Split-Transaktion),
                        // ist dies unser aktuelles Guthaben.
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

                    let key = (
                        voucher.voucher_standard.uuid.clone(),
                        voucher
                            .nominal_value
                            .abbreviation
                            .clone()
                            .unwrap_or_default(),
                    );

                    let entry = balances.entry(key).or_insert_with(|| {
                        (
                            Decimal::zero(),
                            voucher.voucher_standard.name.clone(),
                            voucher
                                .nominal_value
                                .abbreviation
                                .clone()
                                .unwrap_or_default(),
                        )
                    });
                    // Addiere den Betrag zum ersten Element des Tupels (dem Decimal-Wert).
                    entry.0 += amount;
                }
            }
        }

        balances
            .into_iter()
            .map(
                |((standard_uuid, _), (total, standard_name, unit))| AggregatedBalance {
                    standard_uuid,
                    standard_name,
                    unit,
                    total_amount: total.to_string(),
                },
            )
            .collect()
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
}
