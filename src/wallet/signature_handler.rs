//! # src/wallet/signature_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für den
//! Signatur-Workflow zuständig sind (Anfragen, Erstellen, Verarbeiten).

use super::Wallet;
use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::wallet::instance::{VoucherInstance, VoucherStatus};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::services::utils::to_canonical_json;

/// Methoden für den Signatur-Workflow.
impl Wallet {
    /// Erstellt einen `SecureContainer`, um einen Gutschein zur Unterzeichnung zu versenden.
    ///
    /// Diese Funktion verändert den Wallet-Zustand nicht. Sie dient nur dazu, eine
    /// Anfrage zu verpacken.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des anfragenden Gutschein-Besitzers.
    /// * `local_instance_id` - Die ID des Gutscheins im lokalen `voucher_store`.
    /// * `recipient_id` - Die User ID des potenziellen Unterzeichners.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`.
    pub fn create_signing_request(
        &self,
        identity: &UserIdentity,
        local_instance_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or(VoucherCoreError::VoucherNotFound(
                local_instance_id.to_string(),
            ))?;

        // BUGFIX: Füge die fehlende Status-Prüfung hinzu. Eine Signaturanfrage ist
        // nur für aktive oder unvollständige Gutscheine sinnvoll.
        if !matches!(instance.status, VoucherStatus::Active | VoucherStatus::Incomplete { .. }) {
            return Err(VoucherCoreError::VoucherNotActive(
                instance.status.clone(),
            ));
        }
        let payload = to_canonical_json(&instance.voucher)?;

        let container = crate::services::secure_container_manager::create_secure_container(
            identity,
            &[recipient_id.to_string()],
            payload.as_bytes(),
            PayloadType::VoucherForSigning,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Erstellt eine `DetachedSignature` für einen Gutschein und verpackt sie in einem
    /// `SecureContainer` für den Rückversand.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Unterzeichners.
    /// * `voucher_to_sign` - Der Gutschein, der unterzeichnet werden soll (vom Client validiert).
    /// * `signature_data` - Die vom Client vorbereiteten Metadaten der Signatur.
    /// * `original_sender_id` - Die User ID des ursprünglichen Anfragers (Empfänger der Antwort).
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        original_sender_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let signed_signature =
            crate::services::signature_manager::complete_and_sign_detached_signature(
                signature_data,
                &voucher_to_sign.voucher_id,
                identity,
            )?;

        let payload = to_canonical_json(&signed_signature)?;

        let container = crate::services::secure_container_manager::create_secure_container(
            identity,
            &[original_sender_id.to_string()],
            payload.as_bytes(),
            PayloadType::DetachedSignature,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Verarbeitet einen `SecureContainer`, der eine `DetachedSignature` enthält,
    /// und fügt diese dem entsprechenden lokalen Gutschein hinzu.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Empfängers.
    /// * `container_bytes` - Die empfangenen Container-Daten.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg leer ist.
    pub fn process_and_attach_signature(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
    ) -> Result<String, VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let payload = crate::services::secure_container_manager::open_secure_container(&container, identity)?;

        if !matches!(container.c, PayloadType::DetachedSignature) {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let signature: DetachedSignature = serde_json::from_slice(&payload)?;
        crate::services::signature_manager::validate_detached_signature(&signature)?;

        let voucher_id = match &signature {
            DetachedSignature::Signature(s) => &s.voucher_id,
        };

        let target_instance = self.find_active_voucher_by_voucher_id(voucher_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id.clone()))?;

        match signature {
            DetachedSignature::Signature(s) => target_instance.voucher.signatures.push(s),
        }

        Ok(target_instance.local_instance_id.clone())
    }

    /// Findet die aktive Instanz eines Gutscheins anhand seiner globalen `voucher_id`.
    fn find_active_voucher_by_voucher_id(
        &mut self,
        voucher_id: &str,
    ) -> Option<&mut VoucherInstance> {
        self.voucher_store
            .vouchers
            .values_mut()
            .find(|instance| { // KORREKTUR: Signaturen können an 'Active' oder 'Incomplete' Gutscheine angehängt werden.
                instance.voucher.voucher_id == voucher_id
                    && (matches!(instance.status, VoucherStatus::Active)
                        || matches!(instance.status, VoucherStatus::Incomplete { .. }))
            })
    }
}