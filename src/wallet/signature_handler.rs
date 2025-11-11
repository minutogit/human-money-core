//! # src/wallet/signature_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für den
//! Signatur-Workflow zuständig sind (Anfragen, Erstellen, Verarbeiten).

use super::Wallet;
use crate::{error::VoucherCoreError, models::profile::PublicProfile};
use crate::models::profile::UserIdentity;
use crate::wallet::instance::VoucherStatus;
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
    /// * `include_details` - Ob die `PublicProfile`-Daten des Unterzeichners eingebettet werden sollen.
    /// * `original_sender_id` - Die User ID des ursprünglichen Anfragers (Empfänger der Antwort).
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        include_details: bool,
        original_sender_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        // Stelle die optionalen Profil-Details zusammen
        let details = if include_details {
            Some(PublicProfile {
                id: None, // `signer_id` ist bereits auf der Hauptebene vorhanden
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
            })
        } else {
            None
        };

        let signed_signature =
            crate::services::signature_manager::complete_and_sign_detached_signature(
                signature_data,
                identity,
                details,
                &voucher_to_sign.voucher_id, // <-- HINZUFÜGEN
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

        // Since the voucher_id field has been removed from VoucherSignature,
        // we need to match the signature to a voucher differently.
        // In the new design, the signature should be matched based on other identifying factors
        // such as the context of which vouchers are expecting signatures.
        
        let signature_obj = match signature {
            DetachedSignature::Signature(s) => s,
        };

        // Find a voucher that is expecting this signature
        // NEU: Finde den Gutschein direkt über die voucher_id
        let target_instance = self.voucher_store.vouchers.values_mut()
            .find(|instance| instance.voucher.voucher_id == signature_obj.voucher_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(
                format!("No voucher found matching signature's voucher_id: {}", signature_obj.voucher_id)
            ))?;

        // (Optional, aber empfohlen) Prüfen, ob die Signatur bereits vorhanden ist
        if target_instance.voucher.signatures.iter().any(|sig| sig.signature_id == signature_obj.signature_id) {
            // Stillschweigend ignorieren oder Fehler zurückgeben
            return Err(VoucherCoreError::MismatchedSignatureData( // TODO: Besserer Fehlertyp
                format!("Signature {} already attached to voucher {}", signature_obj.signature_id, signature_obj.voucher_id)
            )); 
        }

        target_instance.voucher.signatures.push(signature_obj);

        Ok(target_instance.local_instance_id.clone())
    }


}