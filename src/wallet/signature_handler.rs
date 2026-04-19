//! # src/wallet/signature_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für den
//! Signatur-Workflow zuständig sind (Anfragen, Erstellen, Verarbeiten).

use super::Wallet;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::services::utils::to_canonical_json;
use crate::wallet::instance::VoucherStatus;
use crate::{error::VoucherCoreError, models::profile::PublicProfile};

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
    /// * `config` - Die Verschlüsselungskonfiguration (TargetDid, Password, oder Cleartext).
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`.
    pub fn create_signing_request(
        &self,
        identity: &UserIdentity,
        local_instance_id: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let instance = self.voucher_store.vouchers.get(local_instance_id).ok_or(
            VoucherCoreError::VoucherNotFound(local_instance_id.to_string()),
        )?;

        // BUGFIX: Füge die fehlende Status-Prüfung hinzu. Eine Signaturanfrage ist
        // nur für aktive oder unvollständige Gutscheine sinnvoll.
        if !matches!(
            instance.status,
            VoucherStatus::Active | VoucherStatus::Incomplete { .. }
        ) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }
        let payload = to_canonical_json(&instance.voucher)?;

        let container = crate::services::secure_container_manager::create_secure_container(
            identity,
            config,
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
    /// * `config` - Die Verschlüsselungskonfiguration (TargetDid, Password, oder Cleartext).
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        include_details: bool,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        // Stelle die optionalen Profil-Details zusammen
        let details = if include_details {
            Some(PublicProfile {
                protocol_version: Some("v1".to_string()),
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
                service_offer: self.profile.service_offer.clone(),
                needs: self.profile.needs.clone(),
                picture_url: self.profile.picture_url.clone(),
            })
        } else {
            None
        };

        let init_t_id = &voucher_to_sign.transactions[0].t_id;

        let signed_signature =
            crate::services::signature_manager::complete_and_sign_detached_signature(
                signature_data,
                identity,
                details,
                &voucher_to_sign.voucher_id,
                init_t_id, // <-- HINZUFÜGEN
            )?;

        let payload = to_canonical_json(&signed_signature)?;

        let container = crate::services::secure_container_manager::create_secure_container(
            identity,
            config,
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
    /// * `password` - Optionales Passwort für symmetrische Verschlüsselung.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg die aktualisierte Instance ID enthält.
    pub fn process_and_attach_signature(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<String, VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let payload =
            crate::services::secure_container_manager::open_secure_container(&container, identity, password)?;

        if !matches!(container.c, PayloadType::DetachedSignature) {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let signature: DetachedSignature = serde_json::from_slice(&payload)?;

        let signature_obj_inner = match &signature {
            DetachedSignature::Signature(s) => s,
        };

        // Wir müssen den Gutschein finden, um die init_t_id für die Validierung zu erhalten
        let target_instance_for_val = self
            .voucher_store
            .vouchers
            .values()
            .find(|instance| instance.voucher.voucher_id == signature_obj_inner.voucher_id)
            .ok_or_else(|| {
                VoucherCoreError::VoucherNotFound(format!(
                    "No voucher found matching signature's voucher_id: {}",
                    signature_obj_inner.voucher_id
                ))
            })?;

        let init_t_id = &target_instance_for_val.voucher.transactions[0].t_id;
        crate::services::signature_manager::validate_detached_signature(&signature, init_t_id)?;

        // Since the voucher_id field has been removed from VoucherSignature,
        // we need to match the signature to a voucher differently.
        // In the new design, the signature should be matched based on other identifying factors
        // such as the context of which vouchers are expecting signatures.

        let signature_obj = match signature {
            DetachedSignature::Signature(s) => s,
        };

        // Find a voucher that is expecting this signature
        let target_instance = self
            .voucher_store
            .vouchers
            .values_mut()
            .find(|instance| instance.voucher.voucher_id == signature_obj.voucher_id)
            .ok_or_else(|| {
                VoucherCoreError::VoucherNotFound(format!(
                    "No voucher found matching signature's voucher_id: {}",
                    signature_obj.voucher_id
                ))
            })?;

        // (Optional, aber empfohlen) Prüfen, ob die Signatur bereits vorhanden ist
        if target_instance
            .voucher
            .signatures
            .iter()
            .any(|sig| sig.signature_id == signature_obj.signature_id)
        {
            // Stillschweigend ignorieren oder Fehler zurückgeben
            return Err(VoucherCoreError::MismatchedSignatureData(
                format!(
                    "Signature {} already attached to voucher {} [LOCAL_ID:{}]",
                    signature_obj.signature_id, signature_obj.voucher_id, target_instance.local_instance_id
                ),
            ));
        }

        target_instance.voucher.signatures.push(signature_obj);

        Ok(target_instance.local_instance_id.clone())
    }

    /// Entfernt eine Zusatzsignatur (z. B. von Bürgen oder Zeugen) von einem Gutschein.
    ///
    /// Dieser Vorgang darf nur vom Ersteller des Gutscheins ausgeführt werden und nur,
    /// solange der Gutschein noch nicht in Umlauf ist (nur eine init-Transaktion vorhanden).
    ///
    /// # Arguments
    /// * `identity` - Die Identität des anfragenden Nutzers (muss der Ersteller sein).
    /// * `local_instance_id` - Die ID des Gutscheins im lokalen `voucher_store`.
    /// * `signature_id` - Die ID der zu entfernenden Signatur.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg `Ok(())` zurückgibt.
    ///
    /// # Errors
    /// * `VoucherNotFound` - Der Gutschein wurde nicht gefunden.
    /// * `VoucherNotActive` - Der Gutschein hat nicht den Status Active oder Incomplete.
    /// * `NotTheCreator` - Die anfragende Identität ist nicht der Ersteller des Gutscheins.
    /// * `VoucherAlreadyInCirculation` - Der Gutschein hat bereits mehr als eine Transaktion (ist im Umlauf).
    /// * `CannotRemoveCreatorSignature` - Es wurde versucht, die Kern-Signatur des Erstellers zu entfernen.
    pub fn remove_signature(
        &mut self,
        identity: &UserIdentity,
        local_instance_id: &str,
        signature_id: &str,
    ) -> Result<(), VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get_mut(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        // 1. Status-Prüfung: Nur Active oder Incomplete erlaubt
        if !matches!(
            instance.status,
            VoucherStatus::Active | VoucherStatus::Incomplete { .. }
        ) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }

        // 2. History-Prüfung: Nur eine init-Transaktion erlaubt
        if instance.voucher.transactions.len() != 1 {
            return Err(VoucherCoreError::VoucherAlreadyInCirculation);
        }
        let first_transaction = &instance.voucher.transactions[0];
        if first_transaction.t_type != "init" {
            return Err(VoucherCoreError::VoucherAlreadyInCirculation);
        }

        // 3. Identity-Prüfung: Nur der Ersteller darf Signaturen entfernen
        let creator_id = instance
            .voucher
            .creator_profile
            .id
            .as_ref()
            .ok_or_else(|| VoucherCoreError::Generic("Creator profile has no ID".to_string()))?;
        if &identity.user_id != creator_id {
            return Err(VoucherCoreError::NotTheCreator);
        }

        // 4. Rollen-Prüfung: Finde die Signatur und prüfe, ob sie entfernt werden darf
        let signature_to_remove = instance
            .voucher
            .signatures
            .iter()
            .find(|sig| sig.signature_id == signature_id)
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Signature with ID {} not found",
                    signature_id
                ))
            })?;

        if signature_to_remove.role == "creator" {
            return Err(VoucherCoreError::CannotRemoveCreatorSignature);
        }

        // 5. Signatur entfernen
        instance
            .voucher
            .signatures
            .retain(|sig| sig.signature_id != signature_id);

        // 6. Status-Reevaluierung: Wenn Signaturen fehlen, setze auf Incomplete
        // Hinweis: Eine vollständige Validierung gegen den Standard erfordert Zugriff auf den Standard,
        // was auf dieser Ebene nicht verfügbar ist. Wir setzen konservativ auf Incomplete,
        // wenn Signaturen entfernt wurden. Die App-Service-Schicht kann bei Bedarf neu validieren.
        if !matches!(instance.status, VoucherStatus::Incomplete { .. }) {
            instance.status = VoucherStatus::Incomplete {
                reasons: vec![crate::ValidationFailureReason::RequiredSignatureMissing {
                    role_description: "Signature removed, validation against standard required".to_string(),
                }],
            };
        }

        Ok(())
    }
}
