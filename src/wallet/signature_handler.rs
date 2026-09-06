//! # src/wallet/signature_handler.rs
//!
//! Contains the implementation of `Wallet` methods responsible for the
//! signature workflow (requesting, creating, processing).

use super::Wallet;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::services::utils::to_canonical_json;
use crate::wallet::instance::VoucherStatus;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::PublicProfile;

/// Methods for the signature workflow.
impl Wallet {
    /// Creates a `SecureContainer` to send a voucher for signing.
    ///
    /// This function does not modify wallet state. It only serves to package a request.
    ///
    /// # Arguments
    /// * `identity` - The identity of the requesting voucher owner.
    /// * `local_instance_id` - The ID of the voucher in the local `voucher_store`.
    /// * `config` - The encryption configuration (TargetDid, Password, or Cleartext).
    ///
    /// # Returns
    /// The serialized bytes of the `SecureContainer`.
    pub fn create_signing_request(
        &self,
        identity: &UserIdentity,
        local_instance_id: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let instance = self.voucher_store.vouchers.get(local_instance_id).ok_or(
            VoucherCoreError::VoucherNotFound(local_instance_id.to_string()),
        )?;

        // BUGFIX: Add missing status check. A signature request is
        // only meaningful for active or incomplete vouchers.
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

    /// Creates a `DetachedSignature` for a voucher and packages it in a
    /// `SecureContainer` for return transmission.
    ///
    /// # Arguments
    /// * `identity` - The identity of the signer.
    /// * `voucher_to_sign` - The voucher to be signed (validated by client).
    /// * `signature_data` - Signature metadata prepared by the client.
    /// * `include_details` - Whether the signer's `PublicProfile` data should be embedded.
    /// * `config` - The encryption configuration (TargetDid, Password, or Cleartext).
    ///
    /// # Returns
    /// The serialized bytes of the `SecureContainer` containing the signature.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        include_details: bool,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        // Assemble optional profile details
        let details = if include_details {
            Some(PublicProfile {
                protocol_version: Some("v1".to_string()),
                id: None, // `signer_id` is already present at the top level
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

        // HMC-SEC-06-04: The voucher originates from an external signing
        // request. Indexing `transactions[0]` directly on unvalidated remote
        // input is a remotely reachable panic that aborts the host process.
        let init_t_id = &voucher_to_sign
            .transactions
            .first()
            .ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                    "Voucher has no transactions".to_string(),
                ))
            })?
            .t_id;

        let signed_signature =
            crate::services::signature_manager::complete_and_sign_detached_signature(
                signature_data,
                identity,
                details,
                &voucher_to_sign.voucher_id,
                init_t_id, // <-- ADD
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

    /// Processes a `SecureContainer` containing a `DetachedSignature`
    /// and attaches it to the corresponding local voucher.
    ///
    /// # Arguments
    /// * `identity` - The identity of the recipient.
    /// * `container_bytes` - The received container data.
    /// * `password` - Optional password for symmetric encryption.
    ///
    /// # Returns
    /// A `Result` containing the updated instance ID on success.
    pub fn process_and_attach_signature(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<String, VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let payload =
            crate::services::secure_container_manager::open_secure_container(&container, identity, password)?;

        // HMSEC-SA06-09: Rebind the integrity id `i` to the received bytes
        // before acting on the payload. Placed AFTER decryption so AEAD
        // authentication errors keep precedence (established error contract);
        // for validly encrypted containers this is the gate that rejects
        // stolen `(i, signature)` pairs and mutated AEAD-exempt envelope
        // fields (`unprotected`, `salt`, `et`, `c`).
        crate::services::secure_container_manager::verify_container_integrity_binding(&container)?;

        if !matches!(container.c, PayloadType::DetachedSignature) {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let signature: DetachedSignature = serde_json::from_slice(&payload)?;

        let signature_obj_inner = match &signature {
            DetachedSignature::Signature(s) => s,
        };

        // We must find the voucher to obtain init_t_id for validation
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

        // HMC-SEC-06-04: Graceful error instead of an index panic if the
        // stored voucher has an empty transaction chain.
        let init_t_id = &target_instance_for_val
            .voucher
            .transactions
            .first()
            .ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                    "Voucher has no transactions".to_string(),
                ))
            })?
            .t_id;
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

        // (Optional, but recommended) Check if signature is already present
        if target_instance
            .voucher
            .signatures
            .iter()
            .any(|sig| sig.signature_id == signature_obj.signature_id)
        {
            // Silently ignore or return error
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

    /// Removes an additional signature (e.g. from guarantors or witnesses) from a voucher.
    ///
    /// This operation may only be performed by the voucher creator and only
    /// while the voucher is not yet in circulation (only one init transaction present).
    ///
    /// # Arguments
    /// * `identity` - The identity of the requesting user (must be the creator).
    /// * `local_instance_id` - The ID of the voucher in the local `voucher_store`.
    /// * `signature_id` - The ID of the signature to be removed.
    ///
    /// # Returns
    /// A `Result` returning `Ok(())` on success.
    ///
    /// # Errors
    /// * `VoucherNotFound` - The voucher was not found.
    /// * `SignatureRemovalRequiresIncomplete` - Removal only allowed in 'Incomplete' status.
    /// * `NotTheCreator` - The requesting identity is not the voucher creator.
    /// * `VoucherAlreadyInCirculation` - The voucher already has more than one transaction (is in circulation).
    /// * `CannotRemoveCreatorSignature` - An attempt was made to remove the creator's core signature.
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

        // 1. Status check: Only Incomplete allowed
        if !matches!(instance.status, VoucherStatus::Incomplete { .. }) {
            return Err(VoucherCoreError::SignatureRemovalRequiresIncomplete(
                instance.status.clone(),
            ));
        }

        // 2. History check: Only one init transaction allowed
        if instance.voucher.transactions.len() != 1 {
            return Err(VoucherCoreError::VoucherAlreadyInCirculation);
        }
        let first_transaction = &instance.voucher.transactions[0];
        if first_transaction.t_type != "init" {
            return Err(VoucherCoreError::VoucherAlreadyInCirculation);
        }

        // 3. Identity check: Only the creator may remove signatures
        let creator_id = instance
            .voucher
            .creator_profile
            .id
            .as_ref()
            .ok_or_else(|| VoucherCoreError::Generic("Creator profile has no ID".to_string()))?;
        if &identity.user_id != creator_id {
            return Err(VoucherCoreError::NotTheCreator);
        }

        // 4. Role check: Find signature and check if it is allowed to be removed
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

        // 5. Remove signature
        instance
            .voucher
            .signatures
            .retain(|sig| sig.signature_id != signature_id);

        // 6. Status re-evaluation: If required signatures are missing, set to Incomplete
        // Note: Full validation against standard requires access to the standard,
        // which is not available at this layer. We conservatively set to Incomplete
        // when signatures are removed. The AppService layer can revalidate as needed.
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

