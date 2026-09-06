//! # src/models/signature.rs
//!
//! Defines a generic wrapper structure for detached signatures,
//! needed for the signing workflow.

use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::{PublicProfile, UserIdentity};
use crate::models::voucher::VoucherSignature;
use crate::services::crypto::{get_hash_from_slices, get_pubkey_from_user_id, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use serde::{Deserialize, Serialize};

/// An enum encapsulating one of the possible detached signatures.
///
/// This is used as a payload for the `SecureContainer` when a signer
/// sends their signature back to the voucher creator. This wrapper allows
/// the `Wallet` logic to remain agnostic to the specific signature type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DetachedSignature {
    // NOTE: This represents a signature *in transit*.
    // We use `VoucherSignature` as a container for the data,
    // since the structure (e.g. `role`) is identical.
    Signature(VoucherSignature),
}

impl DetachedSignature {
    /// Returns a reference to the inner `VoucherSignature`.
    pub fn inner(&self) -> &VoucherSignature {
        match self {
            DetachedSignature::Signature(s) => s,
        }
    }

    /// Consumes the wrapper and returns the inner `VoucherSignature`.
    pub fn into_inner(self) -> VoucherSignature {
        match self {
            DetachedSignature::Signature(s) => s,
        }
    }

    /// Completes and signs a `DetachedSignature`.
    ///
    /// This function takes a partially populated `DetachedSignature` object,
    /// fills the cryptographic fields (`signature_id`, `signature`, `signature_time`),
    /// and returns the complete, signed object.
    ///
    /// # Arguments
    /// * `signer_identity` - The identity of the signer.
    /// * `details` - The optional `PublicProfile` of the signer.
    /// * `voucher_id` - The voucher ID to which the signature relates.
    /// * `init_t_id` - The transaction ID of the genesis (init) transaction.
    ///
    /// # Returns
    /// A `Result` containing the completed `DetachedSignature`.
    pub fn complete_and_sign(
        mut self,
        signer_identity: &UserIdentity,
        details: Option<PublicProfile>,
        voucher_id: &str,
        init_t_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        let signer_id = match &mut self {
            DetachedSignature::Signature(sig) => {
                sig.signer_id = signer_identity.user_id.clone();
                sig.voucher_id = voucher_id.to_string();

                // If details parameter is Some, use it to complete the signature by merging
                // with existing details, giving priority to values in the details parameter.
                // If details parameter is None, explicitly clear the details (e.g., for include_details=false).
                match &details {
                    Some(profile_details) => {
                        // Details are provided - merge with existing details or use entirely
                        match &sig.details {
                            Some(sig_details) => {
                                // Both signature and profile have details - merge giving priority to profile where it has values
                                let mut merged_details = sig_details.clone();

                                if profile_details.first_name.is_some() {
                                    merged_details.first_name = profile_details.first_name.clone();
                                }
                                if profile_details.last_name.is_some() {
                                    merged_details.last_name = profile_details.last_name.clone();
                                }
                                if profile_details.gender.is_some() {
                                    merged_details.gender = profile_details.gender.clone();
                                }
                                if profile_details.organization.is_some() {
                                    merged_details.organization = profile_details.organization.clone();
                                }
                                if profile_details.community.is_some() {
                                    merged_details.community = profile_details.community.clone();
                                }
                                if profile_details.email.is_some() {
                                    merged_details.email = profile_details.email.clone();
                                }
                                if profile_details.phone.is_some() {
                                    merged_details.phone = profile_details.phone.clone();
                                }
                                if profile_details.url.is_some() {
                                    merged_details.url = profile_details.url.clone();
                                }
                                if profile_details.coordinates.is_some() {
                                    merged_details.coordinates = profile_details.coordinates.clone();
                                }
                                if profile_details.address.is_some() {
                                    merged_details.address = profile_details.address.clone();
                                }

                                sig.details = Some(merged_details);
                            }
                            None => {
                                // Signature has no details, use profile details entirely
                                sig.details = Some(profile_details.clone());
                            }
                        }
                    }
                    None => {
                        // No details should be included - explicitly set to None
                        sig.details = None;
                    }
                }

                sig.signer_id.clone()
            }
        };

        if signer_identity.user_id != signer_id {
            return Err(VoucherCoreError::MismatchedSignatureData(
                "Signer ID in signature does not match signer identity".to_string(),
            ));
        }

        // Reset cryptographic fields and determine timestamp uniformly
        let signature_time = get_current_timestamp();
        let signature_json_for_id = match &self {
            DetachedSignature::Signature(sig) => {
                let mut sig_clone = sig.clone();
                sig_clone.signature_id = "".to_string();
                sig_clone.signature = "".to_string();
                sig_clone.signature_time = signature_time.clone();

                to_canonical_json(&sig_clone)?.into_bytes()
            }
        };

        let signature_id =
            get_hash_from_slices(&[signature_json_for_id.as_slice(), init_t_id.as_bytes()]);
        let digital_signature = sign_ed25519(&signer_identity.signing_key, signature_id.as_bytes());
        let signature_str = bs58::encode(digital_signature.to_bytes()).into_string();

        match &mut self {
            DetachedSignature::Signature(sig) => {
                sig.signature_id = signature_id;
                sig.signature = signature_str;
                sig.signature_time = signature_time;
            }
        }

        Ok(self)
    }

    /// Validates the cryptographic integrity of a `DetachedSignature`.
    ///
    /// Checks whether `signature_id` matches metadata and whether
    /// the digital `signature` is valid.
    ///
    /// # Arguments
    /// * `init_t_id` - The transaction ID of the genesis (init) transaction.
    ///
    /// # Returns
    /// An empty `Result` if validation succeeds.
    pub fn validate(&self, init_t_id: &str) -> Result<(), VoucherCoreError> {
        // --- BYPASS CHECK START ---
        #[cfg(feature = "test-utils")]
        {
            if crate::is_signature_bypass_active() {
                return Ok(());
            }
        }
        // --- BYPASS CHECK END ---

        let (mut sig_obj_to_verify, signer_id, expected_sig_id, signature_b58) = match self {
            DetachedSignature::Signature(sig) => (
                serde_json::to_value(sig)?,
                sig.signer_id.clone(),
                sig.signature_id.clone(),
                sig.signature.clone(),
            ),
        };

        // Remove cryptographic fields to recalculate metadata hash
        let obj = sig_obj_to_verify.as_object_mut().unwrap();
        obj.insert("signature_id".to_string(), "".into());
        obj.insert("signature".to_string(), "".into());

        let calculated_sig_id = get_hash_from_slices(&[
            to_canonical_json(&sig_obj_to_verify)?.as_bytes(),
            init_t_id.as_bytes(),
        ]);

        if calculated_sig_id != expected_sig_id {
            return Err(VoucherCoreError::Validation(
                ValidationError::InvalidSignatureId(expected_sig_id),
            ));
        }

        let public_key = get_pubkey_from_user_id(&signer_id)?;
        let signature_bytes: Vec<u8> = bs58::decode(signature_b58).into_vec()?;

        let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            VoucherCoreError::Validation(ValidationError::SignatureDecodeError(
                "Invalid signature length: must be 64 bytes".to_string(),
            ))
        })?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_array);

        if !verify_ed25519(&public_key, expected_sig_id.as_bytes(), &signature) {
            return Err(VoucherCoreError::Validation(
                ValidationError::InvalidSignature {
                    signer_id: signer_id.to_string(),
                },
            ));
        }

        Ok(())
    }
}
