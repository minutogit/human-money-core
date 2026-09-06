//! # src/models/profile.rs
//!
//! Defines the data structures for a complete user profile,
//! including identity, voucher holdings, and a history of transaction bundles.
//! These structures are responsible for managing a user's "wallet".

use crate::models::conflict::TransactionFingerprint;
use crate::models::voucher::Address; // Imports the Address structure
use crate::models::voucher::Voucher;
use crate::wallet::instance::VoucherInstance;
use ed25519_dalek::{SigningKey, VerifyingKey as EdPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

/// Represents the cryptographic identity of a user.
/// The private key is kept securely in memory and zeroized on drop.
#[derive(ZeroizeOnDrop, Clone)]
pub struct UserIdentity {
    /// The user's private Ed25519 key.
    /// **Important:** This key is not serialized and never leaves the profile.
    /// `ed25519_dalek::SigningKey` already implements `ZeroizeOnDrop` natively.
    pub signing_key: SigningKey,
    /// The public Ed25519 key, derived from the private key.
    #[zeroize(skip)]
    pub public_key: EdPublicKey,
    /// The public, shareable user ID, generated from the public key.
    #[zeroize(skip)]
    pub user_id: String,
}

impl Default for UserIdentity {
    fn default() -> Self {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let public_key = signing_key.verifying_key();
        Self {
            signing_key,
            public_key,
            user_id: String::new(),
        }
    }
}

/// An enum indicating the direction of a transaction from the profile holder's perspective.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[derive(Default)]
pub enum TransactionDirection {
    #[default]
    Sent,
    Received,
}


/// A lightweight summary of a `TransactionBundle` for display in a history.
/// Contains all metadata, but instead of the full vouchers, only their IDs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransactionBundleHeader {
    /// The unique ID of the associated bundle.
    pub bundle_id: String,
    /// The user ID of the sender.
    pub sender_id: String,
    /// The user ID of the recipient.
    pub recipient_id: String,
    /// A list of IDs of the vouchers transferred in this bundle.
    pub voucher_ids: Vec<String>,
    /// The timestamp of bundle creation in ISO 8601 format.
    pub timestamp: String,
    /// An optional note added by the sender.
    pub notes: Option<String>,
    /// The digital signature of the sender confirming the authenticity of the bundle.
    pub sender_signature: String,
    /// Indicates whether the bundle was sent or received.
    pub direction: TransactionDirection,
    /// Optional profile name of the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
}

/// Represents a complete, signed bundle for an exchange of vouchers.
/// This is the atomic unit exchanged between users.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransactionBundle {
    /// A unique ID for this bundle, generated from the hash of its content (excluding signature).
    pub bundle_id: String,
    /// The user ID of the sender.
    pub sender_id: String,
    /// The user ID of the recipient.
    pub recipient_id: String,
    /// A list of the full `Voucher` objects being transferred.
    pub vouchers: Vec<Voucher>,
    /// The timestamp of bundle creation in ISO 8601 format.
    pub timestamp: String,
    /// An optional note visible to the recipient.
    pub notes: Option<String>,
    /// The digital signature of the sender signing the `bundle_id`, thus making the
    /// entire bundle tamper-proof.
    pub sender_signature: String,

    /// The list of forwarded fingerprints supporting double-spend detection.
    #[serde(default)]
    pub forwarded_fingerprints: Vec<TransactionFingerprint>,

    /// The associated 'depth' values for the forwarded fingerprints.
    /// Key: ds_tag of the fingerprint.
    #[serde(default)]
    pub fingerprint_depths: HashMap<String, i8>,

    /// Optional profile name of the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
}

impl TransactionBundle {
    /// Creates a `TransactionBundleHeader` from a `TransactionBundle`.
    pub fn to_header(&self, direction: TransactionDirection) -> TransactionBundleHeader {
        TransactionBundleHeader {
            bundle_id: self.bundle_id.clone(),
            sender_id: self.sender_id.clone(),
            recipient_id: self.recipient_id.clone(),
            voucher_ids: self.vouchers.iter().map(|v| v.voucher_id.clone()).collect(),
            timestamp: self.timestamp.clone(),
            notes: self.notes.clone(),
            sender_signature: self.sender_signature.clone(),
            direction,
            sender_profile_name: self.sender_profile_name.clone(),
        }
    }
}

/// Represents the persistent storage for all vouchers of a user.
/// This structure is kept separate from `UserProfile` to keep metadata
/// lightweight and efficiently manage the voucher collection.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VoucherStore {
    /// The inventory of vouchers, indexed by their local instance ID (`local_voucher_instance_id`).
    pub vouchers: HashMap<String, VoucherInstance>,
}

/// Represents the persistent storage for the metadata of transaction bundles.
/// This structure is kept separate from `UserProfile` in its own encrypted file.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BundleMetadataStore {
    /// A history of all sent and received transaction bundles,
    /// indexed by `bundle_id`.
    pub history: HashMap<String, TransactionBundleHeader>,
}

/// A standardized public profile that can be reused in signatures and
/// in the creator field.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct PublicProfile {
    /// Protocol version string (e.g. "v1")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,

    /// The user ID (did:key) of the profile holder.
    /// Optional, as it is often redundant with the parent ID (e.g. signer_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,

    /// Gender of creator ISO 5218 (1 = male, 2 = female, 0 = not known, 9 = Not applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,

    /// Geographical coordinates (e.g. "latitude, longitude").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// A textual description of the services or goods offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_offer: Option<String>,

    /// A textual description of the needed services or goods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,

    /// URL to a profile picture (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
}

/// The main structure representing the entire state of a user wallet.
/// It contains identity, voucher inventory, and transaction history.
/// This structure is serialized and stored encrypted on disk.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(Default)]
pub struct UserProfile {
    /// The public user ID. Derived from `identity` and duplicated here for easy access.
    pub user_id: String,
    // Fields for profile details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_offer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
    /// The public key of the L2 server trusted by this wallet.
    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub l2_server_pubkey: Option<[u8; 32]>,
}

// Implement `Default` for UserProfile to create an empty instance that is then populated.
// The `identity` is added separately after creation.

impl UserProfile {
    /// Converts this `UserProfile` into a `PublicProfile`, including the `id`.
    pub fn to_public_profile(&self) -> PublicProfile {
        self.to_public_profile_with_id(true)
    }

    /// Converts this `UserProfile` into a `PublicProfile`, optionally including the `id`.
    pub fn to_public_profile_with_id(&self, include_id: bool) -> PublicProfile {
        PublicProfile {
            protocol_version: Some("v1".to_string()),
            id: if include_id { Some(self.user_id.clone()) } else { None },
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            organization: self.organization.clone(),
            community: self.community.clone(),
            address: self.address.clone(),
            gender: self.gender.clone(),
            email: self.email.clone(),
            phone: self.phone.clone(),
            coordinates: self.coordinates.clone(),
            url: self.url.clone(),
            service_offer: self.service_offer.clone(),
            needs: self.needs.clone(),
            picture_url: self.picture_url.clone(),
        }
    }
}

impl From<&UserProfile> for PublicProfile {
    fn from(profile: &UserProfile) -> Self {
        profile.to_public_profile()
    }
}
