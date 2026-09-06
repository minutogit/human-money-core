use serde::{Deserialize, Serialize};

pub mod base58_32 {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bs58::encode(data).into_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
        vec.try_into()
            .map_err(|_| de::Error::custom("Length mismatch, expected 32 bytes"))
    }
}

pub mod base58_32_vec {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for e in data {
            seq.serialize_element(&bs58::encode(e).into_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s_vec = Vec::<String>::deserialize(deserializer)?;
        let mut res = Vec::with_capacity(s_vec.len());
        for s in s_vec {
            let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
            let arr: [u8; 32] = vec
                .try_into()
                .map_err(|_| de::Error::custom("Length mismatch, expected 32 bytes"))?;
            res.push(arr);
        }
        Ok(res)
    }
}

pub mod base58_32_opt {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(d) => serializer.serialize_str(&bs58::encode(d).into_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => {
                let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
                let arr: [u8; 32] = vec
                    .try_into()
                    .map_err(|_| de::Error::custom("Length mismatch, expected 32 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

pub mod base58_u128 {
    //! Base58 string codec for 128-bit values (e.g. encrypted timestamps).
    //!
    //! JSON wire format is a Base58 string because plain JSON numbers lose
    //! precision beyond 53 bits and some serde_json configurations reject
    //! native 128-bit integers entirely.
    use serde::{Deserialize, Deserializer, Serializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bs58::encode(data.to_le_bytes()).into_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
        let arr: [u8; 16] = vec
            .try_into()
            .map_err(|_| de::Error::custom("Length mismatch, expected 16 bytes"))?;
        Ok(u128::from_le_bytes(arr))
    }
}

pub mod base58_64 {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bs58::encode(data).into_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
        vec.try_into()
            .map_err(|_| de::Error::custom("Length mismatch, expected 64 bytes"))
    }
}

pub mod base58_64_opt {
    use serde::{Deserialize, Deserializer, Serializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(data: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(d) => serializer.serialize_str(&bs58::encode(d).into_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => {
                let vec = bs58::decode(s).into_vec().map_err(de::Error::custom)?;
                let arr: [u8; 64] = vec
                    .try_into()
                    .map_err(|_| de::Error::custom("Length mismatch, expected 64 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Preparation for future anti-spam / Sybil access control.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2AuthPayload {
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub ephemeral_pubkey: [u8; 32], // The temporary sender key
    #[serde(with = "crate::models::layer2_api::base58_64_opt")]
    pub auth_signature: Option<[u8; 64]>, // Placeholder for future challenge signature
}

/// Request: Anchor a voucher (genesis) or a transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2LockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String, // Hex string (64 chars), mandatory field
    pub ds_tag: Option<String>,    // Hex string (64 chars), None for 'init'

    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub transaction_hash: [u8; 32], // The hash of the new transaction (t_id)
    pub is_genesis: bool,
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub sender_ephemeral_pub: [u8; 32],

    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub receiver_ephemeral_pub_hash: Option<[u8; 32]>,

    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub change_ephemeral_pub_hash: Option<[u8; 32]>,

    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub layer2_signature: [u8; 64],

    // --- V3 Protocol (HMC_TX_AUTH_V3 / SST): trap binding fields ---
    /// The commitment shard $R_i$ of the shared-signature trap (Base58).
    /// `Some("none")` for genesis locks; `Some(<R_i>)` for spend locks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_r: Option<String>,

    /// The response shard $s_i$ of the shared-signature trap (Base58).
    /// `Some("none")` for genesis locks; `Some(<s_i>)` for spend locks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_s: Option<String>,

    /// The encrypted timestamp of the transaction in nanoseconds
    /// (`encrypted_nanos = original_nanos ^ hash(prev_hash + t_id)`).
    /// Bound into the payload digest to make the lock replay/malleability-proof.
    #[serde(with = "crate::models::layer2_api::base58_u128", default)]
    pub encrypted_timestamp: u128,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>, // Only required when is_genesis = true

    // --- SECURITY (HMSEC-SA04-08): privacy-guard binding field ---
    /// The Base64-encoded AEAD privacy guard (`Transaction.privacy_guard`) of
    /// the locked transaction, if any. Its canonical commitment
    /// ([`crate::services::l2_gateway::privacy_guard_commitment`]) is bound
    /// into the V3 payload digest, so the server can verify lock signatures
    /// for guarded spends and guard equivocation becomes attributable.
    /// `None` commits the empty string (genesis / public-mode spends).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,
}

/// Data structure for a single lock entry on Layer 2.
/// Serves as cryptographic proof for the state of a tag.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2LockEntry {
    pub layer2_voucher_id: String,
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub t_id: [u8; 32],
    #[serde(with = "crate::models::layer2_api::base58_32")]
    pub sender_ephemeral_pub: [u8; 32],
    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub receiver_ephemeral_pub_hash: Option<[u8; 32]>,
    #[serde(with = "crate::models::layer2_api::base58_32_opt", default)]
    pub change_ephemeral_pub_hash: Option<[u8; 32]>,
    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub layer2_signature: [u8; 64],
    // --- V3 Protocol (HMC_TX_AUTH_V3 / SST): trap binding fields ---
    /// The commitment shard $R_i$ of the shared-signature trap (`None`/legacy for genesis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_r: Option<String>,
    /// The response shard $s_i$ of the shared-signature trap (Base58).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_s: Option<String>,
    /// The encrypted timestamp of the transaction in nanoseconds.
    #[serde(with = "crate::models::layer2_api::base58_u128", default)]
    pub encrypted_timestamp: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>,
    // --- SECURITY (HMSEC-SA04-08): privacy-guard binding field ---
    /// The Base64-encoded AEAD privacy guard of the locked transaction, if
    /// any. Its canonical commitment is bound into the V3 payload digest that
    /// `layer2_signature` authenticates (see [`crate::services::l2_gateway`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,
}

/// Request: Query the state of a voucher and reconcile transaction history.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2StatusQuery {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    /// The full Base58 string of the tag to check (challenge).
    pub challenge_ds_tag: String,
    /// Exponentially thinned list of ancestor prefixes (10 characters Base58) for LCA search.
    pub locator_prefixes: Vec<String>,
}

/// Request: Batch upload of multiple transactions for synchronization.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2BatchLockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub locks: Vec<L2LockRequest>,
}

/// Response: The verdict of the L2 server regarding the state of a tag or the chain.
#[derive(Serialize, Deserialize, Debug, Clone)]
// The Verified variant legitimately carries a full lock entry; boxing it
// would only add indirection to a deserialized-once wire object.
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type")]
pub enum L2Verdict {
    /// The tag is occupied. Contains the complete proof (LockEntry).
    Verified { lock_entry: L2LockEntry },
    /// The server does not yet know this tag, but found a common ancestor.
    MissingLocks {
        /// The 10-character prefix of the last common transaction.
        sync_point: String,
    },
    /// The voucher (Voucher ID) is completely unknown to the Layer 2 system.
    UnknownVoucher,
    /// Deprecated/Fallback: General confirmation (should be replaced by Verified).
    #[serde(rename = "Ok")]
    Ok {
        #[serde(with = "crate::models::layer2_api::base58_64")]
        signature: [u8; 64],
    },
    /// The request was rejected by the server (e.g. invalid signature).
    Rejected { reason: String },
}

/// Envelope for all L2 server responses.
/// Guarantees the authenticity of the server via an Ed25519 signature.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ResponseEnvelope {
    pub verdict: L2Verdict,
    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub server_signature: [u8; 64],
}
