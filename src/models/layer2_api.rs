use serde::{Deserialize, Serialize};

pub use humoco_proto::types::{
    AttestationVote,
    L2Verdict as CanonicalL2Verdict,
    NodePubKey,
    QuorumProof,
    ShardId,
};
pub use humoco_proto::crypto::{
    DOMAIN_L2_WRITE,
    DOMAIN_L2_STATUS_QUERY,
    DOMAIN_L2_EQUIVOCATION,
    compute_lock_attestation_digest,
    compute_status_attestation_digest,
};

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

    /// Explicit UTC millisecond timestamp when this lock request was prepared for L2 ingress.
    ///
    /// # Protocol Specifications:
    /// - **5-minute Time Bucket Allocation:** Layer-2 nodes assign incoming locks to discrete
    ///   5-minute buckets via `floor(created_at_ms / 300_000)` for BFT shard synchronization
    ///   and immutable Merkle root sealing.
    /// - **30-second Clock-Drift Window:** Nodes reject any lock request whose `created_at_ms`
    ///   deviates from network time by more than 30 seconds (`|created_at_ms - net_time_ms| <= 30_000`).
    /// - **Gateway Retry & Multi-Homing Invariant:** Clients MUST resend the EXACT identical
    ///   byte payload (`created_at_ms`, signature, etc.) upon network timeouts or when failing
    ///   over across multiple gateway nodes. Clients must NEVER re-generate timestamps or re-sign
    ///   on retry. This ensures:
    ///   1. Deterministic bucket placement across different gateway nodes (avoids split-bucket divergence).
    ///   2. Immediate hot-path idempotency via Rule 3 (`Verified` verdict returned on seeing the same `t_id`).
    ///   3. Adherence to the 30-second drift window during rapid retries (500–1500 ms timeouts).
    #[serde(default)]
    pub created_at_ms: u64,

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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
    /// Explicit UTC millisecond timestamp when the lock entry was created on Layer 2.
    /// Determines the 5-minute time bucket (`floor(created_at_ms / 300_000)`) in the L2 registry
    /// and is cryptographically bound into the canonical `HMC_TX_AUTH_V3` payload digest.
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>,
    // --- SECURITY (HMSEC-SA04-08): privacy-guard binding field ---
    /// The Base64-encoded AEAD privacy guard of the locked transaction, if
    /// any. Its canonical commitment is bound into the V3 payload digest that
    /// `layer2_signature` authenticates (see [`crate::services::l2_gateway`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,
}

impl From<&L2LockRequest> for L2LockEntry {
    fn from(req: &L2LockRequest) -> Self {
        Self {
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            trap_r: req.trap_r.clone(),
            trap_s: req.trap_s.clone(),
            encrypted_timestamp: req.encrypted_timestamp,
            created_at_ms: req.created_at_ms,
            deletable_at: req.deletable_at.clone(),
            privacy_guard: req.privacy_guard.clone(),
        }
    }
}

impl From<L2LockRequest> for L2LockEntry {
    fn from(req: L2LockRequest) -> Self {
        Self {
            layer2_voucher_id: req.layer2_voucher_id,
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            trap_r: req.trap_r,
            trap_s: req.trap_s,
            encrypted_timestamp: req.encrypted_timestamp,
            created_at_ms: req.created_at_ms,
            deletable_at: req.deletable_at,
            privacy_guard: req.privacy_guard,
        }
    }
}

fn default_read_quorum() -> u8 {
    1
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
    #[serde(default = "default_read_quorum")]
    pub read_quorum: u8,
}

/// Request: Batch upload of multiple transactions for synchronization.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2BatchLockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub locks: Vec<L2LockRequest>,
}

/// Request: Atomic chain lock for offline steps bundled with genesis.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ChainLockRequest {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,
    pub chain: Vec<L2LockRequest>,
}

/// Response: The verdict of the L2 server regarding the state of a tag or the chain.
/// Signed attestation from a consensus or ingress node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationDto {
    pub lock_id: String,
    pub parent_lock: String,
    pub node_id: u16,
    /// Full 32-byte Ed25519 NodePubKey of the signer (hex). Empty for legacy payloads.
    #[serde(default)]
    pub node_pubkey: String,
    pub timestamp: u64,
    pub signature: String,
    #[serde(default)]
    pub shard_id: u16,
}

impl AttestationDto {
    /// Decodes the full 32-byte signer NodePubKey, if present and well-formed.
    pub fn node_pubkey_bytes(&self) -> Option<[u8; 32]> {
        if self.node_pubkey.is_empty() {
            return None;
        }
        let raw = hex::decode(&self.node_pubkey).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Some(out)
    }
}

/// Assembled quorum certificate with partial signatures from shard nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCertificateDto {
    pub lock_id: String,
    pub shard_id: u16,
    /// 0 = PROVISIONAL, 1 = FINAL
    pub status: u8,
    pub active_nodes_count: usize,
    pub signer_count: usize,
    pub signatures: Vec<AttestationDto>,
}

impl From<QuorumProof> for QuorumCertificateDto {
    fn from(proof: QuorumProof) -> Self {
        let signer_count = proof.votes.len();
        let signatures = proof
            .votes
            .into_iter()
            .map(|v| {
                let node_id = u16::from_be_bytes([v.signer_pubkey[0], v.signer_pubkey[1]]);
                AttestationDto {
                    lock_id: String::new(),
                    parent_lock: String::new(),
                    node_id,
                    node_pubkey: hex::encode(v.signer_pubkey),
                    timestamp: 0,
                    signature: hex::encode(v.signature),
                    shard_id: proof.shard_id,
                }
            })
            .collect();

        Self {
            lock_id: String::new(),
            shard_id: proof.shard_id,
            status: if signer_count >= 14 { 1 } else { 0 },
            active_nodes_count: 20.max(signer_count),
            signer_count,
            signatures,
        }
    }
}

impl TryFrom<&QuorumCertificateDto> for QuorumProof {
    type Error = &'static str;

    fn try_from(cert: &QuorumCertificateDto) -> Result<Self, Self::Error> {
        let mut votes = Vec::with_capacity(cert.signatures.len());
        for att in &cert.signatures {
            let signer_pubkey = if !att.node_pubkey.is_empty() {
                let bytes = hex::decode(&att.node_pubkey).map_err(|_| "invalid hex in node_pubkey")?;
                bytes.try_into().map_err(|_| "node_pubkey must be 32 bytes")?
            } else {
                return Err("missing node_pubkey in attestation");
            };

            let sig_bytes = if let Ok(raw) = hex::decode(&att.signature) {
                raw.try_into().map_err(|_| "signature must be 64 bytes")?
            } else if let Ok(raw) = bs58::decode(&att.signature).into_vec() {
                raw.try_into().map_err(|_| "signature must be 64 bytes")?
            } else {
                return Err("invalid signature format in attestation");
            };

            votes.push(AttestationVote {
                signer_pubkey,
                signature: sig_bytes,
            });
        }

        Ok(QuorumProof {
            shard_id: cert.shard_id,
            votes,
        })
    }
}

impl TryFrom<QuorumCertificateDto> for QuorumProof {
    type Error = &'static str;

    fn try_from(cert: QuorumCertificateDto) -> Result<Self, Self::Error> {
        QuorumProof::try_from(&cert)
    }
}

/// Response: The verdict of the L2 server regarding the state of a tag or the chain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
// The Verified variant legitimately carries a full lock entry; boxing it
// would only add indirection to a deserialized-once wire object.
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type")]
pub enum L2Verdict {
    /// Lock was successfully registered with a valid quorum proof.
    Confirmed { proof: QuorumProof },
    /// The tag is occupied. Contains the complete proof (LockEntry).
    Verified { lock_entry: L2LockEntry },
    /// Conflict detected (e.g. 409 double-spend attempt). Contains the existing lock entry.
    Conflict { existing_lock: L2LockEntry },
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

impl From<CanonicalL2Verdict> for L2Verdict {
    fn from(v: CanonicalL2Verdict) -> Self {
        match v {
            CanonicalL2Verdict::Confirmed { proof } => L2Verdict::Confirmed { proof },
            CanonicalL2Verdict::Conflict { existing_tag } => L2Verdict::Conflict {
                existing_lock: L2LockEntry {
                    layer2_voucher_id: String::new(),
                    t_id: existing_tag,
                    sender_ephemeral_pub: [0u8; 32],
                    receiver_ephemeral_pub_hash: None,
                    change_ephemeral_pub_hash: None,
                    layer2_signature: [0u8; 64],
                    trap_r: None,
                    trap_s: None,
                    encrypted_timestamp: 0,
                    created_at_ms: 0,
                    deletable_at: None,
                    privacy_guard: None,
                },
            },
            CanonicalL2Verdict::Rejected { reason } => L2Verdict::Rejected { reason },
        }
    }
}

/// Envelope for all L2 server responses.
/// Guarantees the authenticity of the server via an Ed25519 signature.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ResponseEnvelope {
    pub verdict: L2Verdict,
    #[serde(with = "crate::models::layer2_api::base58_64")]
    pub server_signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_certificate: Option<QuorumCertificateDto>,
}

impl L2ResponseEnvelope {
    pub fn new(verdict: L2Verdict, server_signature: [u8; 64]) -> Self {
        Self {
            verdict,
            server_signature,
            quorum_certificate: None,
        }
    }

    /// Returns canonical `QuorumProof` if present in the verdict or certificate.
    pub fn quorum_proof(&self) -> Option<QuorumProof> {
        if let L2Verdict::Confirmed { ref proof } = self.verdict {
            return Some(proof.clone());
        }
        if let Some(ref cert) = self.quorum_certificate {
            if let Ok(proof) = QuorumProof::try_from(cert) {
                return Some(proof);
            }
        }
        None
    }
}

/// The outcome of processing an L2 response in the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L2ProcessingOutcome {
    Confirmed,
    Quarantined { reason: String },
    SyncRequired { sync_point: String },
}

/// Outcome of reconciling an individual voucher output against Layer-2 status.
///
/// # Two-Tier Ingress Safety Architecture:
/// - **Tier 1 (Macro-Check - WalletSeal / State Anchor):**
///   On startup or sync, the wallet checks its State Anchor (`build_anchor_status_query`).
///   If `AnchorSyncVerdict::Synchronized`, the entire wallet (all vouchers bound in
///   `voucher_merkle_root`) is guaranteed to be consistent with Layer-2 in O(1).
///   No per-voucher checks are needed.
/// - **Tier 2 (Micro-Check - Voucher-Level Reconciliation):**
///   If Tier 1 detects a rollback (`AnchorSyncVerdict::RollbackDetected`, e.g. after
///   restoring a backup), or when performing a targeted pre-payment check at checkout,
///   individual voucher outputs are queried via `POST /v1/status`.
///   - `UnspentSafe` (HTTP 404): No successor lock exists. The voucher output is unspent and safe to use.
///   - `AlreadySpent` (HTTP 200): A child lock exists. The voucher was already spent.
///     The wallet marks it as `VoucherStatus::Archived` and updates balances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoucherReconciliationResult {
    /// No successor lock exists on L2 (HTTP 404). Output is unspent and safe to spend.
    UnspentSafe,
    /// A successor lock exists on L2 (HTTP 200). The voucher was already spent remotely.
    /// The wallet has updated its status to `VoucherStatus::Archived` and adjusted balances.
    AlreadySpent {
        successor_t_id: String,
    },
}
