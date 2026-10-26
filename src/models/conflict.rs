//! # src/models/conflict.rs
//!
//! Defines the data structures for detecting, proving, and
//! resolving double-spending conflicts.

use crate::models::voucher::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

//==============================================================================
// PART 1: CONFLICT DETECTION STRUCTURES (from fingerprint.rs)
//==============================================================================

/// Represents an individual, self-authenticating fingerprint of a transaction.
/// This structure contains all necessary cryptographic information to prove a double spend,
/// verify input authority via V4 signatures, and manage expired fingerprints.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct TransactionFingerprint {
    /// The double-spend tag (DS tag).
    /// This is the primary key used to group potential conflicts.
    /// It MUST be deterministic and constant for the same input.
    pub ds_tag: String,

    /// The unique ID of the transaction (`t_id`). A diverging value here with an
    /// identical `ds_tag` signals a double spend.
    pub t_id: String,

    /// The encrypted timestamp of the transaction in nanoseconds (u128).
    /// `encrypted_nanos = original_nanos ^ truncate_16_bytes(hash(prev_hash || t_id))`
    pub encrypted_timestamp: u128,

    /// The technical signature (Layer 2) of the sender. Serves as cryptographic proof
    /// to unambiguously attribute the fraud attempt to the perpetrator (holder of the ephemeral key).
    pub layer2_signature: String,

    /// The revealed ephemeral public key of the sender (32 bytes, Base58).
    ///
    /// Together with the signed fingerprint fields, this key allows any gossip
    /// recipient to verify `layer2_signature` against `HMC_TX_AUTH_V4`.
    /// Permanent owner attribution additionally requires a victim disclosure.
    #[serde(default)]
    pub sender_ephemeral_pub: String,

    /// The date after which the fingerprint can be safely deleted from storage
    /// (corresponds to `deletable_at` of the 'init' transaction).
    pub deletable_at: String,

    /// V4 SST commitment shard $R_i$ of the shared Schnorr
    /// signature (32 bytes, Base58). Genesis fingerprints carry the canonical
    /// `"none"` placeholder. Two valid colliding shards reconstruct a candidate
    /// signature identity; a checked victim receipt proves ownership of E.
    #[serde(default)]
    pub trap_r: String,

    /// V4 SST response shard $s_i$ of the shared Schnorr
    /// signature (32 bytes, Base58). Genesis fingerprints carry the canonical
    /// `"none"` placeholder.
    #[serde(default)]
    pub trap_s: String,

    /// The voucher container ID authenticated by HMC_TX_AUTH_V4
    /// that the embedded `layer2_signature` authorizes. Spends carry the hex
    /// `layer2_voucher_id`, genesis fingerprints the canonical `"none"`
    /// placeholder — mirroring exactly what the spender signed. Binding this
    /// into the payload digest prevents cross-voucher lock transplantation.
    #[serde(default)]
    pub layer2_voucher_id: String,

    /// # SECURITY (HMSEC-SA04-08): the canonical commitment
    /// ([`crate::services::l2_gateway::privacy_guard_commitment`]) of the
    /// transaction's `privacy_guard`. Diverging commitments under one input
    /// expose guard equivocation as distinguishable evidence instead of
    /// collapsing into byte-identical fingerprints.
    #[serde(default)]
    pub privacy_guard_hash: String,

    /// Layer-2 lock creation / transaction timestamp in milliseconds.
    /// Bound into the canonical `HMC_TX_AUTH_V4` payload digest.
    #[serde(default)]
    pub created_at_ms: u64,
}

/// Serves as a storage container for all known transaction fingerprints (local voucher history and foreign gossip).
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct KnownFingerprints {
    /// **History (persistent):** A complete history of all fingerprints of
    /// transactions that ever took place on vouchers held by the user.
    /// This is the comprehensive database for detecting fraud attempts in the network.
    #[serde(default)]
    pub local_history: HashMap<String, Vec<TransactionFingerprint>>,

    /// **Foreign data (ephemeral):** A collection of fingerprints received from other
    /// participants in the network. Serves as a "blocklist" and
    /// for detecting double spends in which one was not directly involved.
    #[serde(default)]
    pub foreign_fingerprints: HashMap<String, Vec<TransactionFingerprint>>,
}

/// Serves as critical, persistent storage for all fingerprints of transactions
/// where the wallet owner was the **sender**. This small, separate file is
/// essential for reliably preventing accidental double-spending.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct OwnFingerprints {
    /// **Active (ephemeral):** Fingerprints of spendable transactions. Used for
    /// fast in-memory checks before creating a new transaction.
    #[serde(default)]
    pub active_fingerprints: HashMap<String, Vec<TransactionFingerprint>>,
    /// **History (persistent):** A complete and immutable history
    /// of all fingerprints of transactions where the user was the sender.
    /// This is the critical component for backups and conflict verification.
    #[serde(default)]
    pub history: HashMap<String, Vec<TransactionFingerprint>>,
}

//==============================================================================
// PART 2: ACTIVE GOSSIP STATE LAYER (30/70 KISS-Gossip)
//==============================================================================

/// Represents an entry in the DirectQueue.
/// Directly forwarded transaction tips from incoming vouchers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DirectEntry {
    /// The fingerprint of the latest transaction tip.
    pub fingerprint: TransactionFingerprint,
    /// Hashes of recipients that have already received this tip.
    #[serde(default)]
    pub sent_to: Vec<[u8; 4]>,
}

/// Represents an entry in the QuarantineDirectQueue.
/// Locally discovered double-spend pairs that need priority propagation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct QuarantineEntry {
    /// The colliding fingerprint pair.
    pub pair: [TransactionFingerprint; 2],
    /// Hashes of recipients that have already received this quarantine pair.
    #[serde(default)]
    pub sent_to: Vec<[u8; 4]>,
}

/// Compact active gossip state persisted atomically in the wallet storage container.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct ActiveGossipState {
    /// Direct queue for 30% direct tips (max 3 distinct recipients each).
    #[serde(default)]
    pub direct_queue: VecDeque<DirectEntry>,
    /// Fresh gossip pool for 70% lottery foreign fingerprints.
    #[serde(default)]
    pub fresh_gossip_pool: VecDeque<TransactionFingerprint>,
    /// Locally discovered fraud pairs (guaranteed 3x delivery).
    #[serde(default)]
    pub quarantine_direct_queue: Vec<QuarantineEntry>,
    /// Relayed fraud pairs from foreign peers (70% one-shot lottery).
    #[serde(default)]
    pub quarantine_relay_pool: VecDeque<[TransactionFingerprint; 2]>,
}

//==============================================================================
// PART 3: STRUCTURES FOR PROVING AND RESOLVING CONFLICTS
//==============================================================================

/// Private receipt evidence disclosed only after two authenticated spends collide.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VictimWitnessDisclosure {
    /// Index of the honestly validated handover in ProofOfDoubleSpend.fingerprints.
    pub fingerprint_index: usize,
    pub sender_permanent_did: String,
    pub witness: crate::models::voucher::TrapWitness,
}

/// Portable signed conflict evidence, optionally carrying a victim ownership disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpend {
    /// The unique, deterministic ID of this conflict.
    /// It is formed from the hash of the core conflict data:
    /// `proof_id = hash(offender_id + fork_point_prev_hash)`.
    /// Thus, anyone discovering the same conflict generates the same ID.
    pub proof_id: String,

    /// The ID of the sender (offender) who performed the double spend.
    ///
    /// # Attribution hierarchy (V4)
    /// A permanent DID requires a checked victim receipt binding E to that
    /// identity, plus two conflicting E-signed fingerprints. Otherwise the
    /// offender is the authenticated ephemeral input key or remains anonymous.
    pub offender_id: String,

    /// Advisory signature identity candidate. It becomes an authenticated
    /// owner identity only when a victim ownership disclosure is verified.
    #[serde(default)]
    pub suspected_identity: Option<String>,

    /// The `prev_hash` from which the fraudulent transactions fork.
    pub fork_point_prev_hash: String,

    /// The complete, conflicting transactions that prove the fraud.
    pub conflicting_transactions: Vec<Transaction>,

    /// Original authenticated evidence, including guard hashes and voucher binding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprints: Vec<TransactionFingerprint>,

    /// Input ownership evidence; absent from normal L1 chains and gossip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub victim_witnesses: Vec<VictimWitnessDisclosure>,

    /// The date after which this proof can be deleted.
    pub deletable_at: String,

    // Metadata for the specific report of this proof
    pub reporter_id: String,
    pub report_timestamp: String,

    /// The signature of the creator (reporter) over the `proof_id` to confirm
    /// the authenticity of this report.
    pub reporter_signature: String,

    /// The name of the affected voucher (optional, for better UI display).
    #[serde(default)]
    pub affected_voucher_name: Option<String>,

    /// The standard UUID of the affected voucher (optional).
    #[serde(default)]
    pub voucher_standard_uuid: Option<String>,

    /// A list of endorsements confirming that the conflict
    /// was settled with the victims. Can be `None` if unresolved.
    pub resolutions: Option<Vec<ResolutionEndorsement>>,

    /// The optional signed verdict of a Layer 2 service.
    /// If `Some`, this verdict overrides the local "maximum caution" rule.
    #[serde(default)]
    pub layer2_verdict: Option<Layer2Verdict>,
    /// Indicates whether this is a conflict involving test vouchers.
    #[serde(default)]
    pub non_redeemable_test_voucher: bool,
}

/// The role of the local wallet with respect to a conflict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ConflictRole {
    /// One of the colliding paths affects a voucher that was active locally.
    Victim,
    /// The collision was detected passively (e.g. via gossip).
    #[default]
    Witness,
}

/// The trustworthiness status of a partner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustStatus {
    /// No negative entries present.
    Clean,
    /// Unresolved proof of fraud exists. Display warning.
    KnownOffender(String),
    /// Incident is considered officially or locally resolved.
    Resolved {
        proof_id: String,
        is_local: bool,
        note: Option<String>,
    },
}

/// Local wrapper for a double-spend proof that stores private user decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStoreEntry {
    /// The cryptographic core proof.
    pub proof: ProofOfDoubleSpend,
    /// Did the user manually click "trust"?
    pub local_override: bool,
    /// Optional user note for manual resolution.
    #[serde(default)]
    pub local_note: Option<String>,
    /// Was the user a victim or only a witness?
    pub conflict_role: ConflictRole,
}

/// Endorsement by a victim that a conflict identified by a `proof_id`
/// has been settled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionEndorsement {
    /// The unique ID of this endorsement.
    /// Generated by hashing its own metadata (everything except id/signature),
    /// including the `proof_id`, to form a cryptographic chain.
    pub endorsement_id: String,

    /// The ID of the proof to which this resolution relates. Establishes the
    /// cryptographic link to the conflict.
    pub proof_id: String,

    /// The ID of the victim confirming the resolution. Must match one of the
    /// `recipient_id`s from the `conflicting_transactions`.
    pub victim_id: String,

    /// Timestamp of the endorsement.
    pub resolution_timestamp: String,

    /// Optional note, e.g. "Damage was fully reimbursed".
    pub notes: Option<String>,

    /// The signature of the victim over the `endorsement_id`. Confirms that
    /// the victim agrees to the settlement of the conflict identified by `proof_id`.
    pub victim_signature: String,
}

//==============================================================================
// PART 4: STORAGE CONTAINER FOR CONFLICT PROOFS
//==============================================================================

/// Serves as a storage container for all cryptographically proven double-spend conflicts.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ProofStore {
    /// A collection of all `ProofStoreEntry` objects.
    /// The key is the deterministic `proof_id` of the respective conflict.
    #[serde(default)]
    pub proofs: HashMap<String, ProofStoreEntry>,
}

/// Represents the tamper-proof verdict of a Layer 2 server regarding a conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer2Verdict {
    /// The ID of the server or committee that reached the verdict.
    pub server_id: String,
    /// The timestamp of the verdict.
    pub verdict_timestamp: String,
    /// The `t_id` of the transaction classified as "valid" (because first seen) by the server.
    pub valid_transaction_id: String,
    /// The signature of the server over the hash of this verdict object to make it tamper-proof.
    pub server_signature: String,
}

