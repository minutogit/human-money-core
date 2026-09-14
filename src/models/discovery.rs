//! # `src/models/discovery.rs`
//!
//! Data structures for peer discovery and bootstrap configuration.
//!
//! These models are used to distribute and configure network entry points
//! without network calls in the core library itself. They are pure data
//! containers with deterministic `snake_case` serde serialization so that
//! hashes and signatures remain cryptographically stable.

use serde::{Deserialize, Serialize};

/// Entry describing a single bootstrap node from the seed file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BootstrapNodeEntry {
    /// URL of the bootstrap/L2 node (e.g. `https://l2.example.com`).
    pub url: String,
    /// Optional Ed25519 public key of the node (`did:key` or raw base58) for pinning.
    pub node_pubkey: Option<String>,
}

/// Seed file distributed via mirrors containing the initial set of bootstrap nodes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BootstrapSeedFile {
    /// Schema version of the seed file.
    pub version: u32,
    /// Network identifier (e.g. `mainnet`, `testnet`, `devnet`).
    pub network: String,
    /// ISO 8601 timestamp of the last update.
    pub updated_at: String,
    /// List of bootstrap node entries.
    pub nodes: Vec<BootstrapNodeEntry>,
    /// List of mirror URLs hosting the seed file itself.
    pub mirrors: Vec<String>,
}

/// User-configured custom server / peer entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CustomServerEntry {
    /// URL of the custom server.
    pub url: String,
    /// Human-readable display name.
    pub name: String,
    /// Optional authentication token for the server.
    pub auth_token: Option<String>,
    /// Optional peer token used for peer-to-peer authentication.
    pub peer_token: Option<String>,
    /// Whether this entry is currently active and should be used for routing.
    pub is_active: bool,
}
