//! # Layer 2 Mock Node Example
//!
//! This example implements a simplified, functional in-memory Layer 2 Node.
//! It demonstrates how the wallet interacts with L2 nodes to query voucher statuses,
//! request locks, and verify cryptographic response envelopes.
//!
//! Run with: `cargo run --example l2_mock_node`

use human_money_core::models::layer2_api::{
    L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signer, SigningKey};

/// An example of a simplified, yet functional L2 mock server.
/// This server demonstrates the behavior that the wallet expects from an L2 node,
/// including cryptographic signing of verdicts (L2ResponseEnvelope).
pub struct MockL2Node {
    /// The set of all known voucher IDs (represents the Bloom filter in a real node)
    vouchers: HashSet<String>,
    /// Stores actual lock entries. Map: Layer2VoucherId -> (DsTag -> L2LockEntry)
    locks: HashMap<String, HashMap<String, L2LockEntry>>,
    /// Server private key for authenticating its responses
    server_key: SigningKey,
}

impl MockL2Node {
    pub fn new() -> Self {
        Self {
            vouchers: HashSet::new(),
            locks: HashMap::new(),
            server_key: SigningKey::generate(&mut rand::thread_rng()),
        }
    }

    /// Returns server public key (needed by wallet for verification)
    pub fn get_server_pubkey(&self) -> [u8; 32] {
        self.server_key.verifying_key().to_bytes()
    }

    /// Wraps an L2Verdict in an L2ResponseEnvelope and signs it
    fn wrap_and_sign(&self, verdict: L2Verdict) -> Vec<u8> {
        let verdict_serialized = serde_json::to_vec(&verdict).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&verdict_serialized);
        let verdict_hash = hasher.finalize();

        let signature = self.server_key.sign(&verdict_hash);

        let envelope = L2ResponseEnvelope {
            verdict,
            server_signature: signature.to_bytes(),
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    /// Handles a request to lock a tag (LockRequest)
    pub fn handle_lock_request(&mut self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2LockRequest = serde_json::from_slice(req_bytes).unwrap();

        // Add voucher ID to "Bloom filter"
        self.vouchers.insert(req.layer2_voucher_id.clone());

        let ds_tag = if req.is_genesis {
            // For Genesis, we use t_id as key (since no actual ds_tag exists yet)
            bs58::encode(req.transaction_hash).into_string()
        } else {
            req.ds_tag.clone().expect("Non-genesis must have ds_tag")
        };

        let voucher_locks = self.locks.entry(req.layer2_voucher_id.clone()).or_default();

        let entry = L2LockEntry {
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            trap_r: req.trap_r.clone(),
            trap_s: req.trap_s.clone(),
            encrypted_timestamp: req.encrypted_timestamp,
            deletable_at: req.deletable_at.clone(),
            privacy_guard: None,
        };

        // Store entry in in-memory DB ("Locking")
        voucher_locks.insert(ds_tag, entry);

        // Send confirmation back (Fallback/Old-Style Ok in this example)
        let verdict = L2Verdict::Ok {
            signature: [0u8; 64],
        };
        self.wrap_and_sign(verdict)
    }

    /// Handles a status query (Information-Gathering / Sync)
    pub fn handle_status_query(&self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2StatusQuery = serde_json::from_slice(req_bytes).unwrap();

        // 1. Fast Bloom filter check
        if !self.vouchers.contains(&req.layer2_voucher_id) {
            return self.wrap_and_sign(L2Verdict::UnknownVoucher);
        }

        let voucher_locks = self.locks.get(&req.layer2_voucher_id).unwrap();

        // 2. Direct lookup for challenge tag (is tag already locked?)
        if let Some(entry) = voucher_locks.get(&req.challenge_ds_tag) {
            // Return exact proof (Proof of Truth)
            return self.wrap_and_sign(L2Verdict::Verified {
                lock_entry: entry.clone(),
            });
        }

        // 3. Locator search (Find Last Common Ancestor for sync)
        for prefix in &req.locator_prefixes {
            for (ds_tag, _entry) in voucher_locks {
                if ds_tag.starts_with(prefix) {
                    return self.wrap_and_sign(L2Verdict::MissingLocks {
                        sync_point: prefix.clone(),
                    });
                }
            }
        }

        // If we know the voucher, but none of the locators
        // (should rarely happen with proper Genesis handling)
        self.wrap_and_sign(L2Verdict::MissingLocks {
            sync_point: "genesis".to_string(),
        })
    }
}

fn main() {
    println!("L2 Mock Node Example initialized.");
    println!("This is a demonstration of how a Human Money Core L2 Node processes requests.");

    let node = MockL2Node::new();
    let pubkey_hex = hex::encode(node.get_server_pubkey());
    println!("Server Pubkey (Ed25519): {}", pubkey_hex);

    // In a real application, here you would start a QUIC or HTTP server
    // and pass the incoming byte streams to `handle_status_query` and `handle_lock_request`.
}
