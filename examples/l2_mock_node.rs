use human_money_core::models::layer2_api::{
    L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signer, SigningKey};

/// Ein Beispiel für einen stark vereinfachten, aber funktionalen L2 Mock Server.
/// Dieser Server demonstriert das Verhalten, das das Wallet von einem L2-Node erwartet,
/// inklusive der kryptografischen Signierung von Verdicts (L2ResponseEnvelope).
pub struct MockL2Node {
    /// Die Menge aller bekannten Gutschein-IDs (repräsentiert den Bloom-Filter in einer echten Node)
    vouchers: HashSet<String>,
    /// Speichert die tatsächlichen Lock-Einträge. Map: Layer2VoucherId -> (DsTag -> L2LockEntry)
    locks: HashMap<String, HashMap<String, L2LockEntry>>,
    /// Der private Schlüssel des Servers zur Authentifizierung seiner Antworten
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

    /// Gibt den öffentlichen Schlüssel des Servers zurück (wird vom Wallet zur Verifikation benötigt)
    pub fn get_server_pubkey(&self) -> [u8; 32] {
        self.server_key.verifying_key().to_bytes()
    }

    /// Verpackt ein L2Verdict in einen L2ResponseEnvelope und signiert diesen
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

    /// Verarbeitet eine Anfrage zum Sperren eines Tags (LockRequest)
    pub fn handle_lock_request(&mut self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2LockRequest = serde_json::from_slice(req_bytes).unwrap();

        // Füge die Gutschein-ID dem "Bloom-Filter" hinzu
        self.vouchers.insert(req.layer2_voucher_id.clone());

        let ds_tag = if req.is_genesis {
            // Bei Genesis nutzen wir die t_id als Key (da noch kein eigentlicher ds_tag existiert)
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
            deletable_at: req.deletable_at.clone(),
        };

        // Speichern des Eintrags in der In-Memory DB ("Locking")
        voucher_locks.insert(ds_tag, entry);

        // Bestätigung zurücksenden (Fallback/Old-Style Ok in diesem Beispiel)
        let verdict = L2Verdict::Ok {
            signature: [0u8; 64],
        };
        self.wrap_and_sign(verdict)
    }

    /// Verarbeitet eine Statusabfrage (Information-Gathering / Sync)
    pub fn handle_status_query(&self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2StatusQuery = serde_json::from_slice(req_bytes).unwrap();

        // 1. Schneller Bloom-Filter Check
        if !self.vouchers.contains(&req.layer2_voucher_id) {
            return self.wrap_and_sign(L2Verdict::UnknownVoucher);
        }

        let voucher_locks = self.locks.get(&req.layer2_voucher_id).unwrap();

        // 2. Direkter Lookup nach dem Challenge Tag (ist der Tag schon gesperrt?)
        if let Some(entry) = voucher_locks.get(&req.challenge_ds_tag) {
            // Rückgabe des exakten Beweises (Proof of Truth)
            return self.wrap_and_sign(L2Verdict::Verified {
                lock_entry: entry.clone(),
            });
        }

        // 3. Locator Search (Finde den Last Common Ancestor für die Synchronisation)
        for prefix in &req.locator_prefixes {
            for (ds_tag, _entry) in voucher_locks {
                if ds_tag.starts_with(prefix) {
                    return self.wrap_and_sign(L2Verdict::MissingLocks {
                        sync_point: prefix.clone(),
                    });
                }
            }
        }

        // Falls wir zwar den Gutschein, aber absolut keinen der Locators kennen
        // (sollte bei korrekter Genesis-Abhandlung selten passieren)
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
