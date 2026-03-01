use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time;

use human_money_core::models::layer2_api::{
    L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
use human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw;

// =============================================================================
// CLI Struktur
// =============================================================================

#[derive(Parser, Debug)]
#[command(author, version, about = "L2 Client Simulator – Compliance, Stress & Stateful Manual Mode")]
struct Cli {
    /// URL of the target L2 Server (e.g., http://localhost:8080)
    #[arg(long)]
    url: String,

    /// Optional Base58-encoded Server Public Key
    #[arg(long)]
    server_pubkey: Option<String>,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Compliance mode (Integration testing against the server)
    Compliance,
    /// Stress test mode (Load generation)
    Stress {
        /// Requests per second
        #[arg(long, default_value_t = 1000)]
        rate: u32,
        /// Number of parallel async workers
        #[arg(long, default_value_t = 50)]
        connections: u32,
    },
    /// Stateful manual mode for step-by-step graph exploration
    Manual {
        #[command(subcommand)]
        cmd: ManualCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ManualCmd {
    /// Create a new genesis lock and register the voucher in local state
    Genesis,
    /// Transfer (spend) the first available leaf of a voucher
    Transfer {
        /// The layer2_voucher_id to transfer
        voucher_id: String,
    },
    /// Split the first leaf into 2 successor leaves (payment + change)
    Split {
        /// The layer2_voucher_id to split
        voucher_id: String,
    },
    /// Attempt a double-spend on the first leaf of a voucher
    DoubleSpend {
        /// The layer2_voucher_id to double-spend
        voucher_id: String,
    },
    /// Query the L2 server for the status of a voucher's first leaf
    Query {
        /// The layer2_voucher_id to query
        voucher_id: String,
    },
    /// List all vouchers tracked in local state
    List,
    /// Delete the local state file and start fresh
    Reset,
    /// Generate N transfers locally without sending to the L2 server (offline simulation)
    OfflineTransfer {
        /// The layer2_voucher_id to transfer offline
        voucher_id: String,
        /// Number of offline transfer steps to generate
        count: u32,
    },
    /// Synchronize offline locks with the L2 server using the locator-prefix protocol
    Sync {
        /// The layer2_voucher_id to synchronize
        voucher_id: String,
    },
}

// =============================================================================
// State Management
// =============================================================================

const STATE_FILE: &str = "l2_simulator_state.json";

/// Ein einzelnes "Blatt" (UTXO) im L2-Graph. Enthält alle Daten,
/// um die nächste Transaktion korrekt zu signieren.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Leaf {
    /// Der aktuelle Transaction-Hash (Base58), der als ds_tag für den Nachfolger gilt.
    t_id_bs58: String,
    /// Der rohe Signing-Key (32 Bytes), um den nächsten Lock zu signieren.
    signing_key_bytes: Vec<u8>,
    /// Label für den Architekten (z.B. "genesis", "transfer:1", "split:0")
    label: String,
    /// Historische t_id_bs58 Werte dieses Pfades (älteste zuerst).
    /// Werden als Grundlage für locator_prefixes beim Sync genutzt.
    #[serde(default)]
    history: Vec<String>,
    /// Locks, die lokal generiert, aber noch nicht an den Server gesendet wurden.
    /// Werden durch 'offline-transfer' befüllt und durch 'sync' geleert.
    #[serde(default)]
    offline_locks: Vec<L2LockRequest>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VoucherState {
    layer2_voucher_id: String,
    /// Die aktiven, ausgabefähigen Blätter dieses Gutscheins.
    leaves: Vec<Leaf>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SimulatorState {
    vouchers: HashMap<String, VoucherState>,
}

impl SimulatorState {
    fn load() -> Self {
        std::fs::read_to_string(STATE_FILE)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        let json = serde_json::to_string_pretty(self).expect("State serialization failed");
        std::fs::write(STATE_FILE, json).expect("Failed to write state file");
    }
}

// =============================================================================
// Haupt-Dispatcher
// =============================================================================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Compliance => {
            run_compliance_test(&cli.url, cli.server_pubkey.as_deref()).await;
        }
        Mode::Stress { rate, connections } => {
            run_stress_test(&cli.url, rate, connections).await;
        }
        Mode::Manual { cmd } => {
            run_manual_cmd(&cli.url, cmd).await;
        }
    }
}

// =============================================================================
// Manual Mode: Dispatcher
// =============================================================================

async fn run_manual_cmd(url: &str, cmd: ManualCmd) {
    match cmd {
        ManualCmd::Genesis => cmd_genesis(url).await,
        ManualCmd::Transfer { voucher_id } => cmd_transfer(url, &voucher_id).await,
        ManualCmd::Split { voucher_id } => cmd_split(url, &voucher_id).await,
        ManualCmd::DoubleSpend { voucher_id } => cmd_double_spend(url, &voucher_id).await,
        ManualCmd::Query { voucher_id } => cmd_query(url, &voucher_id).await,
        ManualCmd::List => cmd_list(),
        ManualCmd::Reset => cmd_reset(),
        ManualCmd::OfflineTransfer { voucher_id, count } => {
            cmd_offline_transfer(&voucher_id, count);
        }
        ManualCmd::Sync { voucher_id } => cmd_sync(url, &voucher_id).await,
    }
}

// =============================================================================
// Manual Mode: genesis
// =============================================================================

async fn cmd_genesis(url: &str) {
    let client = Client::new();
    let mut rng = OsRng;

    // Neuen Ephemeral Signing Key erzeugen
    let sender_key = SigningKey::generate(&mut rng);
    let sender_pub = sender_key.verifying_key().to_bytes();

    // Zufällige t_id generieren
    let mut t_id_bytes = [0u8; 32];
    rng.fill_bytes(&mut t_id_bytes);
    let t_id_bs58 = bs58::encode(&t_id_bytes).into_string();

    // layer2_voucher_id = SHA256(t_id || sender_pub) – spiegelt calculate_layer2_voucher_id wider
    let mut hasher = Sha256::new();
    hasher.update(t_id_bytes);
    hasher.update(sender_pub);
    let vid_hash = hasher.finalize();
    let layer2_voucher_id = hex::encode(vid_hash);

    // Signatur berechnen: challenge_ds_tag bei Genesis = bs58(t_id)
    let challenge_ds_tag = t_id_bs58.clone();
    let payload_hash = calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &layer2_voucher_id,
        &t_id_bytes,
        &sender_pub,
        None,
        None,
        None,
    );
    let signature = sender_key.sign(&payload_hash);

    let req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: layer2_voucher_id.clone(),
        ds_tag: None,
        transaction_hash: t_id_bytes,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: signature.to_bytes(),
        deletable_at: None,
    };

    println!("[ MANUAL | genesis ]");
    println!("  Voucher ID : {}", layer2_voucher_id);
    println!("  t_id       : {}", t_id_bs58);
    println!("  Sending Genesis Lock to {}...", url);

    let res = client
        .post(format!("{}/lock", url))
        .json(&req)
        .send()
        .await
        .expect("Failed to reach server");

    let status = res.status();
    if status.is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse response");
        match &envelope.verdict {
            L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => {
                println!("  Server     : [OK] Verified / Accepted");
            }
            other => {
                println!("  Server     : [WARN] Unexpected verdict: {:?}", other);
            }
        }
    } else {
        println!("  Server     : [ERROR] HTTP {}", status);
        return;
    }

    // Blatt im State speichern
    let leaf = Leaf {
        t_id_bs58: t_id_bs58.clone(),
        signing_key_bytes: sender_key.to_bytes().to_vec(),
        label: "genesis".to_string(),
        history: vec![],
        offline_locks: vec![],
    };

    let mut state = SimulatorState::load();
    state.vouchers.insert(
        layer2_voucher_id.clone(),
        VoucherState {
            layer2_voucher_id: layer2_voucher_id.clone(),
            leaves: vec![leaf],
        },
    );
    state.save();

    println!();
    println!("  ✓ State saved. Voucher ID for further commands:");
    println!("    {}", layer2_voucher_id);
}

// =============================================================================
// Manual Mode: transfer
// =============================================================================

async fn cmd_transfer(url: &str, voucher_id: &str) {
    let mut state = SimulatorState::load();
    let voucher = state
        .vouchers
        .get_mut(voucher_id)
        .unwrap_or_else(|| panic!("Voucher '{}' not found in local state. Run 'genesis' first.", voucher_id));

    if voucher.leaves.is_empty() {
        println!("[ERROR] No spendable leaves for voucher '{}'", voucher_id);
        return;
    }

    // Erstes Blatt entnehmen
    let leaf = voucher.leaves.remove(0);
    let old_t_id_bs58 = leaf.t_id_bs58.clone();
    let old_key_bytes: [u8; 32] = leaf
        .signing_key_bytes
        .clone()
        .try_into()
        .expect("Invalid key length in state");
    let _old_key = SigningKey::from_bytes(&old_key_bytes);

    let mut rng = OsRng;

    // Neuen Ephemeral Key für den Nachfolger
    let new_key = SigningKey::generate(&mut rng);
    let new_pub = new_key.verifying_key().to_bytes();

    // Neue t_id generieren
    let mut new_t_id = [0u8; 32];
    rng.fill_bytes(&mut new_t_id);
    let new_t_id_bs58 = bs58::encode(&new_t_id).into_string();

    // ds_tag = bs58(vorherige t_id) – so wie die Core-Logik es verlangt
    let ds_tag = old_t_id_bs58.clone();

    let payload_hash = calculate_l2_payload_hash_raw(
        &ds_tag,
        voucher_id,
        &new_t_id,
        &new_pub,
        None,
        None,
        None,
    );
    let signature = new_key.sign(&payload_hash);

    let req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: new_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag.clone()),
        transaction_hash: new_t_id,
        is_genesis: false,
        sender_ephemeral_pub: new_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: signature.to_bytes(),
        deletable_at: None,
    };

    println!("[ MANUAL | transfer ]");
    println!("  Voucher ID   : {}", voucher_id);
    println!("  Spent leaf   : {} ({})", old_t_id_bs58, leaf.label);
    println!("  ds_tag       : {}", ds_tag);
    println!("  New t_id     : {}", new_t_id_bs58);
    println!("  Sending Transfer Lock to {}...", url);

    let client = Client::new();
    let res = client
        .post(format!("{}/lock", url))
        .json(&req)
        .send()
        .await
        .expect("Failed to reach server");

    let status = res.status();
    if status.is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse response");
        match &envelope.verdict {
            L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => {
                println!("  Server       : [OK] Transfer accepted!");
            }
            L2Verdict::Rejected { reason } => {
                println!("  Server       : [REJECTED] {}", reason);
                // Blatt zurücklegen, da nicht verbraucht
                voucher.leaves.insert(0, leaf);
                state.save();
                return;
            }
            other => {
                println!("  Server       : [WARN] Unexpected verdict: {:?}", other);
            }
        }
    } else {
        println!("  Server       : [ERROR] HTTP {}", status);
        return;
    }

    // Neues Blatt speichern, altes wurde bereits entfernt
    // History: Vorgänger-Geschichte kopieren und verbrauchten ds_tag anhängen
    let mut new_history = leaf.history.clone();
    new_history.push(old_t_id_bs58.clone());

    let new_leaf = Leaf {
        t_id_bs58: new_t_id_bs58.clone(),
        signing_key_bytes: new_key.to_bytes().to_vec(),
        label: format!("transfer:{}", leaf.label),
        history: new_history,
        offline_locks: vec![],
    };
    voucher.leaves.push(new_leaf);
    state.save();

    println!("  ✓ State updated. New leaf: {}", new_t_id_bs58);
}

// =============================================================================
// Manual Mode: split
// =============================================================================

async fn cmd_split(url: &str, voucher_id: &str) {
    let mut state = SimulatorState::load();
    let voucher = state
        .vouchers
        .get_mut(voucher_id)
        .unwrap_or_else(|| panic!("Voucher '{}' not found in local state.", voucher_id));

    if voucher.leaves.is_empty() {
        println!("[ERROR] No spendable leaves for voucher '{}'", voucher_id);
        return;
    }

    // Erstes Blatt entnehmen (wird durch die Split-Transaktion verbraucht)
    let consumed_leaf = voucher.leaves.remove(0);
    let ds_tag = consumed_leaf.t_id_bs58.clone();

    let mut rng = OsRng;

    // Einen zentralen Split-Lock senden, der den Vorgänger verbraucht.
    // Der Split selbst ist eine normale Transaktion mit einer neuen t_id.
    let split_key = SigningKey::generate(&mut rng);
    let split_pub = split_key.verifying_key().to_bytes();
    let mut split_t_id = [0u8; 32];
    rng.fill_bytes(&mut split_t_id);
    let split_t_id_bs58 = bs58::encode(&split_t_id).into_string();

    let split_payload_hash = calculate_l2_payload_hash_raw(
        &ds_tag,
        voucher_id,
        &split_t_id,
        &split_pub,
        None,
        None,
        None,
    );
    let split_sig = split_key.sign(&split_payload_hash);

    let split_req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: split_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag.clone()),
        transaction_hash: split_t_id,
        is_genesis: false,
        sender_ephemeral_pub: split_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: split_sig.to_bytes(),
        deletable_at: None,
    };

    println!("[ MANUAL | split ]");
    println!("  Voucher ID        : {}", voucher_id);
    println!("  Consumed leaf     : {} ({})", ds_tag, consumed_leaf.label);
    println!("  Split anchor t_id : {}", split_t_id_bs58);
    println!("  Sending Split anchor lock to {}...", url);

    let client = Client::new();
    let res = client
        .post(format!("{}/lock", url))
        .json(&split_req)
        .send()
        .await
        .expect("Failed to reach server");

    let status = res.status();
    if status.is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse response");
        match &envelope.verdict {
            L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => {
                println!("  Server            : [OK] Split anchor accepted!");
            }
            L2Verdict::Rejected { reason } => {
                println!("  Server            : [REJECTED] {}", reason);
                // Blatt zurücklegen, da nicht verbraucht
                voucher.leaves.insert(0, consumed_leaf);
                state.save();
                return;
            }
            other => {
                println!("  Server            : [WARN] {:?}", other);
            }
        }
    } else {
        println!("  Server            : [ERROR] HTTP {}", status);
        return;
    }

    // Erzeuge exakt 2 neue, unabhängige Blätter: Zahlbetrag (payment) + Wechselgeld (change).
    // In einem echten System würden diese Locks separat übermittelt;
    // hier legen wir sie als "pending children" im State an, die jederzeit
    // via `transfer` einzeln ausgegeben werden können.
    println!("  Creating 2 successor leaves in state (payment + change)...");
    let labels = ["payment", "change"];
    let mut new_leaves = Vec::with_capacity(2);
    // History: Vorgänger-Geschichte + verbrauchter ds_tag
    let mut child_history = consumed_leaf.history.clone();
    child_history.push(ds_tag.clone());
    for i in 0..2usize {
        let child_key = SigningKey::generate(&mut rng);
        let mut child_t_id_bytes = [0u8; 32];
        rng.fill_bytes(&mut child_t_id_bytes);
        // Index einmischen, um garantiert unterschiedliche Hashes zu erzeugen
        child_t_id_bytes[0] ^= i as u8;
        let child_t_id_bs58 = bs58::encode(&child_t_id_bytes).into_string();

        println!("    Leaf [{}] ({}): {}", i, labels[i], child_t_id_bs58);

        new_leaves.push(Leaf {
            t_id_bs58: child_t_id_bs58,
            signing_key_bytes: child_key.to_bytes().to_vec(),
            label: format!("split:{}", labels[i]),
            history: child_history.clone(),
            offline_locks: vec![],
        });
    }

    voucher.leaves.extend(new_leaves);
    state.save();

    println!("  ✓ State updated. 2 new leaves available for independent spending.");
    println!("  Hint: Use 'transfer <voucher_id>' twice to spend each leaf independently.");
}

// =============================================================================
// Manual Mode: double-spend
// =============================================================================

async fn cmd_double_spend(url: &str, voucher_id: &str) {
    let state = SimulatorState::load();
    let voucher = state
        .vouchers
        .get(voucher_id)
        .unwrap_or_else(|| panic!("Voucher '{}' not found in local state.", voucher_id));

    if voucher.leaves.is_empty() {
        println!("[ERROR] No spendable leaves for voucher '{}'", voucher_id);
        return;
    }

    let leaf = &voucher.leaves[0];
    let ds_tag = leaf.t_id_bs58.clone();

    let mut rng = OsRng;
    let client = Client::new();

    println!("[ MANUAL | double-spend ]");
    println!("  Voucher ID : {}", voucher_id);
    println!("  Leaf       : {} ({})", ds_tag, leaf.label);
    println!("  Generating two conflicting locks for the SAME ds_tag...");

    // Beide Locks nutzen denselben ds_tag, aber unterschiedliche t_ids und Keys
    for attempt in 1..=2u8 {
        let spend_key = SigningKey::generate(&mut rng);
        let spend_pub = spend_key.verifying_key().to_bytes();
        let mut attempt_t_id = [0u8; 32];
        rng.fill_bytes(&mut attempt_t_id);
        // Unterschiedliche t_ids sicherstellen
        attempt_t_id[31] = attempt;
        let attempt_t_id_bs58 = bs58::encode(&attempt_t_id).into_string();

        let payload_hash = calculate_l2_payload_hash_raw(
            &ds_tag,
            voucher_id,
            &attempt_t_id,
            &spend_pub,
            None,
            None,
            None,
        );
        let sig = spend_key.sign(&payload_hash);

        let req = L2LockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: spend_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(ds_tag.clone()),
            transaction_hash: attempt_t_id,
            is_genesis: false,
            sender_ephemeral_pub: spend_pub,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: sig.to_bytes(),
            deletable_at: None,
        };

        println!();
        println!("  --- Attempt #{} ---", attempt);
        println!("  t_id       : {}", attempt_t_id_bs58);
        println!("  ds_tag     : {}", ds_tag);

        let res = client
            .post(format!("{}/lock", url))
            .json(&req)
            .send()
            .await
            .expect("Failed to reach server");

        let http_status = res.status();
        if http_status.is_success() {
            let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse response");
            match &envelope.verdict {
                L2Verdict::Verified { lock_entry } => {
                    let existing = bs58::encode(lock_entry.t_id).into_string();
                    if existing == attempt_t_id_bs58 {
                        println!("  Server: [OK] Attempt #{} accepted as the canonical lock.", attempt);
                    } else {
                        println!(
                            "  Server: [DS DETECTED] Returned existing lock with t_id: {}",
                            existing
                        );
                        println!("  ✓ Double-spend properly proved by server!");
                    }
                }
                L2Verdict::Rejected { reason } => {
                    println!("  Server: [REJECTED] {} – double-spend blocked!", reason);
                }
                other => {
                    println!("  Server: [WARN] Unexpected verdict: {:?}", other);
                }
            }
        } else {
            println!("  Server: [HTTP {}] Request rejected.", http_status);
        }
    }

    println!();
    println!("  NOTE: State was NOT updated – the leaf remains available for legitimate spending.");
}

// =============================================================================
// Manual Mode: query
// =============================================================================

async fn cmd_query(url: &str, voucher_id: &str) {
    let state = SimulatorState::load();
    let voucher = state
        .vouchers
        .get(voucher_id)
        .unwrap_or_else(|| panic!("Voucher '{}' not found in local state.", voucher_id));

    if voucher.leaves.is_empty() {
        println!("[ERROR] No leaves for voucher '{}'", voucher_id);
        return;
    }

    let leaf = &voucher.leaves[0];
    // challenge_ds_tag = der Key, unter dem der letzte Lock am Server gespeichert ist.
    // Original: derive_challenge_tag(last_tx)
    //   Genesis    → t_id_genesis (= leaf.t_id_bs58, history ist leer)
    //   Non-Genesis → trap_data.ds_tag = t_id des Vorgänger-Blattes (= history.last())
    let challenge_ds_tag = if leaf.history.is_empty() {
        leaf.t_id_bs58.clone() // Genesis
    } else {
        leaf.history.last().unwrap().clone() // Non-Genesis: letzter ds_tag
    };

    let key_bytes: [u8; 32] = leaf
        .signing_key_bytes
        .clone()
        .try_into()
        .expect("Invalid key length in state");
    let key = SigningKey::from_bytes(&key_bytes);
    let pub_bytes = key.verifying_key().to_bytes();

    let query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: pub_bytes,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        challenge_ds_tag: challenge_ds_tag.clone(),
        locator_prefixes: vec![],
    };

    println!("[ MANUAL | query ]");
    println!("  Voucher ID       : {}", voucher_id);
    println!("  Querying leaf    : {} ({})", challenge_ds_tag, leaf.label);

    let client = Client::new();
    let res = client
        .post(format!("{}/status", url))
        .json(&query)
        .send()
        .await
        .expect("Failed to reach server");

    let http_status = res.status();
    if http_status.is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse response");
        match &envelope.verdict {
            L2Verdict::Verified { lock_entry } => {
                println!("  Server: [VERIFIED]");
                println!("    t_id = {}", bs58::encode(lock_entry.t_id).into_string());
                println!(
                    "    sender_pub = {}",
                    bs58::encode(lock_entry.sender_ephemeral_pub).into_string()
                );
            }
            L2Verdict::UnknownVoucher => {
                println!("  Server: [UNKNOWN VOUCHER] – not yet registered on L2.");
            }
            L2Verdict::MissingLocks { sync_point } => {
                println!("  Server: [MISSING LOCKS] – sync from '{}'", sync_point);
            }
            other => {
                println!("  Server: {:?}", other);
            }
        }
    } else {
        println!("  Server: [HTTP {}]", http_status);
    }
}

// =============================================================================
// Manual Mode: list
// =============================================================================

fn cmd_list() {
    let state = SimulatorState::load();
    if state.vouchers.is_empty() {
        println!("No vouchers in local state ({})", STATE_FILE);
        return;
    }
    println!("Vouchers in {} :", STATE_FILE);
    for (vid, voucher) in &state.vouchers {
        println!("  {}", vid);
        if voucher.leaves.is_empty() {
            println!("    (no spendable leaves)");
        } else {
            for (i, leaf) in voucher.leaves.iter().enumerate() {
                let offline_info = if leaf.offline_locks.is_empty() {
                    String::new()
                } else {
                    format!(" [{} offline lock(s) pending sync]", leaf.offline_locks.len())
                };
                println!(
                    "    Leaf [{}]: {} – label='{}'{}",
                    i, leaf.t_id_bs58, leaf.label, offline_info
                );
            }
        }
    }
}

// =============================================================================
// Compliance Test Mode
// =============================================================================

fn generate_mock_lock_request(
    is_genesis: bool,
    provided_voucher_id: Option<String>,
    provided_t_id: Option<[u8; 32]>,
    provided_ds_tag: Option<String>,
) -> (L2LockRequest, SigningKey) {
    let mut rng = OsRng;
    let sender_key = SigningKey::generate(&mut rng);
    let sender_pub = sender_key.verifying_key().to_bytes();

    let layer2_voucher_id = provided_voucher_id.unwrap_or_else(|| {
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        hex::encode(id)
    });

    let transaction_hash = provided_t_id.unwrap_or_else(|| {
        let mut t = [0u8; 32];
        rng.fill_bytes(&mut t);
        t
    });

    let ds_tag = if is_genesis {
        None
    } else {
        Some(provided_ds_tag.unwrap_or_else(|| {
            let mut t = [0u8; 32];
            rng.fill_bytes(&mut t);
            bs58::encode(t).into_string()
        }))
    };

    let challenge_ds_tag = if is_genesis {
        bs58::encode(transaction_hash).into_string()
    } else {
        ds_tag.clone().unwrap()
    };

    let payload_hash = calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &layer2_voucher_id,
        &transaction_hash,
        &sender_pub,
        None,
        None,
        None,
    );

    let signature = sender_key.sign(&payload_hash);

    let req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id,
        ds_tag,
        transaction_hash,
        is_genesis,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: signature.to_bytes(),
        deletable_at: None,
    };

    (req, sender_key)
}

async fn run_compliance_test(url: &str, _server_pubkey: Option<&str>) {
    let client = Client::new();
    println!("Starting Compliance Test against {}...", url);

    // 1. Genesis Lock
    let (genesis_req, _) = generate_mock_lock_request(true, None, None, None);
    let v_id = genesis_req.layer2_voucher_id.clone();
    let genesis_t_id = bs58::encode(genesis_req.transaction_hash).into_string();

    println!("-> Sending Genesis Lock (is_genesis=true)...");
    let res = client
        .post(format!("{}/lock", url))
        .json(&genesis_req)
        .send()
        .await
        .expect("Failed to reach server");
    assert!(
        res.status().is_success(),
        "Genesis lock failed with status {}",
        res.status()
    );

    let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse L2ResponseEnvelope");
    match envelope.verdict {
        L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => println!("   [OK] Genesis Lock verified!"),
        _ => panic!("Expected Verified or Ok verdict!"),
    }

    // 2. Happy Path Query
    println!("-> Querying Status (Happy Path)...");
    let query_happy = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: genesis_req.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: v_id.clone(),
        challenge_ds_tag: genesis_t_id.clone(),
        locator_prefixes: vec![],
    };

    let res = client
        .post(format!("{}/status", url))
        .json(&query_happy)
        .send()
        .await
        .expect("Failed to reach server");
    assert!(res.status().is_success());

    let envelope: L2ResponseEnvelope = res.json().await.expect("Parse failed");
    match envelope.verdict {
        L2Verdict::Verified { .. } => println!("   [OK] Happy Path Verified!"),
        L2Verdict::Ok { .. } => println!("   [OK] Happy Path Verified (Legacy OK)!"),
        _ => panic!("Expected Verified verdict for Genesis status!"),
    }

    // 3. Double Spend
    println!("-> Sending Double Spend (same ds_tag, different t_id)...");
    let mut rng = OsRng;
    let mut diff_t_id = [0u8; 32];
    rng.fill_bytes(&mut diff_t_id);

    let (ds_req, _) = generate_mock_lock_request(
        false,
        Some(v_id.clone()),
        Some(diff_t_id),
        Some(genesis_t_id.clone()),
    );

    let res = client
        .post(format!("{}/lock", url))
        .json(&ds_req)
        .send()
        .await
        .expect("Failed to send request");

    if res.status().is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.expect("Parse error");
        match envelope.verdict {
            L2Verdict::Verified { lock_entry } => {
                let existing_t_id = lock_entry.t_id;
                assert_eq!(existing_t_id, genesis_req.transaction_hash);
                assert_ne!(existing_t_id, diff_t_id, "Server allowed double spend!");
                println!("   [OK] Double Spend properly proved via returning existing lock!");
            }
            L2Verdict::Rejected { reason } => {
                println!("   [OK] Double Spend rejected by server: {}", reason);
            }
            _ => panic!("Unexpected verdict for double-spend!"),
        }
    } else {
        println!("   [OK] Double Spend rejected with HTTP {}", res.status());
    }

    // 4. Unknown Voucher
    println!("-> Querying Unknown Voucher...");
    let (unknown_req, _) = generate_mock_lock_request(true, None, None, None);
    let unknown_query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: unknown_req.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: unknown_req.layer2_voucher_id.clone(),
        challenge_ds_tag: "abcde".to_string(),
        locator_prefixes: vec![],
    };

    let res = client
        .post(format!("{}/status", url))
        .json(&unknown_query)
        .send()
        .await
        .expect("Failed request");

    if res.status().is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.unwrap();
        match envelope.verdict {
            L2Verdict::UnknownVoucher => println!("   [OK] Unknown Voucher verified!"),
            _ => panic!("Expected UnknownVoucher verdict!"),
        }
    } else {
        println!("   [OK] Unknown Voucher rejected with HTTP {}", res.status());
    }

    // 5. Invalid Signature
    println!("-> Sending Invalid Signature (tampered layer2_signature)...");
    let (mut bad_req, _) = generate_mock_lock_request(true, None, None, None);
    // Flippe das erste Byte der Signatur – mathematisch garantiert ungültig
    bad_req.layer2_signature[0] ^= 0xFF;

    let res = client
        .post(format!("{}/lock", url))
        .json(&bad_req)
        .send()
        .await
        .expect("Failed to send invalid-sig request");

    if res.status().is_success() {
        let envelope: L2ResponseEnvelope = res.json().await.expect("Parse error");
        match envelope.verdict {
            L2Verdict::Rejected { reason } => {
                println!("   [OK] Invalid Signature rejected by server: {}", reason);
            }
            L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => {
                panic!("Server accepted invalid cryptographic signature!");
            }
            other => {
                println!("   [WARN] Unexpected verdict for invalid-sig: {:?}", other);
            }
        }
    } else {
        println!(
            "   [OK] Invalid Signature rejected with HTTP {}",
            res.status()
        );
    }

    println!("Compliance Test completed successfully!");
}

// =============================================================================
// Stress Test Mode
// =============================================================================

async fn run_stress_test(url: &str, rate: u32, connections: u32) {
    let client = Client::new();
    let counter = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    // Summe der Latenzen (ms) aller erfolgreichen Requests im aktuellen 3s-Fenster
    let latency_sum_ms = Arc::new(AtomicU64::new(0));
    // Anzahl erfolgreicher Requests im aktuellen 3s-Fenster (für den Durchschnitt)
    let latency_count = Arc::new(AtomicUsize::new(0));

    let c = counter.clone();
    let e = errors.clone();
    let ls = latency_sum_ms.clone();
    let lc = latency_count.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(3));
        let mut last_cnt = 0;
        loop {
            interval.tick().await;
            let current_cnt = c.load(Ordering::Relaxed);
            let current_err = e.load(Ordering::Relaxed);
            let diff = current_cnt - last_cnt;
            last_cnt = current_cnt;

            // Durchschnittslatenz aus dem vergangenen 3s-Fenster berechnen und zurücksetzen
            let sum_ms = ls.swap(0, Ordering::Relaxed);
            let count = lc.swap(0, Ordering::Relaxed);
            let avg_latency = if count > 0 { sum_ms / count as u64 } else { 0 };

            println!(
                "[Stats] {} reqs/sec | Total: {} | Errors: {} | Avg Latency: {} ms",
                diff / 3,
                current_cnt,
                current_err,
                avg_latency
            );
        }
    });

    println!(
        "Starting Stress Test against {} with {} req/s and {} workers",
        url, rate, connections
    );
    let interval_ns = 1_000_000_000 / rate as u64;

    let sem = Arc::new(Semaphore::new(connections as usize));
    let mut ticker = time::interval(Duration::from_nanos(interval_ns));

    loop {
        ticker.tick().await;

        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };

        let (req, _) = generate_mock_lock_request(true, None, None, None);
        let client_clone = client.clone();
        let u = url.to_string();
        let c = counter.clone();
        let e = errors.clone();
        let ls = latency_sum_ms.clone();
        let lc = latency_count.clone();

        tokio::spawn(async move {
            let mut rng = OsRng;
            let is_status = rng.next_u32() % 2 == 0;

            let t_start = tokio::time::Instant::now();

            let res = if is_status {
                let v_id = req.layer2_voucher_id.clone();
                let query = L2StatusQuery {
                    auth: L2AuthPayload {
                        ephemeral_pubkey: req.sender_ephemeral_pub,
                        auth_signature: None,
                    },
                    layer2_voucher_id: v_id,
                    challenge_ds_tag: bs58::encode(&req.transaction_hash).into_string(),
                    locator_prefixes: vec![],
                };
                client_clone
                    .post(format!("{}/status", u))
                    .json(&query)
                    .send()
                    .await
            } else {
                client_clone
                    .post(format!("{}/lock", u))
                    .json(&req)
                    .send()
                    .await
            };

            let elapsed_ms = t_start.elapsed().as_millis() as u64;

            c.fetch_add(1, Ordering::Relaxed);
            match res {
                Ok(resp) if !resp.status().is_server_error() => {
                    // Latenz nur für erfolgreiche Requests aufsummieren
                    ls.fetch_add(elapsed_ms, Ordering::Relaxed);
                    lc.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    e.fetch_add(1, Ordering::Relaxed);
                }
            }
            drop(permit);
        });
    }
}

// =============================================================================
// Manual Mode: reset
// =============================================================================

fn cmd_reset() {
    if std::path::Path::new(STATE_FILE).exists() {
        std::fs::remove_file(STATE_FILE)
            .unwrap_or_else(|e| panic!("Failed to delete {}: {}", STATE_FILE, e));
        println!("Local state cleared. ({} deleted)", STATE_FILE);
    } else {
        println!("State is already empty. ({} does not exist)", STATE_FILE);
    }
}

// =============================================================================
// Manual Mode: offline-transfer
// =============================================================================

fn cmd_offline_transfer(voucher_id: &str, count: u32) {
    if count == 0 {
        println!("[ERROR] count must be > 0");
        return;
    }

    let mut state = SimulatorState::load();
    let voucher = state
        .vouchers
        .get_mut(voucher_id)
        .unwrap_or_else(|| panic!("Voucher '{}' not found in local state.", voucher_id));

    if voucher.leaves.is_empty() {
        println!("[ERROR] No spendable leaves for voucher '{}'", voucher_id);
        return;
    }

    let leaf = &mut voucher.leaves[0];
    let mut rng = OsRng;

    println!("[ MANUAL | offline-transfer (count={}) ]", count);
    println!("  Voucher ID : {}", voucher_id);
    println!("  Starting from leaf: {} ({})", leaf.t_id_bs58, leaf.label);
    println!("  Generating {} offline lock(s)...", count);

    // Aktuellen Zustand des Blatts als Ausgangspunkt
    let mut current_t_id_bs58 = leaf.t_id_bs58.clone();
    let mut current_key_bytes = leaf.signing_key_bytes.clone();
    let mut new_history = leaf.history.clone();
    let mut new_offline_locks: Vec<L2LockRequest> = leaf.offline_locks.clone();

    for i in 0..count {
        // Neuen Ephemeral Key für diesen Schritt
        let new_key = SigningKey::generate(&mut rng);
        let new_pub = new_key.verifying_key().to_bytes();

        // Neue t_id generieren
        let mut new_t_id = [0u8; 32];
        rng.fill_bytes(&mut new_t_id);
        let new_t_id_bs58 = bs58::encode(&new_t_id).into_string();

        // ds_tag = aktuelle t_id des Vorgängers
        let ds_tag = current_t_id_bs58.clone();

        let payload_hash = calculate_l2_payload_hash_raw(
            &ds_tag,
            voucher_id,
            &new_t_id,
            &new_pub,
            None,
            None,
            None,
        );
        let signature = new_key.sign(&payload_hash);

        let lock = L2LockRequest {
            auth: L2AuthPayload {
                ephemeral_pubkey: new_pub,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(ds_tag.clone()),
            transaction_hash: new_t_id,
            is_genesis: false,
            sender_ephemeral_pub: new_pub,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: signature.to_bytes(),
            deletable_at: None,
        };

        println!(
            "    Step [{}]: ds_tag={} → new t_id={}",
            i + 1,
            &ds_tag[..10],
            &new_t_id_bs58[..10]
        );

        // ds_tag des verbrauchten Blattes in History aufnehmen
        new_history.push(ds_tag);
        new_offline_locks.push(lock);

        // Nächste Iteration: neuer Ausgangspunkt
        current_t_id_bs58 = new_t_id_bs58;
        current_key_bytes = new_key.to_bytes().to_vec();
    }

    // Blatt mit dem finalen Zustand aktualisieren
    leaf.history = new_history;
    leaf.offline_locks = new_offline_locks;
    leaf.t_id_bs58 = current_t_id_bs58.clone();
    leaf.signing_key_bytes = current_key_bytes;
    leaf.label = format!("offline-transfer:{}x", count);

    state.save();

    println!();
    println!("  ✓ {} offline lock(s) stored in state.", count);
    println!("  Current leaf t_id : {}", current_t_id_bs58);
    println!("  Run 'sync {}' to push them to the L2 server.", voucher_id);
}

// =============================================================================
// Manual Mode: sync
// =============================================================================

async fn cmd_sync(url: &str, voucher_id: &str) {
    let mut state = SimulatorState::load();
    let voucher = state
        .vouchers
        .get_mut(voucher_id)
        .unwrap_or_else(|| panic!("Voucher '{}' not found in local state.", voucher_id));

    if voucher.leaves.is_empty() {
        println!("[ERROR] No leaves for voucher '{}'", voucher_id);
        return;
    }

    let leaf = &voucher.leaves[0];

    if leaf.offline_locks.is_empty() {
        println!("[ MANUAL | sync ]");
        println!("  No offline locks to sync for voucher '{}'", voucher_id);
        return;
    }

    // challenge_ds_tag = der Key, unter dem der letzte (bekannte) Lock am Server gespeichert ist.
    // Da offline_locks noch nicht gesendet wurden, ist der letzte serverseitig bekannte Lock
    // derjenige BEFORE den offline_locks – also history.last() des Genesis/Transfer-Blatts.
    // Original: derive_challenge_tag(last_known_tx)
    //   Genesis    → t_id_genesis (history leer)
    //   Non-Genesis → letzter in history gespeicherter ds_tag (= letzter übermittelter Lock)
    //
    // WICHTIG: leere history bedeutet, dass das Blatt noch kein transfer vor offline-transfer hatte.
    // In diesem Fall zeigt leaf.t_id_bs58 auf die Genesis-t_id – der korrekte challenge.
    let challenge_ds_tag = if leaf.history.is_empty() {
        leaf.t_id_bs58.clone() // Genesis-Blatt: noch keine online Transfers davor
    } else {
        // history enthält alle ds_tags der bisherigen (online!) Locks.
        // Der letzte Eintrag ist der ds_tag des letzten online gesendeten Locks.
        leaf.history.last().unwrap().clone()
    };
    let n_locks = leaf.offline_locks.len();

    // Locator-Prefixes nach dem originalen exponentiellen Algorithmus aus
    // generate_locator_prefixes (src/services/l2_gateway.rs):
    // Wir gehen von der letzten History-Position rückwärts mit Schritten 1, 2, 4, 8, 16...
    // Die History enthält die verbrauchten ds_tags (älteste zuerst).
    // Zusätzlich wird das Genesis-Präfix immer am Ende angehängt.
    let locator_prefixes: Vec<String> = {
        let history = &leaf.history;
        let n = history.len();
        let mut prefixes: Vec<String> = Vec::new();

        if n > 0 {
            // Rückwärts mit exponentiellen Schritten: Index n-1, n-2, n-4, n-8, ...
            let mut step: usize = 1;
            let mut i = n - 1;

            loop {
                prefixes.push(history[i].chars().take(10).collect());

                if i < step {
                    break;
                }
                i -= step;
                step *= 2; // Exponentielle Abstände: 1, 2, 4, 8, 16...
            }

            // Genesis-Präfix (history[0] = ältester ds_tag) immer anhängen,
            // falls nicht bereits enthalten.
            let genesis_prefix: String = history[0].chars().take(10).collect();
            if !prefixes.contains(&genesis_prefix) {
                prefixes.push(genesis_prefix);
            }
        }

        prefixes
    };

    let key_bytes: [u8; 32] = leaf
        .signing_key_bytes
        .clone()
        .try_into()
        .expect("Invalid key length in state");
    let key = SigningKey::from_bytes(&key_bytes);
    let pub_bytes = key.verifying_key().to_bytes();

    let query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: pub_bytes,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        challenge_ds_tag: challenge_ds_tag.clone(),
        locator_prefixes: locator_prefixes.clone(),
    };

    println!("[ MANUAL | sync ]");
    println!("  Voucher ID        : {}", voucher_id);
    println!("  Offline locks     : {}", n_locks);
    println!("  challenge_ds_tag  : {}", &challenge_ds_tag[..10.min(challenge_ds_tag.len())]);
    println!("  locator_prefixes  : {} prefix(es): {:?}", locator_prefixes.len(), &locator_prefixes);
    println!("  Querying {} /status ...", url);

    let client = Client::new();
    let res = client
        .post(format!("{}/status", url))
        .json(&query)
        .send()
        .await
        .expect("Failed to reach server");

    let http_status = res.status();
    if !http_status.is_success() {
        println!("  Server: [HTTP {}] Query failed.", http_status);
        return;
    }

    let envelope: L2ResponseEnvelope = res.json().await.expect("Failed to parse response");

    // Wir brauchen die Locks für das Senden – clone vor dem borrow
    let offline_locks = voucher.leaves[0].offline_locks.clone();

    match envelope.verdict {
        L2Verdict::MissingLocks { sync_point } => {
            println!("  Server: [MISSING LOCKS] sync_point = '{}'", sync_point);

            // Startindex bestimmen: erstes Lock, dessen ds_tag mit sync_point beginnt
            // (oder "genesis" = alle Locks senden)
            let start_idx = if sync_point == "genesis" {
                0
            } else {
                offline_locks
                    .iter()
                    .position(|lock| {
                        lock.ds_tag
                            .as_deref()
                            .map(|tag| tag.starts_with(&sync_point))
                            .unwrap_or(false)
                    })
                    .unwrap_or(0)
            };

            let locks_to_send = &offline_locks[start_idx..];
            println!(
                "  Sending {} lock(s) starting from index {} ...",
                locks_to_send.len(),
                start_idx
            );

            let mut all_ok = true;
            for (i, lock) in locks_to_send.iter().enumerate() {
                let ds_display = lock
                    .ds_tag
                    .as_deref()
                    .map(|t| &t[..10.min(t.len())])
                    .unwrap_or("(genesis)");
                let t_id_display = bs58::encode(lock.transaction_hash).into_string();

                let res = client
                    .post(format!("{}/lock", url))
                    .json(lock)
                    .send()
                    .await
                    .expect("Failed to reach server");

                let lock_status = res.status();
                if lock_status.is_success() {
                    let env: L2ResponseEnvelope =
                        res.json().await.expect("Failed to parse lock response");
                    match env.verdict {
                        L2Verdict::Verified { .. } | L2Verdict::Ok { .. } => {
                            println!(
                                "    [{}/{}] ds_tag={} → [OK]",
                                start_idx + i + 1, n_locks, ds_display
                            );
                        }
                        L2Verdict::Rejected { reason } => {
                            println!(
                                "    [{}/{}] ds_tag={} → [REJECTED] {}",
                                start_idx + i + 1, n_locks, ds_display, reason
                            );
                            all_ok = false;
                            break;
                        }
                        other => {
                            println!(
                                "    [{}/{}] ds_tag={} → [WARN] {:?}",
                                start_idx + i + 1, n_locks, ds_display, other
                            );
                        }
                    }
                } else {
                    println!(
                        "    [{}/{}] ds_tag={} → [HTTP {}]",
                        start_idx + i + 1, n_locks, ds_display, lock_status
                    );
                    all_ok = false;
                    break;
                }

                let _ = t_id_display; // suppress unused warning
            }

            if all_ok {
                // offline_locks leeren, history beibehalten
                voucher.leaves[0].offline_locks.clear();
                state.save();
                println!();
                println!("  ✓ Sync complete. offline_locks cleared.");
            } else {
                println!();
                println!("  [WARN] Sync incomplete. Not all locks were accepted.");
            }
        }
        L2Verdict::Verified { lock_entry } => {
            println!(
                "  Server: [VERIFIED] Server already knows t_id={} – already synced?",
                bs58::encode(lock_entry.t_id).into_string()
            );
        }
        L2Verdict::UnknownVoucher => {
            println!("  Server: [UNKNOWN VOUCHER] – genesis not yet registered on L2.");
            println!("  Hint: Run 'genesis' first, then 'offline-transfer', then 'sync'.");
        }
        other => {
            println!("  Server: [UNEXPECTED] {:?}", other);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn test_valid_lock_request_generation() {
        let (req, key) = generate_mock_lock_request(true, None, None, None);
        let pub_key = key.verifying_key();

        let expected_challenge = bs58::encode(&req.transaction_hash).into_string();

        let payload_hash = calculate_l2_payload_hash_raw(
            &expected_challenge,
            &req.layer2_voucher_id,
            &req.transaction_hash,
            &req.sender_ephemeral_pub,
            req.receiver_ephemeral_pub_hash.as_ref(),
            req.change_ephemeral_pub_hash.as_ref(),
            req.deletable_at.as_deref(),
        );

        let d_sig = Signature::from_bytes(&req.layer2_signature);
        assert!(
            pub_key.verify(&payload_hash, &d_sig).is_ok(),
            "Client Simulator generates INVALID cryptographic signatures!"
        );
    }

    #[test]
    fn test_state_save_and_load() {
        use std::collections::HashMap;
        // Temporäre State-Datei in /tmp, um den echten State nicht zu überschreiben
        let leaf = Leaf {
            t_id_bs58: "testLeafHash123".to_string(),
            signing_key_bytes: vec![0u8; 32],
            label: "genesis".to_string(),
            history: vec![],
            offline_locks: vec![],
        };
        let mut vouchers = HashMap::new();
        vouchers.insert(
            "abc123".to_string(),
            VoucherState {
                layer2_voucher_id: "abc123".to_string(),
                leaves: vec![leaf],
            },
        );
        let state = SimulatorState { vouchers };
        let json = serde_json::to_string(&state).unwrap();
        let loaded: SimulatorState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.vouchers.len(), 1);
        assert_eq!(
            loaded.vouchers["abc123"].leaves[0].t_id_bs58,
            "testLeafHash123"
        );
    }

    #[test]
    fn test_manual_genesis_voucher_id_derivation() {
        // Prüft, dass die lokale VID-Berechnung reproduzierbar ist
        let t_id = [42u8; 32];
        let sender_pub = [7u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(t_id);
        hasher.update(sender_pub);
        let result1 = hex::encode(hasher.finalize());

        let mut hasher2 = Sha256::new();
        hasher2.update(t_id);
        hasher2.update(sender_pub);
        let result2 = hex::encode(hasher2.finalize());

        assert_eq!(result1, result2, "VID derivation must be deterministic");
        assert_eq!(result1.len(), 64, "VID must be a 64-char hex string");
    }
}
