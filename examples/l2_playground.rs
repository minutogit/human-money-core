// examples/l2_playground.rs
// run with: cargo run --example l2_playground
//!
//! Playground zur Demonstration der Layer 2 Integration.
//! Führt zwei Transaktionen aus und zeigt den Vergleich zwischen
//! den lokalen Gutscheindaten (Wallet) und den im L2-Server gespeicherten Locks.

use human_money_core::app_service::AppService;
use human_money_core::models::layer2_api::{L2LockRequest, L2Verdict};
use human_money_core::models::voucher::ValueDefinition;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::models::profile::PublicProfile;
use human_money_core::test_utils::{self, ACTORS, create_custom_standard, SILVER_STANDARD};
use human_money_core::models::voucher_standard_definition::PrivacySettings;
use std::collections::HashMap;
use tempfile::tempdir;

// Eine einfache Simulation eines L2-Servers zur Anzeige der Rohdaten
pub struct L2ServerSimulation {
    // Key: ds_tag (Base58), Value: transaction_hash (Base58)
    pub locks: HashMap<String, String>,
}

impl L2ServerSimulation {
    pub fn new() -> Self {
        Self {
            locks: HashMap::new(),
        }
    }

    pub fn process_request(&mut self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2LockRequest = serde_json::from_slice(req_bytes).expect("Failed to parse request");
        
        let ds_tag_str = bs58::encode(req.ds_tag).into_string();
        let tx_hash_str = bs58::encode(req.transaction_hash).into_string();

        if self.locks.contains_key(&ds_tag_str) {
            let verdict = L2Verdict::DoubleSpend {
                conflicting_t_id: [0u8; 32], // Dummy
                proof_signature: [0u8; 64],
            };
            serde_json::to_vec(&verdict).unwrap()
        } else {
            self.locks.insert(ds_tag_str, tx_hash_str);
            let verdict = L2Verdict::Ok {
                signature: [0u8; 64],
            };
            serde_json::to_vec(&verdict).unwrap()
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== LAYER 2 INTEGRATION PLAYGROUND ===\n");

    let dir = tempdir()?;
    let password = "password123";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.test_user,
        "Alice",
        password,
    );
    let user_id = app.get_user_id()?;
    let bob_id = test_utils::ACTORS.david.identity.user_id.clone();

    // 1. Standard laden
    let (flexible_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        s.privacy = Some(PrivacySettings { mode: "flexible".to_string() });
    });
    let flexible_toml = toml::to_string(&flexible_standard)?;
    let mut standards_toml = HashMap::new();
    standards_toml.insert(flexible_standard.metadata.uuid.clone(), flexible_toml.clone());

    let mut server = L2ServerSimulation::new();

    // --- SCHRITT 1: Genesis ---
    println!("--- SCHRITT 1: Gutschein erstellen (Genesis) ---");
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile { id: Some(user_id.clone()), ..Default::default() },
            nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        },
        Some(password),
    )?;

    let voucher_id = app.get_voucher_summaries(None, None)?[0].local_instance_id.clone();
    
    // L2 Anker für Genesis
    let req_genesis = app.generate_l2_lock_request(&voucher_id)?;
    server.process_request(&req_genesis);
    println!("✅ Genesis anchored on L2.\n");

    // --- SCHRITT 2: Transaktion 1 ---
    println!("--- SCHRITT 2: Erste Transaktion (10 an Bob) ---");
    let request1 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "10".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    app.create_transfer_bundle(request1, &standards_toml, None, Some(password))?;
    
    let v_id_1 = app.get_voucher_summaries(None, Some(&[human_money_core::VoucherStatus::Active]))?
        .iter().find(|s| s.current_amount == "90.0000").map(|s| s.local_instance_id.clone()).unwrap();

    let req_tx1 = app.generate_l2_lock_request(&v_id_1)?;
    server.process_request(&req_tx1);
    println!("✅ Transaction 1 anchored on L2.\n");

    // --- SCHRITT 3: Transaktion 2 ---
    println!("--- SCHRITT 3: Zweite Transaktion (5 an Bob) ---");
    let request2 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_id,
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: v_id_1,
            amount_to_send: "5".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    app.create_transfer_bundle(request2, &standards_toml, None, Some(password))?;

    let v_id_2 = app.get_voucher_summaries(None, Some(&[human_money_core::VoucherStatus::Active]))?
        .iter().find(|s| s.current_amount == "85.0000").map(|s| s.local_instance_id.clone()).unwrap();

    let req_tx2 = app.generate_l2_lock_request(&v_id_2)?;
    server.process_request(&req_tx2);
    println!("✅ Transaction 2 anchored on L2.\n");

    // --- FINALE AUSGABE ---
    println!("======================================================");
    println!("ROHDATEN: LOKALER GUTSCHEIN (Wallet)");
    println!("======================================================");
    let details = app.get_voucher_details(&v_id_2)?;
    println!("{}", serde_json::to_string_pretty(&details.voucher)?);
    println!("\n");

    println!("======================================================");
    println!("ROHDATEN: LAYER 2 SERVER (Lock Table)");
    println!("======================================================");
    println!("Erklärung: Der Server speichert pro 'ds_tag' (Double-Spend-Tag)");
    println!("den Hash der Transaktion, die diesen Tag verbraucht hat.");
    println!("Wird ein ds_tag mit einem anderen Hash erneut eingereicht -> Double Spend!");
    println!("");
    println!("{:<50} | {:<50}", "DS_TAG (Base58)", "TRANSACTION_HASH (Base58)");
    println!("{:-<50}-|-{:-<50}", "", "");
    
    // Wir sortieren für eine stabilere Ausgabe (optional)
    let mut sorted_locks: Vec<_> = server.locks.iter().collect();
    sorted_locks.sort_by_key(|a| a.0);

    for (ds_tag, tx_hash) in sorted_locks {
        println!("{:<50} | {:<50}", ds_tag, tx_hash);
    }
    println!("======================================================\n");
    
    println!("VERGLEICHSHINWEIS:");
    println!("1. Der erste DS_TAG im Server entspricht dem Hash der Voucher-ID (Genesis).");
    println!("2. Jeder folgende DS_TAG stammt aus den 'trap_data' der vorherigen Transaktion.");
    println!("3. Die TRANSACTION_HASHES im Server stimmen exakt mit den Hashes der Transaktions-Objekte oben überein.");

    Ok(())
}
