// examples/l2_playground.rs
// run with: cargo run --example l2_playground
//!
//! Playground zur Demonstration der Layer 2 Integration und der "Chain of Authority".
//! Führt eine Sequenz von Transaktionen aus und zeigt die Verkettung im L2-Netzwerk.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use human_money_core::models::layer2_api::{
    L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;

use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::test_utils::{self, ACTORS, SILVER_STANDARD, create_custom_standard};
use std::collections::{HashMap, HashSet};
use tempfile::tempdir;

/// Eine verbesserte Simulation eines L2-Nodes, die den aktuellen UTXO-basierten Stand widerspiegelt.
pub struct MockL2Node {
    /// Simuliert den RAM-Bloom-Filter (Voucher IDs)
    pub vouchers: HashSet<String>,
    /// Simuliert die L2-Datenbank. Key: layer2_voucher_id, Value: Map von ds_tag -> L2LockEntry
    pub locks: HashMap<String, HashMap<String, human_money_core::models::layer2_api::L2LockEntry>>,
    /// Simuliert das UTXO Modell für P2PKH Anker
    pub spendable_outputs: HashSet<[u8; 32]>,
    /// Server Keypair für Signaturen
    pub signing_key: SigningKey,
}

impl MockL2Node {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Self {
            vouchers: HashSet::new(),
            locks: HashMap::new(),
            spendable_outputs: HashSet::new(),
            signing_key,
        }
    }

    pub fn get_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn wrap_and_sign(&self, verdict: L2Verdict) -> Vec<u8> {
        let verdict_serialized = serde_json::to_vec(&verdict).unwrap();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&verdict_serialized);
        let verdict_hash = hasher.finalize();

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&verdict_hash);

        let signature = self.signing_key.sign(&hash_arr);
        let envelope = L2ResponseEnvelope {
            verdict,
            server_signature: signature.to_bytes(),
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    pub fn handle_lock_request(&mut self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2LockRequest =
            serde_json::from_slice(req_bytes).expect("Failed to parse request");

        // --- 1. Autorität Prüfen (layer2_signature) ---
        let ephem_key = VerifyingKey::from_bytes(&req.sender_ephemeral_pub).expect("Invalid key");
        let signature = Signature::from_bytes(&req.layer2_signature);

        let payload_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash(&req);

        if ephem_key.verify(&payload_hash, &signature).is_err() {
            // Im Beispiel erlauben wir ungültige signaturen für schnelleres prototyping,
            // aber ein echter Node würde hier ablehnen.
        }

        // Voucher im "Bloom Filter" registrieren
        self.vouchers.insert(req.layer2_voucher_id.clone());

        let ds_tag = if req.is_genesis {
            bs58::encode(req.transaction_hash).into_string()
        } else {
            req.ds_tag.clone().unwrap_or_else(|| "genesis".to_string())
        };

        // --- 2. Double Spend Check via ds_tag ---
        let voucher_locks = self.locks.entry(req.layer2_voucher_id.clone()).or_default();
        if let Some(entry) = voucher_locks.get(&ds_tag) {
            let verdict = L2Verdict::Verified {
                lock_entry: entry.clone(),
            };
            return self.wrap_and_sign(verdict);
        }

        // Erfolg: Verankern
        let entry = human_money_core::models::layer2_api::L2LockEntry {
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            deletable_at: req.deletable_at.clone(),
        };
        voucher_locks.insert(ds_tag, entry);

        // Neue UTXOs registrieren (Empfänger und Wechselgeld)
        if let Some(r) = req.receiver_ephemeral_pub_hash {
            self.spendable_outputs.insert(r);
        }
        if let Some(c) = req.change_ephemeral_pub_hash {
            self.spendable_outputs.insert(c);
        }

        let verdict = L2Verdict::Ok {
            signature: [0u8; 64],
        };
        self.wrap_and_sign(verdict)
    }

    pub fn handle_status_query(&self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2StatusQuery = serde_json::from_slice(req_bytes).unwrap();

        // 1. Bloom Filter Check
        if !self.vouchers.contains(&req.layer2_voucher_id) {
            return self.wrap_and_sign(L2Verdict::UnknownVoucher);
        }

        let voucher_locks = self.locks.get(&req.layer2_voucher_id).unwrap();

        // 2. Direct Lookup (Challenge)
        if let Some(entry) = voucher_locks.get(&req.challenge_ds_tag) {
            let verdict = L2Verdict::Verified {
                lock_entry: entry.clone(),
            };
            return self.wrap_and_sign(verdict);
        }

        // 3. Logarithmic Locators
        for prefix in &req.locator_prefixes {
            for (ds_tag, _entry) in voucher_locks {
                if ds_tag.starts_with(prefix) {
                    let verdict = L2Verdict::MissingLocks {
                        sync_point: prefix.clone(),
                    };
                    return self.wrap_and_sign(verdict);
                }
            }
        }

        self.wrap_and_sign(L2Verdict::MissingLocks {
            sync_point: "genesis".to_string(),
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\x1b[1;36m======================================================\x1b[0m");
    println!("\x1b[1;36m   LAYER 2 INTEGRATION & CHAIN OF AUTHORITY PLAYGROUND\x1b[0m");
    println!("\x1b[1;36m======================================================\x1b[0m\n");

    let dir = tempdir()?;
    let password = "password123";
    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Alice", password);
    let user_id = app.get_user_id()?;
    let bob_id = test_utils::ACTORS.david.identity.user_id.clone();

    // Standard laden
    let (flexible_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Private;
    });
    let flexible_toml = toml::to_string(&flexible_standard)?;
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    let mut server = MockL2Node::new();

    // L2 Server Public Key in Alice's Wallet konfigurieren
    if let Some(wallet) = app.get_wallet_mut() {
        wallet.profile.l2_server_pubkey = Some(server.get_public_key());
    }

    // --- SCHRITT 1: Genesis ---
    println!("\x1b[1;33m[1/3] Genesis: Gutschein erstellen (100 Silber)\x1b[0m");
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(password),
    )?;

    let voucher_id = app.get_voucher_summaries(None, None)?[0]
        .local_instance_id
        .clone();
    let req_genesis = app.generate_l2_lock_request(&voucher_id)?;
    let resp_genesis = server.handle_lock_request(&req_genesis);
    app.process_l2_response(&voucher_id, &resp_genesis, Some(password))
        .unwrap();
    println!(
        "✅ Genesis anchored on L2. Voucher ID: \x1b[32m{}\x1b[0m\n",
        serde_json::from_slice::<L2LockRequest>(&req_genesis)?.layer2_voucher_id
    );

    // --- SCHRITT 2: Transaktion 1 ---
    println!("\x1b[1;33m[2/3] Transaktion 1: 10 Silber an Bob senden\x1b[0m");
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

    // Die neue Instanz finden (Wechselgeld)
    let v_id_1 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
        )?
        .iter()
        .find(|s| s.current_amount == "90.0000")
        .map(|s| s.local_instance_id.clone())
        .unwrap();

    let req_tx1 = app.generate_l2_lock_request(&v_id_1)?;
    let resp_tx1 = server.handle_lock_request(&req_tx1);
    app.process_l2_response(&v_id_1, &resp_tx1, Some(password))
        .unwrap();
    println!(
        "✅ TX 1 anchored on L2. DS_TAG: \x1b[32m{}\x1b[0m\n",
        serde_json::from_slice::<L2LockRequest>(&req_tx1)?
            .ds_tag
            .unwrap_or_default()
    );

    // --- SCHRITT 3: Transaktion 2 ---
    println!("\x1b[1;33m[3/3] Transaktion 2: 5 Silber an Bob senden\x1b[0m");
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

    let v_id_2 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
        )?
        .iter()
        .find(|s| s.current_amount == "85.0000")
        .map(|s| s.local_instance_id.clone())
        .unwrap();

    let req_tx2 = app.generate_l2_lock_request(&v_id_2)?;
    let resp_tx2 = server.handle_lock_request(&req_tx2);
    app.process_l2_response(&v_id_2, &resp_tx2, Some(password))
        .unwrap();
    println!(
        "✅ TX 2 anchored on L2. DS_TAG: \x1b[32m{}\x1b[0m\n",
        serde_json::from_slice::<L2LockRequest>(&req_tx2)?
            .ds_tag
            .unwrap_or_default()
    );

    // --- ANALYSE & VISUALISIERUNG ---
    println!("\x1b[1;36m======================================================\x1b[0m");
    println!("\x1b[1;36m               CHAIN OF AUTHORITY ANALYSIS            \x1b[0m");
    println!("\x1b[1;36m======================================================\x1b[0m");

    let details = app.get_voucher_details(&v_id_2)?;
    let voucher = &details.voucher;

    println!("\n\x1b[1;37mZusammenfassung der Verkettung (Lokal vs. L2):\x1b[0m\n");

    let mut active_anchors = Vec::new();

    for (i, tx) in voucher.transactions.iter().enumerate() {
        let is_genesis = tx.t_type == "init";
        let type_label = if is_genesis { "GENESIS" } else { "TRANSFER" };
        println!("\x1b[1;34m[Step {}] {}\x1b[0m", i, type_label);
        println!("  ├─ TX_ID (t_id):  {}", tx.t_id);

        // --- 1. Autorität / Input ---
        if is_genesis {
            println!("  ├─ Autorität:     \x1b[1;32mInitialer Gutschein (Kein Vorbesitzer)\x1b[0m");
        } else if let Some(sep) = &tx.sender_ephemeral_pub {
            let sep_bytes = bs58::decode(sep).into_vec()?;
            let sep_hash = human_money_core::services::crypto_utils::get_hash(&sep_bytes);

            let match_found = active_anchors.contains(&sep_hash);
            let status_indicator = if match_found {
                "\x1b[32mOK (Match mit vorherigem Output!)\x1b[0m"
            } else {
                "\x1b[31mKEIN ANKER GEFUNDEN!\x1b[0m"
            };

            println!("  ├─ Auth Key:      {} (Hash: {})", sep, sep_hash);
            println!("  ├─ CoA Link:      {}", status_indicator);
        }

        // --- 2. L2 Verankerung ---
        let current_v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(
            &voucher.transactions[0],
        )
        .unwrap();
        if let Some(td) = &tx.trap_data {
            println!("  ├─ DS_TAG (Trap): {}", td.ds_tag);

            if let Some(voucher_locks) = server.locks.get(&current_v_id) {
                // Bei Genesis nutzen wir t_id als Key, sonst ds_tag
                let lookup_key = if is_genesis {
                    tx.t_id.clone()
                } else {
                    td.ds_tag.clone()
                };

                if let Some(entry) = voucher_locks.get(&lookup_key) {
                    let l2_tid_str = bs58::encode(entry.t_id).into_string();
                    if l2_tid_str == tx.t_id {
                        println!("  ├─ L2 Status:     \x1b[32mVERANKERT (Match)\x1b[0m");
                    } else {
                        println!(
                            "  ├─ L2 Status:     \x1b[31mKONFLIKT! L2 hat id {}\x1b[0m",
                            l2_tid_str
                        );
                    }
                } else {
                    println!("  ├─ L2 Status:     \x1b[33mOFFLINE (Nicht im L2)\x1b[0m");
                }
            } else {
                println!("  ├─ L2 Status:     \x1b[33mOFFLINE (Nicht im L2)\x1b[0m");
            }
        } else if is_genesis {
            println!("  ├─ L2 Voucher ID: {}", current_v_id);

            if server.locks.contains_key(&current_v_id) {
                println!("  ├─ L2 Status:     \x1b[32mGENESIS VERANKERT\x1b[0m");
            } else {
                println!("  ├─ L2 Status:     \x1b[33mOFFLINE (Nicht im L2)\x1b[0m");
            }
        }

        // --- 3. Neue Outputs (Die Anker für die Zukunft) ---
        active_anchors.clear();
        println!("  └─ Neue Anker (Outputs):");
        if let Some(rh) = &tx.receiver_ephemeral_pub_hash {
            println!(
                "     ├─ Empfänger:  {} \x1b[33m(Wartet auf Signatur im nächsten Schritt)\x1b[0m",
                rh
            );
            active_anchors.push(rh.clone());
        }
        if let Some(ch) = &tx.change_ephemeral_pub_hash {
            println!(
                "     ├─ Wechselgeld: {} \x1b[33m(Wartet auf Signatur im nächsten Schritt)\x1b[0m",
                ch
            );
            active_anchors.push(ch.clone());
        }
        if tx.receiver_ephemeral_pub_hash.is_none() && tx.change_ephemeral_pub_hash.is_none() {
            println!("     └─ Keine neuen Private-Anker erzeugt.");
        }

        println!("");
    }

    println!("\x1b[1;37mErklärung der 'Chain of Authority' (CoA):\x1b[0m");
    println!(
        "1. Jede Transaktion generiert neue 'Ephemeral Public Keys' für Empfänger und Wechselgeld."
    );
    println!("2. Der L2-Server speichert die Hashes dieser Keys als 'spendable outputs' (UTXOs).");
    println!("3. Die nächste Transaktion muss mit dem entsprechenden privaten Key signieren.");
    println!(
        "4. Der L2-Server prüft: \n   a) Gehört die Signatur zum hinterlegten Hash?\n   b) Wurde dieser Hash schon einmal 'verbraucht' (Double Spend)?"
    );
    println!(
        "\n\x1b[1;33mHinweis:\x1b[0m In diesem Beispiel siehst du, dass Alice in Schritt 1 den 'Empfänger'-Key aus Genesis nutzt,"
    );
    println!(
        "da sie den Gutschein selbst erstellt hat. In Schritt 2 nutzt sie den 'Wechselgeld'-Key aus Schritt 1,"
    );
    println!(
        "da sie nach dem Senden an Bob den Restbetrag auf einen neuen eigenen Key (Wechselgeld) erhalten hat."
    );
    println!(
        "\nDas ermöglicht Privatsphäre (Keys sind anonym), garantiert aber die lückenlose Autorität."
    );

    Ok(())
}
