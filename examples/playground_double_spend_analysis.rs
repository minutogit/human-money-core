// examples/playground_double_spend_analysis.rs

//! # Playground: Double-Spend Analysis
//!
//! This playground demonstrates the internal mechanics of Double-Spend Detection (DS-Tag).
//! It creates a legitimate voucher, splits it, and then simulates a double-spend attempt
//! by resetting the wallet state and spending the same voucher again to a different recipient.
//!
//! **Goal:** Prove that modifying the amount does NOT change the DS-Tag, thus preventing
//! evasion of double-spend detection.
//!
//! **Scenario:**
//! 1. Creator creates a voucher (Silver Standard).
//! 2. Creator sends 40.0000 to Alice (Transaction 1).
//! 3. **STATE RESET**: Creator 'forgets' this transaction (simulated by reloading start state).
//! 4. Creator sends 99.0000 to Bob (Transaction 2) - using the SAME input voucher!
//! 5. We compare the DS-Tags of Transaction 1 and Transaction 2.

use human_money_core::app_service::AppService;
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;
use human_money_core::services::voucher_manager::NewVoucherData;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- DOUBLE SPEND ANALYSIS PLAYGROUND ---");

    // 1. Setup Services (Creator, Alice, Bob)
    let password = "password123";
    let dir_creator_base = tempdir()?;
    let dir_alice = tempdir()?;
    let dir_bob = tempdir()?;

    // We need a persistent path for creator to simulate state reset
    let creator_storage_path = dir_creator_base.path().join("storage");
    let creator_backup_path = dir_creator_base.path().join("backup");
    fs::create_dir_all(&creator_storage_path)?;

    // -- INIT CREATOR --
    {
        let mut service_creator = AppService::new(&creator_storage_path)?;
        service_creator.create_profile(
            "Creator",
            &AppService::generate_mnemonic(12)?,
            None,
            Some("creator"),
            password,
        )?;
    } // Drop to close

    // -- INIT ALICE & BOB --
    let mut service_alice = AppService::new(dir_alice.path())?;
    service_alice.create_profile(
        "Alice",
        &AppService::generate_mnemonic(12)?,
        None,
        Some("alice"),
        password,
    )?;
    service_alice.unlock_session(password, 60)?;
    let alice_id = service_alice.get_user_id()?;

    let mut service_bob = AppService::new(dir_bob.path())?;
    service_bob.create_profile(
        "Bob",
        &AppService::generate_mnemonic(12)?,
        None,
        Some("bob"),
        password,
    )?;
    service_bob.unlock_session(password, 60)?;
    let bob_id = service_bob.get_user_id()?;

    // 2. Create Voucher (Silver Standard)
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_v1/standard.toml")?;
    let mut standards_map = HashMap::new();
    // We need to parse to get UUID
    let (std_def, _) =
        human_money_core::services::standard_manager::verify_and_parse_standard(&standard_toml)?;
    standards_map.insert(std_def.immutable.identity.uuid.clone(), standard_toml.clone());

    let voucher_id;
    let local_instance_id;

    {
        println!("DEBUG: Init creator scope (Create Voucher)");
        let mut service_creator = AppService::new(&creator_storage_path)?;

        // LOGIN
        let profiles = service_creator.list_profiles()?;
        let profile = profiles
            .iter()
            .find(|p| p.profile_name == "Creator")
            .expect("Creator profile missing");
        service_creator.login(&profile.folder_name, password, false)?;
        service_creator.unlock_session(password, 60)?; // Safe now

        let creator_id = service_creator.get_user_id()?;

        let creator_profile = PublicProfile {
            id: Some(creator_id.clone()),
            first_name: Some("Creator".to_string()),
            ..Default::default()
        };

        let voucher_data = NewVoucherData {
            nominal_value: ValueDefinition {
                unit: "Unzen".to_string(),
                amount: "100.0000".to_string(),
                ..Default::default()
            },
            creator_profile,
            ..Default::default()
        };

        let voucher =
            service_creator.create_new_voucher(&standard_toml, "de", voucher_data, None)?;
        voucher_id = voucher.voucher_id.clone();

        let summaries = service_creator.get_voucher_summaries(None, None)?;
        let summary = summaries.first().expect("Creator should have voucher");
        local_instance_id = summary.local_instance_id.clone();

        println!("✅ Voucher created. ID: {}", voucher_id);
    } // Drop to close and save

    // 3. BACKUP STATE (Before Transaction)
    println!("💾 Backing up Creator state (Before spending)...");
    copy_dir_all(&creator_storage_path, &creator_backup_path)?;

    // 4. TRANSACTION 1: Send 40 to Alice
    let tx1_json;
    {
        println!("\n➡ Transaction 1: Creator sends 40.0000 to Alice...");
        let mut service_creator = AppService::new(&creator_storage_path)?;

        // LOGIN
        let profiles = service_creator.list_profiles()?;
        let profile = profiles
            .iter()
            .find(|p| p.profile_name == "Creator")
            .expect("Creator profile missing");
        service_creator.login(&profile.folder_name, password, false)?;
        service_creator.unlock_session(password, 60)?;

        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: alice_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: local_instance_id.clone(),
                amount_to_send: "40.0000".to_string(),
            }],
            notes: Some("To Alice".to_string()),
            sender_profile_name: None,
        };

        let bundle_result = service_creator.create_transfer_bundle(
            request,
            &standards_map,
            None,
            Some(password),
        )?;

        // Alice receives
        service_alice.unlock_session(password, 60)?;
        let _ = service_alice.receive_bundle(
            &bundle_result.bundle_bytes,
            &standards_map,
            None,
            Some(password),
        )?;

        // Get the voucher from Alice to see the transaction
        let alice_summaries = service_alice.get_voucher_summaries(None, None)?;
        let alice_summary = alice_summaries.first().unwrap();
        let alice_details = service_alice.get_voucher_details(&alice_summary.local_instance_id)?;
        let tx = alice_details.voucher.transactions.last().unwrap();
        tx1_json = serde_json::to_string_pretty(tx)?;
        println!("✅ Transaction 1 successful.");
    }

    // 5. RESTORE STATE (Reset)
    println!("\n⏪ RESETTING STATE: Creator 'forgets' Transaction 1...");
    fs::remove_dir_all(&creator_storage_path)?;
    copy_dir_all(&creator_backup_path, &creator_storage_path)?;

    // 6. TRANSACTION 2: Send 99 to Bob (Double Spend)
    let tx2_json;
    {
        println!("➡ Transaction 2: Creator sends 99.0000 to Bob (Double Spend Attempt)...");
        let mut service_creator = AppService::new(&creator_storage_path)?;

        // LOGIN
        let profiles = service_creator.list_profiles()?;
        let profile = profiles
            .iter()
            .find(|p| p.profile_name == "Creator")
            .expect("Creator profile missing");
        service_creator.login(&profile.folder_name, password, false)?;
        service_creator.unlock_session(password, 60)?;

        // Check if voucher is "back"
        let summaries = service_creator.get_voucher_summaries(None, None)?;
        println!(
            "   Creator wallet has {} vouchers (should be 1).",
            summaries.len()
        );

        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: bob_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: local_instance_id.clone(), // Same ID!
                amount_to_send: "99.0000".to_string(),        // DIFFERENT Amount!
            }],
            notes: Some("To Bob".to_string()),
            sender_profile_name: None,
        };

        let bundle_result = service_creator.create_transfer_bundle(
            request,
            &standards_map,
            None,
            Some(password),
        )?;

        // Bob receives
        service_bob.unlock_session(password, 60)?;
        let _ = service_bob.receive_bundle(
            &bundle_result.bundle_bytes,
            &standards_map,
            None,
            Some(password),
        )?;

        let bob_summaries = service_bob.get_voucher_summaries(None, None)?;
        let bob_summary = bob_summaries.first().unwrap();
        let bob_details = service_bob.get_voucher_details(&bob_summary.local_instance_id)?;
        let tx = bob_details.voucher.transactions.last().unwrap();
        tx2_json = serde_json::to_string_pretty(tx)?;
        println!("✅ Transaction 2 successful (locally).");
    }

    // 7. COMPARISON & ANALYSIS
    println!("\n--- ANALYSIS: Comparing Transactions ---");

    println!("\n[Transaction 1 (Alice, 40.00)]");
    println!("{}", tx1_json);

    println!("\n[Transaction 2 (Bob, 99.00)]");
    println!("{}", tx2_json);

    let tx1: human_money_core::models::voucher::Transaction = serde_json::from_str(&tx1_json)?;
    let tx2: human_money_core::models::voucher::Transaction = serde_json::from_str(&tx2_json)?;

    let ds_tag1 = tx1.trap_data.unwrap().u;
    let ds_tag2 = tx2.trap_data.unwrap().u;

    println!("\n🔍 DS-Tag Comparison:");
    println!("   Tag 1: {}", ds_tag1);
    println!("   Tag 2: {}", ds_tag2);

    if ds_tag1 == ds_tag2 {
        println!("\n✅ SUCCESS: DS-Tags are IDENTICAL!");
        println!(
            "   Even though the amounts (40.00 vs 99.00) and recipients (Alice vs Bob) are different,"
        );
        println!("   the cryptographic tag identifying the spent input is the same.");
        println!("   The network will reject the second transaction as a Double Spend.");
    } else {
        println!("\n❌ FAILURE: DS-Tags differ!");
    }

    Ok(())
}
