// tests/architecture/gossip_decoupled_double_spend.rs
// cargo test --test architecture_tests gossip_decoupled_double_spend -- --nocapture
//!
//! # Integration Test: Decentralized Double-Spend Detection via Gossip Protocol
//!
//! ## Scenario
//!
//! This test verifies the P2P gossip distribution of `TransactionFingerprints` across completely
//! decoupled voucher transactions. It checks whether a double-spend that occurred in one
//! history (Voucher A) is detected and reported in `list_conflicts()` by an uninvolved
//! third party (User 4) solely through passively received fingerprints in other
//! transactions (Vouchers B and C).
//!
//! ## Importance: Offline-First "Immune System"
//!
//! This is a critical test for the system's "immune system." It demonstrates that double-spending
//! can be detected rapidly even without direct ownership of the affected vouchers. By propagating
//! transaction fingerprints via unrelated payment bundles, the network can expose fraud 
//! much faster than traditional decoupled systems, acting as a decentralized, 
//! proactive defense mechanism.
//!
//! ## Tested Behavior
//!
//! 1. **Gossip Persistence:** Received fingerprints from gossip bundles are permanently
//!    stored in `foreign_fingerprints`.
//! 2. **Decentralized Verification:** The `conflict_manager` identifies collisions as
//!    `verifiable_conflict` even when the data originates exclusively from gossip sources.
//! 3. **Soft-Proof Creation:** A `ProofOfDoubleSpend` (Gossip Soft Proof) is created for
//!    conflicts known only via gossip, even if full transaction data is not locally available.

#[cfg(test)]
mod tests {
    use human_money_core::app_service::AppService;
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::services::voucher_manager::NewVoucherData;
    use human_money_core::test_utils::{self, actors, ACTORS, FREETALER_STANDARD};
    use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
    use std::collections::HashMap;
    use tempfile::tempdir;

    const PASSWORD: &str = "gossip-test-pw";

    /// Removes an obsolete lock file before login if necessary.
    fn clear_lock(dir: &std::path::Path, folder: &str) {
        let lock = dir.join(folder).join(".wallet.lock");
        if lock.exists() {
            let _ = std::fs::remove_file(&lock);
        }
    }

    /// Creates a service with a profile, logs it out, and returns (Service, ProfileInfo).
    fn make_user(
        base: &std::path::Path,
        actor: &actors::TestUser,
        name: &str,
        pw: &str,
    ) -> (AppService, human_money_core::app_service::ProfileInfo) {
        test_utils::setup_service_with_profile(base, actor, name, pw)
    }

    /// Returns the TOML representation of the FreeTaler standard.
    fn freetaler_toml() -> String {
        toml::to_string(&FREETALER_STANDARD.0).unwrap()
    }

    /// Returns a `standards` HashMap required for `create_transfer_bundle` and `receive_bundle`.
    fn standards_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
            freetaler_toml(),
        );
        m
    }

    /// Creates a simple FreeTaler voucher for the specified user.
    fn create_voucher_for_user(service: &mut AppService, user_id: &str, pw: &str) -> String {
        let data = NewVoucherData {
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                unit: "Taler".to_string(),
                ..Default::default()
            },
            creator_profile: PublicProfile {
                id: Some(user_id.to_string()),
                ..Default::default()
            },
            non_redeemable_test_voucher: true,
            ..Default::default()
        };
        let voucher = service
            .create_new_voucher(&freetaler_toml(), "en", data, Some(pw))
            .expect("Voucher creation failed");
        voucher.voucher_id
    }

    /// Copies a directory recursively (for rollback simulation).
    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if src_path.is_dir() {
                copy_dir_recursive(&src_path, &dst_path);
            } else {
                std::fs::copy(&src_path, &dst_path).unwrap();
            }
        }
    }

    #[test]
    fn test_gossip_decoupled_double_spend_detection() {
        // =======================================================================
        // SETUP: 5 independent wallets
        // =======================================================================
        let dir = tempdir().unwrap();
        let base = dir.path();

        // Create actors (Service + ProfileInfo; currently logged out)
        let (mut user0, profile0) = make_user(base, &ACTORS.alice, "User0-Genesis", PASSWORD);
        let (mut user1, profile1) = make_user(base, &ACTORS.bob, "User1-Attacker", PASSWORD);
        let (mut user2, profile2) = make_user(base, &ACTORS.charlie, "User2-LegitRecv", PASSWORD);
        let (mut user3, profile3) = make_user(base, &ACTORS.david, "User3-ForkRecv", PASSWORD);

        // User 4: fresh account, no predefined actor
        let actor4 = actors::user_from_mnemonic_fast(
            &actors::generate_valid_mnemonic(),
            Some("u4"),
        );
        let (mut user4, profile4) = make_user(base, &actor4, "User4-Observer", PASSWORD);

        let standards = standards_map();

        // Login once to save IDs
        clear_lock(base, &profile0.folder_name);
        user0.login(&profile0.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        let user0_id = user0.get_user_id().unwrap();
        user0.logout();

        clear_lock(base, &profile1.folder_name);
        user1.login(&profile1.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        let user1_id = user1.get_user_id().unwrap();
        user1.logout();

        clear_lock(base, &profile2.folder_name);
        user2.login(&profile2.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        let user2_id = user2.get_user_id().unwrap();
        user2.logout();

        clear_lock(base, &profile3.folder_name);
        user3.login(&profile3.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        let user3_id = user3.get_user_id().unwrap();
        user3.logout();

        clear_lock(base, &profile4.folder_name);
        user4.login(&profile4.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        let user4_id = user4.get_user_id().unwrap();
        user4.logout();

        // =======================================================================
        // STEP 1: Genesis — User 0 creates Voucher A, sends to User 1
        // =======================================================================
        clear_lock(base, &profile0.folder_name);
        user0.login(&profile0.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();

        create_voucher_for_user(&mut user0, &user0_id, PASSWORD);
        let voucher_a_local_id = user0
            .get_voucher_summaries(None, None, None)
            .unwrap()[0]
            .local_instance_id
            .clone();

        println!("[Test] Step 1: user0 → user1 (Voucher A)");
        let bundle_a0 = user0
            .create_transfer_bundle(
                MultiTransferRequest {
                    recipient_id: user1_id.clone(),
                    sources: vec![SourceTransfer {
                        local_instance_id: voucher_a_local_id.clone(),
                        amount_to_send: "100".to_string(),
                    }],
                    notes: None,
                    sender_profile_name: None,
                    // FreeTaler is "flexible" — we force stealth mode
                    use_privacy_mode: Some(true),
                },
                &standards,
                None,
                Some(PASSWORD),
            )
            .unwrap()
            .bundle_bytes;
        user0.logout();

        clear_lock(base, &profile1.folder_name);
        user1.login(&profile1.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        user1.receive_bundle(&bundle_a0, &standards, None, Some(PASSWORD), false).unwrap();
        let voucher_a_at_user1 = user1
            .get_voucher_summaries(None, None, None)
            .unwrap()[0]
            .local_instance_id
            .clone();
        // Important: user1 remains logged in for the backup, but is logged out first.
        user1.logout();

        // =======================================================================
        // BACKUP before Step 2 (Rollback Point)
        // =======================================================================
        let user1_wallet_path = base.join(&profile1.folder_name);
        let user1_backup_path = base.join("user1_backup_before_step2");
        copy_dir_recursive(&user1_wallet_path, &user1_backup_path);
        println!("[Test] Backup of user1 created (before legitimate transfer)");

        // =======================================================================
        // STEP 2: Legitimate Transfer — User 1 → User 2
        // =======================================================================
        clear_lock(base, &profile1.folder_name);
        user1.login(&profile1.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();

        println!("[Test] Step 2: user1 → user2 (Voucher A, legitimate)");
        let bundle_a_legit = user1
            .create_transfer_bundle(
                MultiTransferRequest {
                    recipient_id: user2_id.clone(),
                    sources: vec![SourceTransfer {
                        local_instance_id: voucher_a_at_user1.clone(),
                        amount_to_send: "100".to_string(),
                    }],
                    notes: None,
                    sender_profile_name: None,
                    use_privacy_mode: Some(true),
                },
                &standards,
                None,
                Some(PASSWORD),
            )
            .unwrap()
            .bundle_bytes;
        user1.logout();

        clear_lock(base, &profile2.folder_name);
        user2.login(&profile2.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        user2.receive_bundle(&bundle_a_legit, &standards, None, Some(PASSWORD), false).unwrap();
        println!("[Test] user2 received Voucher A (legitimate chain)");
        user2.logout();

        // =======================================================================
        // STEP 3: Rollback & Double Spend — User 1 → User 3
        // =======================================================================
        // Rollback user1 wallet to backup (state before Step 2)
        std::fs::remove_dir_all(&user1_wallet_path).unwrap();
        copy_dir_recursive(&user1_backup_path, &user1_wallet_path);
        println!("[Test] Step 3: Rollback of user1 to state before Step 2");

        clear_lock(base, &profile1.folder_name);
        user1.login(&profile1.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();

        // After rollback: user1 has Voucher A as Active again
        let voucher_a_after_rollback = user1
            .get_voucher_summaries(None, None, None)
            .unwrap()[0]
            .local_instance_id
            .clone();

        println!("[Test] Step 3: user1 → user3 (Voucher A, Double Spend!)");
        let bundle_a_fork = user1
            .create_transfer_bundle(
                MultiTransferRequest {
                    recipient_id: user3_id.clone(),
                    sources: vec![SourceTransfer {
                        local_instance_id: voucher_a_after_rollback.clone(),
                        amount_to_send: "100".to_string(),
                    }],
                    notes: None,
                    sender_profile_name: None,
                    use_privacy_mode: Some(true),
                },
                &standards,
                None,
                Some(PASSWORD),
            )
            .unwrap()
            .bundle_bytes;
        user1.logout();

        clear_lock(base, &profile3.folder_name);
        user3.login(&profile3.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        user3.receive_bundle(&bundle_a_fork, &standards, None, Some(PASSWORD), false).unwrap();
        println!("[Test] user3 received the forked Voucher A");

        // Neither user2 nor user3 pass Voucher A along — dormant balance.
        // user3 remains logged in until after the next bundle reception.

        // =======================================================================
        // STEP 4: Decoupled Gossip, Node 1
        //         user2 creates Voucher B, sends to user4
        //         → Bundle contains fingerprints of the legitimate A-history as gossip
        // =======================================================================
        clear_lock(base, &profile2.folder_name);
        user2.login(&profile2.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();

        // user2 creates a completely independent Voucher B
        create_voucher_for_user(&mut user2, &user2_id, PASSWORD);
        let summaries = user2.get_voucher_summaries(None, None, None).unwrap();
        // The newly created Voucher B is the one where creator == user2_id
        // We filter for the one not received (status = Active, creator-TX present)
        let voucher_b_summary = summaries
            .iter()
            .find(|s| {
                let details = user2.get_voucher_details(&s.local_instance_id).unwrap();
                details
                    .voucher
                    .transactions
                    .first()
                    .and_then(|tx| tx.sender_id.as_ref())
                    .map(|sid| sid.contains(&user2_id))
                    .unwrap_or(false)
            })
            .expect("Voucher B (created by user2) not found");
        let voucher_b_local_id = voucher_b_summary.local_instance_id.clone();

        println!("[Test] Step 4: user2 → user4 (Voucher B + Gossip about A-legit)");
        let bundle_b = user2
            .create_transfer_bundle(
                MultiTransferRequest {
                    recipient_id: user4_id.clone(),
                    sources: vec![SourceTransfer {
                        local_instance_id: voucher_b_local_id.clone(),
                        amount_to_send: "100".to_string(),
                    }],
                    notes: None,
                    sender_profile_name: None,
                    use_privacy_mode: Some(true),
                },
                &standards,
                None,
                Some(PASSWORD),
            )
            .unwrap()
            .bundle_bytes;
        user2.logout();

        clear_lock(base, &profile4.folder_name);
        user4.login(&profile4.folder_name, PASSWORD, false, "test-id".to_string()).unwrap();
        user4.receive_bundle(&bundle_b, &standards, None, Some(PASSWORD), false).unwrap();
        println!("[Test] user4 received Voucher B (including gossip of legitimate A-chain)");

        // =======================================================================
        // STEP 5: Decoupled Gossip, Node 2
        //         user3 creates Voucher C, sends to user4
        //         → Bundle contains fingerprints of the forked A-history as gossip
        // =======================================================================
        // user3 creates a completely independent Voucher C
        create_voucher_for_user(&mut user3, &user3_id, PASSWORD);
        let summaries3 = user3.get_voucher_summaries(None, None, None).unwrap();
        let voucher_c_local_id = summaries3
            .iter()
            .find(|s| {
                let details = user3.get_voucher_details(&s.local_instance_id).unwrap();
                details
                    .voucher
                    .transactions
                    .first()
                    .and_then(|tx| tx.sender_id.as_ref())
                    .map(|sid| sid.contains(&user3_id))
                    .unwrap_or(false)
            })
            .expect("Voucher C (created by user3) not found")
            .local_instance_id
            .clone();

        println!("[Test] Step 5: user3 → user4 (Voucher C + Gossip about A-fork)");
        let bundle_c = user3
            .create_transfer_bundle(
                MultiTransferRequest {
                    recipient_id: user4_id.clone(),
                    sources: vec![SourceTransfer {
                        local_instance_id: voucher_c_local_id.clone(),
                        amount_to_send: "100".to_string(),
                    }],
                    notes: None,
                    sender_profile_name: None,
                    use_privacy_mode: Some(true),
                },
                &standards,
                None,
                Some(PASSWORD),
            )
            .unwrap()
            .bundle_bytes;
        user3.logout();

        user4.receive_bundle(&bundle_c, &standards, None, Some(PASSWORD), false).unwrap();
        println!("[Test] user4 received Voucher C (including gossip of forked A-chain)");

        // =======================================================================
        // ASSERTIONS
        // =======================================================================

        // --- Assert 1: Fingerprint collision exists in user4's KnownFingerprints ---
        {
            let (wallet4, _) = user4.get_unlocked_mut_for_test();

            // We expect at least one ds_tag with two different t_ids known (collision = double spend).
            let mut found_collision = false;
            let mut ds_tag_with_collision = String::new();

            let all_sources = [
                &wallet4.known_fingerprints.local_history,
                &wallet4.known_fingerprints.foreign_fingerprints,
            ];

            'outer: for source in &all_sources {
                for (ds_tag, fps) in *source {
                    let unique_t_ids: std::collections::HashSet<&String> =
                        fps.iter().map(|fp| &fp.t_id).collect();
                    if unique_t_ids.len() >= 2 {
                        found_collision = true;
                        ds_tag_with_collision = ds_tag.clone();
                        break 'outer;
                    }
                }
            }

            // Also check via combined view (different sources)
            if !found_collision {
                let mut combined: HashMap<String, std::collections::HashSet<String>> =
                    HashMap::new();
                for source in &all_sources {
                    for (ds_tag, fps) in *source {
                        let entry = combined.entry(ds_tag.clone()).or_default();
                        for fp in fps {
                            entry.insert(fp.t_id.clone());
                        }
                    }
                }
                for (ds_tag, t_ids) in &combined {
                    if t_ids.len() >= 2 {
                        found_collision = true;
                        ds_tag_with_collision = ds_tag.clone();
                        break;
                    }
                }
            }

            println!(
                "[Test] Assert 1: Fingerprint collision found: {} (ds_tag='{}')",
                found_collision,
                ds_tag_with_collision
            );

            // Debug output of known fingerprints
            println!(
                "[Test] user4 local_history entries: {}",
                wallet4.known_fingerprints.local_history.len()
            );
            println!(
                "[Test] user4 foreign_fingerprints entries: {}",
                wallet4.known_fingerprints.foreign_fingerprints.len()
            );
            for (tag, fps) in &wallet4.known_fingerprints.local_history {
                println!(
                    "[Test]   local ds_tag='{}' → {} t_ids: {:?}",
                    &tag[..tag.len().min(16)],
                    fps.len(),
                    fps.iter().map(|fp| &fp.t_id[..fp.t_id.len().min(12)]).collect::<Vec<_>>()
                );
            }
            for (tag, fps) in &wallet4.known_fingerprints.foreign_fingerprints {
                println!(
                    "[Test]   foreign ds_tag='{}' → {} t_ids: {:?}",
                    &tag[..tag.len().min(16)],
                    fps.len(),
                    fps.iter().map(|fp| &fp.t_id[..fp.t_id.len().min(12)]).collect::<Vec<_>>()
                );
            }

            assert!(
                found_collision,
                "ERROR Assert 1: user4 received no fingerprint collision. \
                 Both colliding ds_tags of the double-spend must arrive in known_fingerprints \
                 of user4 (via gossip in Bundle B and C)."
            );
        }

        // --- Assert 2: list_conflicts() shows the double-spend ---
        //
        // This verifies that check_for_double_spend() correctly classified the collision as 
        // `verifiable_conflict`, even though user4 never directly owned Voucher A. 
        // The resulting ProofOfDoubleSpend (Gossip Soft Proof) was stored in the proof_store.
        let conflicts = user4.list_conflicts().unwrap();

        println!(
            "[Test] Assert 2: list_conflicts() result: {} entries",
            conflicts.len()
        );
        for c in &conflicts {
            println!(
                "[Test]   Conflict: proof_id='{}' offender='{}'",
                &c.proof_id[..c.proof_id.len().min(16)],
                &c.offender_id[..c.offender_id.len().min(30)]
            );
        }

        assert!(
            !conflicts.is_empty(),
            "Assert 2 failed: list_conflicts() at User 4 is empty. \
             The double-spend of User 1 was not correctly extracted from gossip fingerprints \
             or stored as a conflict."
        );

        // --- Assert 3: The offender_id is the mathematically extracted did:key of User 1 ---
        //
        // The attacker (User 1) used stealth mode for all transfers, so the sender_id in
        // the transactions was "anonymous". The system must have used the mathematical
        // trap-door recovery (ID = V1 - u1 * M) to unmask the real identity.
        //
        // Since extract_id_point_from_raw_data recovers a bare public key (no prefix),
        // create_user_id(&pk, None) produces a Root-Account DID (did:key:z...) without
        // a prefix. User 1's actual ID may have a prefix, so we compare the underlying
        // Ed25519 public keys instead of raw strings.
        {
            let conflict = &conflicts[0];
            let offender_in_proof = &conflict.offender_id;

            println!(
                "[Test] Assert 3: offender_id in proof = '{}'",
                offender_in_proof
            );
            println!(
                "[Test] Assert 3: user1_id (attacker)   = '{}'",
                user1_id
            );

            // The offender must NOT be "anonymous" — the math must have unmasked them.
            assert_ne!(
                offender_in_proof, "anonymous",
                "Assert 3 failed: offender_id is still 'anonymous'. \
                 The mathematical identity recovery from trap data did not work."
            );

            // The offender_id must be a valid did:key
            assert!(
                offender_in_proof.contains("did:key:z"),
                "Assert 3 failed: offender_id '{}' is not a valid did:key format.",
                offender_in_proof
            );

            // Extract the raw Ed25519 public key from both IDs and compare.
            // The recovered DID is a Root-Account (no prefix), while user1_id may have
            // a prefix — but the underlying cryptographic identity must be identical.
            let recovered_pubkey =
                human_money_core::services::crypto_utils::get_pubkey_from_user_id(
                    offender_in_proof,
                )
                .expect("Failed to extract pubkey from recovered offender_id");

            let attacker_pubkey =
                human_money_core::services::crypto_utils::get_pubkey_from_user_id(&user1_id)
                    .expect("Failed to extract pubkey from user1_id");

            assert_eq!(
                recovered_pubkey.as_bytes(),
                attacker_pubkey.as_bytes(),
                "Assert 3 failed: The mathematically recovered public key does not match \
                 the attacker's (User 1) actual public key.\n\
                 Recovered: {:?}\n\
                 Expected:  {:?}",
                recovered_pubkey.as_bytes(),
                attacker_pubkey.as_bytes(),
            );

            println!(
                "[Test] ✅ Assert 3 PASSED: Offender identity mathematically proven. \
                 did:key matches User 1's public key."
            );
        }

        user4.logout();
    }
}
