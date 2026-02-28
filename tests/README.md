## tests/README.md

This document provides an overview of the integration and unit tests within the `tests/` directory, detailing the purpose of each test file and the individual tests contained within them.

---

## Robustheit & Mutation Testing

Um die Robustheit unserer Test-Suite gegen logische Fehler zu validieren, nutzen wir `cargo-mutants`. Diese Methode hilft dabei, "Regressions-Lücken" zu finden, die dann durch gezielte Integritäts-Tests (siehe `tests/validation/logic_integrity.rs`) geschlossen werden.

### Durchführung
Nutze das bereitgestellte Automatisierungs-Skript:
```bash
./scripts/run_mutation_tests.sh
```
Dieses Skript prüft gezielt die Module `trap_manager`, `voucher_validation` und `transaction_handler`.

---

### `tests/wallet_api/hostile_bundles.rs`
This file contains tests that harden the `AppService` against receiving hostile or internally inconsistent voucher bundles.

-   `testauf _rejection_of_broken_transaction_chain`: Checks that a received bundle with a broken transaction chain (incorrect `prev_hash`) is rejected.
-   `test_rejection_of_inconsistent_split_math`: Checks that a bundle with a "split" transaction where amounts do not sum up correctly to the previous balance is rejected.
-   `test_rejection_of_self_received_bundle`: Ensures that a bundle created for another recipient cannot be processed by the sender themselves.
-   `test_rejection_of_identical_bundle_replay`: Verifies that an identical bundle received again is rejected based on its bundle ID (Layer 1 replay protection).
-   `test_rejection_of_voucher_replay_in_new_bundle`: Ensures that a voucher already received cannot be replayed in a *new* bundle (Layer 2 fingerprint protection).
-   `test_rejection_of_bundle_for_different_prefix_same_identity`: Verifies that a bundle sent to a different prefix (e.g., "mobil") of the same identity is rejected by a wallet with another prefix (e.g., "pc"), enforcing Separated Account Identity (SAI).

### `tests/wallet_api/hostile_standards.rs`
This file contains tests that harden the system against hostile or logically inconsistent voucher standard definitions.

-   `test_disallowed_transaction_type`: Ensures that a transfer fails if the transaction type (`split`) is not allowed by the standard.
-   `test_violation_of_max_creation_validity`: Ensures that voucher creation fails if the specified validity duration exceeds the maximum duration defined in the standard.

### `tests/wallet_api/lifecycle_and_data.rs`
This file contains robustness tests for critical `AppService` functions related to lifecycle (creation, login, recovery) and generic data encryption.

-   `test_data_encryption_workflow`: Verifies the complete "happy path" of the generic data storage, ensuring data can be saved and loaded correctly.
-   `test_data_encryption_fails_when_locked`: Stellt sicher, dass im `Locked`-Zustand kein Zugriff auf sensible Daten möglich ist.
-   `test_data_encryption_fails_with_wrong_password`: Verifies that data storage operations fail with the wrong password.
-   `test_create_profile_fails_with_invalid_mnemonic`: Ensures that profile creation fails with an invalid mnemonic phrase.
-   `test_login_fails_with_wrong_password`: Tests the most common error case during login, ensuring it fails with the wrong password.
-   `test_recovery_preserves_wallet_data`: Ensures that password recovery preserves existing wallet contents.
-   `test_session_unlock_session_success`: Tests unlocking a session with the correct password.
-   `test_session_unlock_session_fail`: Tests that unlocking a session fails with the wrong password.
-   `test_session_mode_a_action_succeeds_with_password_only`: Tests that mode A actions succeed when providing the correct password.
-   `test_session_mode_a_action_fails_with_wrong_password`: Tests that mode A actions fail with the wrong password.
-   `test_session_mode_b_action_fails_without_session`: Tests that mode B actions fail without an active session.
-   `test_session_mode_b_action_succeeds_with_session`: Tests that mode B actions succeed with an active session.
-   `test_session_mode_b_timeout`: Tests that sessions timeout after the specified duration.
-   `test_session_mode_b_refresh_activity_sliding_window`: Tests that session activity refreshes the timeout using a sliding window.
-   `test_session_mode_b_action_refreshes_session`: Tests that performing actions refreshes the session timeout.
-   `test_session_mode_b_lock_session_works`: Tests that locking the session manually prevents mode B actions.
 -   `test_session_mode_a_overrides_mode_b_succeeds`: Tests that mode A overrides mode B when both are possible.
 -   `test_session_mode_a_wrong_password_fails_even_if_mode_b_is_active`: Tests that wrong password in mode A fails even if a mode B session is active.
 -   `test_refresh_fails_on_expired_session`: Tests that attempting to refresh an expired session fails and clears the session cache.
 -   `test_logout_clears_active_session_immediately`: Tests that logging out immediately clears the active session and locks the wallet.

### `tests/wallet_api/transactionality.rs`
This file contains integration tests that ensure all state-changing operations of the `AppService` are atomic. An operation must either be fully successful (including saving) or leave the in-memory state as if it had never been executed.

-   `test_transfer_bundle_is_transactional_on_save_failure`: Ensures that `create_transfer_bundle` does not alter the in-memory state of the wallet if a save operation fails.
-   `test_receive_bundle_is_transactional_on_save_failure`: Ensures that `receive_bundle` does not leave the new voucher in the wallet's in-memory state if a save operation fails.
-   `test_attach_signature_is_transactional_on_save_failure`: Ensures that `process_and_attach_signature` does not change the in-memory voucher state (status, signature count) if a save operation fails.
-   `test_import_endorsement_is_transactional_on_save_failure`: Ensures that `import_resolution_endorsement` does not modify the in-memory conflict proof if a save operation fails.
-   `test_receive_bundle_is_transactional_on_conflict_and_save_failure`: Ensures that `receive_bundle` completely resets the state if a conflict occurs and a subsequent save operation fails.

### `tests/wallet_api/state_management.rs`
This file contains integration tests for complex state management and the handling of conflicts such as double-spending.

-   `api_app_service_full_conflict_resolution_workflow`: Tests the complete "happy path" of conflict resolution via the `AppService`, including creating a proof, creating an endorsement, and importing it.
-   `api_app_service_conflict_api_fails_when_locked`: Ensures that all conflict API methods fail when the wallet is locked.
-   `api_wallet_reactive_double_spend_earliest_wins`: Tests reactive double-spend detection using the "Earliest Wins" heuristic, where the earlier transaction is kept active and the later one is quarantined.
-   `api_wallet_reactive_double_spend_identical_timestamps`: Tests conflict detection when competing transactions have identical timestamps, ensuring a deterministic tie-breaking mechanism is applied.
-   `api_wallet_save_and_load_fidelity`: Verifies that the entire state of a wallet can be saved and restored losslessly, including active and archived vouchers and bundle metadata.
-   `test_create_voucher_adds_exactly_one_instance`: Verifies that `create_new_voucher` adds exactly one voucher instance to the wallet.
-   `test_create_voucher_is_transactional_on_save_failure`: Ensures that `create_new_voucher` is transactional, meaning a failed save operation does not leave the in-memory state "dirty."
-   `test_concurrent_app_service_causes_stale_state_double_spend`: Tests that concurrent access to the same wallet by multiple `AppService` instances is prevented by the pessimistic file-based locking mechanism using PID checking, avoiding stale state double-spending vulnerabilities. This test was previously ignored due to the security gap and has been re-enabled after implementing the locking.

### `tests/wallet_api/signature_workflows.rs`
This file contains integration tests specifically for signature workflows, controlled via the `AppService` and `Wallet` facades. This includes requesting, creating, and attaching signatures.

-   `api_wallet_full_signature_workflow`: Tests the complete signature workflow via the `Wallet` facade, from requesting a signature to attaching it, and verifies the voucher's validation status.
-   `api_wallet_signature_fail_wrong_recipient`: Ensures that a `SecureContainer` cannot be opened by an unintended recipient.
-   `api_wallet_signature_fail_tampered_container`: Ensures that a manipulated `SecureContainer` is rejected due to an authentication error (AEAD).
-   `api_wallet_signature_fail_mismatched_voucher_id`: Ensures that processing fails if a signature refers to an unknown voucher ID.
-   `api_wallet_signature_fail_wrong_payload_type`: Ensures that processing fails if the payload type of the container is not the expected type for signature attachment.
-   `api_app_service_full_signature_workflow`: Tests the complete signature workflow via the `AppService` facade, including requesting, creating, and attaching signatures.
-   `api_wallet_signature_roundtrip_minuto_required`: Tests the signature roundtrip for a standard that requires signatures (Minuto), verifying the status transition from `Incomplete` to `Active`.
-   `test_full_guarantor_workflow_via_app_service`: Tests the full guarantor workflow via the `AppService` facade, specifically the status transition from `Incomplete` to `Active` after all required signatures are attached.
-   `api_wallet_signature_roundtrip_silver_optional`: Tests the signature roundtrip for a standard with optional signatures (Silver), verifying that an optional signature can be successfully attached.

### `tests/architecture/hardening.rs`
This file contains "hardening tests" that verify the robustness of the architecture in edge cases and during consistency checks.

-   `test_cleanup_synchronizes_stores`: Verifies that the cleanup process correctly removes expired fingerprints from both `known_fingerprints.local_history` and `fingerprint_metadata` stores simultaneously.
-   `test_recovery_handles_split_transaction_chain`: Ensures that during wallet recovery, the `depth` values for a split transaction chain are correctly initialized, reflecting the chronological order of transactions.
-   `test_operations_on_empty_wallet_do_not_panic`: Confirms that maintenance operations (like cleanup and rebuilding derived stores) on a brand new, empty wallet execute without panicking and leave the wallet in a consistent empty state.

### `tests/wallet_api/general_workflows.rs`
This file contains integration tests for the primary, non-signature-related end-to-end workflows, handled via the `AppService` and `Wallet` facades.

-   `api_app_service_full_lifecycle`: Simulates the entire user lifecycle via `AppService`, including profile creation, login/logout, voucher creation, and a full transfer to another user, verifying balances and archived states.
-   `api_app_service_lifecycle_with_passphrase`: Tests the `AppService` lifecycle when a BIP39 passphrase is used, ensuring recovery fails without the passphrase and succeeds with it.
-   `api_app_service_mnemonic_helpers`: Tests the static mnemonic helper functions of `AppService`, including generation and validation of mnemonic phrases.
-   `api_app_service_password_recovery`: Tests the password recovery function of `AppService`, ensuring it works with the correct mnemonic and invalidates the old password.
-   `api_app_service_password_recovery_with_passphrase`: Tests password recovery specifically for a wallet created with a passphrase, ensuring the passphrase is required for successful recovery.
-   `api_wallet_lifecycle`: Tests the basic lifecycle of the `Wallet`: creation, saving, and loading, verifying that the loaded user ID matches the original.
-   `api_wallet_transfer_full_amount`: Tests a full transfer of the entire voucher amount, ensuring the sender's voucher is archived and the recipient receives an active voucher.
-   `api_wallet_transfer_split_amount`: Tests a partial transfer (split), ensuring the sender retains a new active voucher with the remainder and the recipient receives an active voucher with the transferred amount.
-   `api_wallet_transfer_invalid_amount`: Ensures that transfers with invalid amounts (e.g., negative, excessive precision) fail.
-   `api_wallet_transfer_inactive_voucher`: Ensures that transfers are only possible with `Active` vouchers, rejecting attempts with `Quarantined` vouchers.
-   `api_wallet_proactive_double_spend_prevention`: Tests proactive double-spend prevention in the `Wallet`, ensuring that an attempt to re-send an already spent voucher fails with `VoucherNotFound`.
-   `api_wallet_create_voucher_and_get_id`: Tests the creation of a new voucher directly in the wallet and verifies that `get_user_id` returns the correct ID and the voucher is active with the correct amount.
-   `api_wallet_query_total_balance`: Tests the correct balance calculation across multiple currencies, ensuring only active vouchers are considered.
-   `api_wallet_rejects_invalid_bundle`: Ensures that the wallet rejects a bundle containing an invalid voucher (e.g., one violating content rules), leaving the recipient's wallet empty.
-   `api_app_service_get_voucher_details_returns_correct_data`: Tests that `get_voucher_details` returns the correct and complete information for a voucher, including its status, content, nominal value, and transactions.
-   `api_wallet_transfer_multi_source`: Tests a multi-source transfer, where funds from multiple vouchers are bundled into a single transaction, verifying remaining amounts for the sender and total balance for the recipient.

### `tests/core_logic/security/double_spend.rs`
This file contains tests for the detection and handling of double-spend scenarios.

-   `test_fingerprint_generation`: Verifies that transaction fingerprints are correctly generated for `init` and `transfer` transactions, including the `valid_until` date rounded to the end of the month.
-   `test_fingerprint_exchange`: Tests the exchange of fingerprints between wallets, ensuring that foreign fingerprints are imported correctly and duplicates are not re-imported.
-   `test_conflict_classification`: Verifies that the wallet correctly classifies conflicts as either "verifiable" (if the user possesses a conflicting voucher) or "unverifiable" (if only foreign fingerprints indicate a conflict).
-   `test_cleanup_expired_fingerprints`: Ensures that expired fingerprints are correctly removed from both local history and foreign fingerprints stores during cleanup.
-   `test_proactive_double_spend_prevention_and_self_healing_in_appservice`: Tests the `AppService`'s proactive double-spend prevention and self-healing mechanism, ensuring that a replayed voucher attempt is blocked and the inconsistent voucher is quarantined.
-   `test_local_double_spend_detection_lifecycle`: Tests the full lifecycle of local double-spend detection, from initial transfer, through a malicious double-spend, to the detection and resolution using the "Earliest Wins" rule when the conflicting vouchers return to the original sender.

### `tests/architecture/resilience_and_gossip.rs`
This file tests the core functions of the new architecture: Resilience (cleanup and recovery) and Gossip (correct propagation and updating of fingerprint metadata).

-   `test_cleanup_phase1_removes_expired_fingerprints`: Verifies that the first phase of storage cleanup correctly removes expired fingerprints from the `known_fingerprints.local_history` store.
-   `test_cleanup_phase2_removes_by_depth_and_tie_breaker`: Ensures that the second phase of cleanup removes fingerprints based on `depth` and a tie-breaking mechanism when the store size exceeds a limit.
-   `test_recovery_rebuilds_from_vouchers_if_metadata_missing`: Confirms that if `fingerprint_metadata.enc` is missing, the wallet can successfully rebuild this metadata from existing vouchers during recovery.
-   `test_recovery_rebuilds_if_fingerprint_stores_missing`: Ensures that if `own_fingerprints.enc` and `known_fingerprints.enc` are missing, the wallet can rebuild these stores from existing vouchers during recovery.
-   `test_recovery_initializes_depth_correctly`: Verifies that during wallet recovery, the `depth` of transactions in a chain is correctly initialized (0 for newest, increasing for older transactions).
-   `test_min_merge_rule_updates_depth`: Tests the "min merge rule" for fingerprint metadata, ensuring that a lower `depth` from an incoming bundle correctly updates the local metadata.
-   `test_min_merge_rule_keeps_lower_local_depth`: Ensures that if the local `depth` is already lower than an incoming `depth` from a bundle, the local lower `depth` is retained.
-   `test_implicit_marking_on_send`: Verifies that when a voucher is sent, the recipient's short hash is implicitly marked in the sender's `known_by_peers` metadata for the relevant fingerprint.
-   `test_selection_heuristic_prioritizes_low_depth`: Tests the fingerprint selection heuristic, ensuring it prioritizes sending fingerprints with lower `depth` values.
-   `test_selection_heuristic_skips_known_peers`: Ensures that the fingerprint selection heuristic skips sending fingerprints to peers who are already known to have that fingerprint.
-   `test_selection_heuristic_fills_contingent`: Verifies that the fingerprint selection heuristic fills the contingent size exactly, even if more fingerprints are available.

### `tests/persistence/file_storage.rs`
This file contains integration tests for the refactored profile and voucher store management, including password recovery logic and edge cases.

-   `test_wallet_creation_save_and_load`: Tests the creation, saving, and loading of a wallet, verifying that the loaded user ID matches the original and that loading with a wrong password fails.
-   `test_password_recovery_and_reset_with_data`: Tests the password recovery and reset functionality, ensuring that wallet data (including vouchers) is preserved and that login with the old password fails while the new one succeeds.
-   `test_load_with_missing_voucher_store`: Ensures that loading a wallet succeeds even if the `vouchers.enc` file is missing, resulting in an an empty voucher store.
-   `test_load_from_corrupted_profile_file`: Verifies that loading a wallet fails with an `InvalidFormat` error if the `profile.enc` file is corrupted.
-   `test_empty_password_handling`: Tests saving and loading a wallet with an empty password, ensuring it works correctly and that loading with a non-empty wrong password fails.
-   `test_save_and_load_arbitrary_data`: Tests the saving and loading of arbitrary encrypted data, verifying data integrity, file existence, and error handling for wrong passwords or non-existent data.
-   `test_save_and_load_with_bundle_history`: Tests saving and loading a wallet that includes bundle history metadata, ensuring that transfer operations and their associated data are preserved across save/load cycles.
-   `test_storage_reentrancy_same_process`: Tests that the same process can re-acquire the wallet lock without deadlocking, ensuring re-entrancy safety.

### `tests/validation/unit_service.rs`
This file contains unit tests for the individual, data-driven functions of the validation engine in the `voucher_validation` service.

-   `test_validate_transaction_count_when_valid_then_succeeds`: Verifies that `validate_transaction_count` succeeds when the number of transactions is within the allowed range (min and max).
-   `test_validate_content_rules_when_content_is_valid_then_succeeds`: Ensures that `validate_content_rules` succeeds when voucher content adheres to all defined rules (fixed values, allowed values, regex patterns).
-   `test_validate_content_rules_when_fixed_field_is_wrong_then_fails`: Verifies that `validate_content_rules` fails when a fixed field in the voucher does not match the expected value in the standard.
-   `test_validate_content_rules_when_value_is_disallowed_then_fails`: Ensures that `validate_content_rules` fails when a field's value is not in the allowed list defined by the standard.
-   `test_validate_content_rules_when_regex_mismatches_then_fails`: Verifies that `validate_content_rules` fails when a field's value does not match the specified regex pattern.
-   `test_validate_field_group_rules_when_counts_are_correct_then_succeeds`: Ensures that `validate_field_group_rules` succeeds when the counts of values within a field group (e.g., gender in signatures) meet the specified min/max requirements.
-   `test_validate_field_group_rules_when_value_count_is_wrong_then_fails`: Verifies that `validate_field_group_rules` fails when the count of a specific value within a field group is outside the allowed min/max range.
-   `test_validate_field_group_rules_when_other_values_exist_but_required_are_met_then_succeeds`: Ensures that `validate_field_group_rules` succeeds even if other values exist in a field group, as long as the required counts for specified values are met.
-   `test_validate_field_group_rules_when_path_is_not_found_then_fails`: Verifies that `validate_field_group_rules` fails with `PathNotFound` if the specified field path does not exist in the JSON.
-   `test_validate_field_group_rules_when_path_is_not_an_array_then_fails`: Ensures that `validate_field_group_rules` fails with `InvalidDataType` if the specified path is not an array when an array is expected.
-   `test_diagnose_signature_json_structure`: A diagnostic test to verify the exact JSON structure of `VoucherSignature` and confirm correct path resolution for nested fields like `details.gender`.

### `tests/validation/standard_definition.rs`
This file contains all tests for verifying voucher standard definitions (TOML), their correct integration into the voucher, and hardening tests.

-   `test_verify_standard_when_toml_is_valid_then_succeeds`: Checks that `verify_and_parse_standard` successfully parses and cryptographically verifies a valid TOML standard file.
-   `test_verify_standard_when_content_is_tampered_then_fails`: Ensures that `verify_and_parse_standard` fails with `InvalidSignature` if the content of the TOML standard is tampered with.
-   `test_verify_standard_when_signature_block_is_missing_then_fails`: Verifies that `verify_and_parse_standard` fails with `MissingSignatureBlock` if the signature block is absent from the TOML.
-   `test_verify_standard_when_signature_is_from_wrong_issuer_then_fails`: Ensures that `verify_and_parse_standard` fails with `InvalidSignature` if the standard is signed by an unauthorized issuer.
-   `test_verify_standard_when_issuer_id_is_malformed_then_fails`: Checks that `verify_and_parse_standard` fails if the issuer ID in the signature block is malformed.
-   `test_get_localized_text_when_direct_match_exists_then_returns_it`: Tests `get_localized_text` to ensure it returns the directly matching localized text.
-   `test_get_localized_text_when_no_match_then_falls_back_to_english`: Verifies that `get_localized_text` falls back to the English text if no direct language match is found.
-   `test_get_localized_text_when_no_english_then_falls_back_to_first`: Ensures that `get_localized_text` falls back to the first available text if neither a direct match nor an English translation is found.
-   `test_validate_voucher_when_standard_hash_mismatches_then_fails`: Checks that `validate_voucher_against_standard` fails if the embedded standard hash in the voucher does not match the hash of the provided standard definition.
-   `test_create_voucher_when_lang_preference_is_set_then_uses_correct_localized_text`: Verifies that `create_voucher` uses the correct localized text from the standard template based on the `lang_preference`.
-   `test_create_transaction_when_standard_is_wrong_then_fails`: Ensures that `create_transaction` fails if the voucher's standard UUID does not match the provided standard.
-   `test_verify_standard_when_signature_string_is_invalid_base58_then_fails`: Checks that `verify_and_parse_standard` fails with `SignatureDecode` if the signature string is not valid Base58.
-   `test_verify_standard_when_signature_string_is_empty_then_fails`: Ensures that `verify_and_parse_standard` fails with `SignatureDecode` if the signature string is empty.
-   `test_parse_standard_when_field_types_are_mismatched_then_fails`: Verifies that `verify_and_parse_standard` fails with a TOML parsing error if field types in the TOML are mismatched.
-   `test_create_voucher_when_standard_template_is_incomplete_then_fails`: Ensures that `create_voucher` fails if the standard template is incomplete (e.g., missing a required unit).

### `tests/validation/forward_compatibility.rs`
This file ensures that the library is robust against future changes to data structures (forward compatibility).

-   `test_validate_voucher_with_unknown_fields_in_json_then_succeeds`: Ensures that `validate_voucher_against_standard` succeeds even if the voucher JSON contains unknown fields, demonstrating forward compatibility.
-   `test_validate_voucher_when_t_type_is_unknown_then_fails`: Verifies that `validate_voucher_against_standard` fails if a transaction has an unknown `t_type` (e.g., "merge"), indicating a violation of allowed transaction types.
-   `test_parse_standard_with_unknown_fields_in_toml_then_succeeds`: Checks that `toml::from_str` can successfully parse a standard TOML string even if it contains unknown fields, demonstrating forward compatibility for standard definitions.

### `tests/validation/logic_integrity.rs`
This file contains deep integrity tests for the core validation logic, specifically hardening the system against subtle edge cases and potential logical regression.

-   `test_valid_until_matches_creation_date`: Verifies that a voucher is valid even if `valid_until` is exactly equal to its `creation_date`.
-   `test_transaction_type_validation`: Ensures that only allowed transaction types (e.g., `init`, `transfer`, `split`) are accepted and invalid ones are rejected.
-   `test_signature_count_limits`: Verifies that the number of additional signatures is within the bounds defined by the standard.
-   `test_transaction_amount_precision`: Ensures that transaction amounts (and remaining amounts) do not exceed the decimal precision allowed by the standard.
-   `test_transaction_monotonic_time`: Verifies that all transactions in a chain have strictly monotonic (strictly increasing) timestamps.
-   `test_p2pkh_recipient_match`: Ensures that the recipient of a transaction matches the sender of the subsequent transaction in a P2PKH chain.
-   `test_p2pkh_change_output_verification`: Verifies correctly linked ephemeral public keys when spending change from a previous transaction.
-   `test_p2pkh_recipient_id_fallback`: Tests the fallback logic for verifying ownership using the recipient's public ID.
-   `test_p2pkh_sender_id_fallback`: Tests the fallback logic for verifying change-spending using the sender's public ID.
-   `test_p2pkh_hash_fallback_match`: Verifies that ownership can be proven via hash matching of ephemeral keys when explicit IDs are not used.
-   `test_trap_data_privacy_validation`: Teats that TrapData does not leak sensitive information like emails or system paths in its `blinded_id`.
-   `test_balance_attribution_logic`: Verifies the heuristic used to attribute unspent funds correctly to a user's balance.
-   `test_init_transaction_party_rules`: Ensures that for `init` transactions, both sender and recipient are correctly identified as the creator.
-   `test_p2pkh_identity_match_isolation`: Verifies that identity-based fallback correctly handles cases where cryptographic hash-linkage is deliberately sabotaged.

### `tests/validation/business_rules.rs`
This file contains integration tests that verify the correct application of complex business rules and the logical consistency of a `Voucher` object.

-   `test_validate_voucher_when_standard_uuid_mismatches_then_fails`: Ensures that `validate_voucher_against_standard` fails if the voucher's standard UUID does not match the provided standard.
-   `test_validate_voucher_when_date_logic_is_invalid_then_fails`: Verifies that `validate_voucher_against_standard` fails if the voucher's `valid_until` date is before its `creation_date`, indicating invalid date logic.
-   `test_validate_voucher_when_amount_string_is_malformed_then_fails`: Ensures that `validate_voucher_against_standard` fails if a transaction's amount string is malformed (e.g., "not-a-number").
-   `test_validate_voucher_when_transaction_time_order_is_invalid_then_fails`: Checks that `validate_voucher_against_standard` fails if transactions in the chain are not in chronological order.
-   `test_validate_voucher_when_transaction_count_exceeds_max_then_fails`: Verifies that `validate_voucher_against_standard` fails if the number of transactions exceeds the maximum allowed by the standard.
-   `test_validate_voucher_when_count_and_group_rules_conflict_then_fails_correctly`: Ensures that `validate_voucher_against_standard` correctly identifies and fails due to conflicts between `counts` rules and `field_group_rules` (e.g., too many guarantors of a specific role).
-   `test_validate_voucher_when_mandatory_signature_is_missing_then_fails`: Checks that `validate_voucher_against_standard` fails if a mandatory signature (e.g., "Official Approver") is missing.
-   `test_validate_voucher_when_signature_description_mismatches_then_fails`: Verifies that `validate_voucher_against_standard` fails if a signature's role description does not match the required description in the standard.
-   `test_validate_voucher_when_signature_description_is_correct_then_succeeds`: Ensures that `validate_voucher_against_standard` succeeds when a signature's role description and signer ID correctly match the requirements in a custom standard.
-   `test_validate_voucher_when_validity_is_too_long_then_fails`: Checks that `validate_voucher_against_standard` fails if the voucher's `valid_until` date exceeds the maximum allowed validity duration defined in the standard.
-   `test_validate_voucher_when_decimal_places_are_invalid_then_fails`: Verifies that `validate_voucher_against_standard` fails if the nominal value or a transaction amount has more decimal places than allowed by the standard.
-   `test_validate_voucher_when_full_transfer_amount_mismatches_then_fails`: Ensures that `validate_voucher_against_standard` fails if a "transfer" transaction (intended to transfer the full amount) has an amount that does not match the remaining spendable balance.
-   `test_create_transaction_when_voucher_is_not_divisible_then_fails_on_split`: Checks that `create_transaction` fails with `VoucherNotDivisible` if a split transaction is attempted on a non-divisible voucher.
-   `test_create_transaction_when_type_is_not_allowed_then_fails`: Verifies that `create_transaction` fails if the attempted transaction type (e.g., "transfer") is not allowed by the standard's behavior rules.
-   `test_gatekeeper_blocks_creation_of_too_short_voucher`: Tests the "Gatekeeper" function, ensuring that `create_voucher` blocks the creation of a voucher if its validity duration is shorter than the minimum required by the standard.
-   `test_firewall_blocks_expired_issuance_to_third_party`: Tests the "Firewall" function, ensuring that `create_transaction` blocks a transfer from the creator to a third party if the voucher's remaining validity is less than the minimum required by the standard.
-   `test_firewall_allows_internal_creator_transfer_when_expired`: Verifies that the "Firewall" allows internal transfers between different prefixes of the same creator, even if the voucher's remaining validity is below the minimum.
-   `test_firewall_allows_non_creator_transfer_when_expired`: Ensures that the "Firewall" allows transfers from a non-creator to a third party, even if the voucher's remaining validity is below the minimum (the rule only applies to the original creator).
-   `test_firewall_allows_valid_issuance_to_third_party`: Checks that the "Firewall" allows a transfer from the creator to a third party if the voucher's remaining validity meets the minimum requirement.
-   `test_firewall_allows_transfer_if_rule_is_undefined`: Verifies that the "Firewall" allows a transfer if the `issuance_minimum_validity_duration` rule is not defined in the standard.
-   `test_creator_as_guarantor_attack_fails`: Ensures that a creator cannot act as a guarantor for their own voucher, preventing a specific type of self-endorsement attack.

### `tests/services/utils.rs`
This file bundles tests for various utility functions and low-level services, such as date calculations and the generation of local instance IDs.

-   `test_iso8601_duration_date_math_correctness`: Verifies the correctness of ISO 8601 duration date calculations, especially for edge cases like month rollovers and leap years.
-   `test_round_up_date_logic`: Tests the logic for rounding up dates to the end of the day, month, or year.
-   `test_chronological_validation_with_timezones`: Ensures that chronological validation correctly identifies transactions with timestamps that are out of order (e.g., an `init` transaction before the voucher's creation date).
-   `test_local_id_for_initial_creator`: Tests that the `local_instance_id` for the initial creator is correctly calculated based on the `init` transaction.
-   `test_local_id_after_full_transfer`: Verifies that the `local_instance_id` for both the recipient and the archived sender is correctly calculated after a full transfer, based on the transfer transaction.
-   `test_local_id_after_split`: Tests that the `local_instance_id` for both the sender (with remainder) and the recipient (of the partial amount) is correctly calculated after a split transaction.
-   `test_local_id_for_non_owner`: Ensures that `calculate_local_instance_id` returns an error if the specified user has never owned the voucher.
-   `test_local_id_changes_on_round_trip`: Verifies that the `local_instance_id` changes when a voucher is sent away and then received back by the original owner, reflecting the new transaction history.

### `tests/services/crypto.rs`
This file bundles all cryptographic tests, including the logic for the Secure Container and general crypto utility functions.

-   `test_multi_recipient_secure_container`: Tests the functionality of a secure container with multiple recipients, ensuring that all intended recipients can open it and unauthorized users cannot.
-   `test_sender_can_reopen_container`: Verifies that the sender of a secure container can also reopen it later, demonstrating the "Double Key Wrapping" mechanism.
-   `test_generate_mnemonic`: Tests the generation of BIP39 mnemonic phrases, ensuring they are not empty.
-   `test_derive_ed25519_keypair`: Tests the derivation of Ed25519 key pairs from a mnemonic, verifying key lengths.
-   `test_validate_mnemonic`: Tests the validation of BIP39 mnemonic phrases, including cases with valid phrases, invalid words, and bad checksums.
-   `test_user_id_creation_requires_prefix`: Ensures that user ID creation requires a non-empty prefix, enforcing the Separated Account Identity (SAI) security principle.
-   `test_ed25519_to_x25519_conversion`: Tests the conversion of Ed25519 public keys to X25519 public keys.
-   `test_ephemeral_dh_key_generation`: Tests the generation of ephemeral X25519 key pairs and the Diffie-Hellman key exchange, ensuring shared secrets match.
-   `test_ed25519_signature`: Tests the signing and verification of messages using Ed25519 signatures, including a check for tampered messages.
-   `test_get_pubkey_from_user_id`: Verifies that the Ed25519 public key can be correctly extracted from a user ID and used for signature verification.
-   `test_static_encryption_flow`: Tests the complete static encryption flow, including Ed25519 to X25519 key conversion, Diffie-Hellman key exchange, HKDF key derivation, and symmetric encryption/decryption, with negative tests for wrong keys.

### `tests/persistence/archive.rs`
This file tests the functionality of the `VoucherArchive` trait and the `FileVoucherArchive` implementation.

-   `test_voucher_archiving_on_full_spend`: Tests the archiving of a voucher when its full amount is spent, verifying that the archive file is created correctly with the exact state of the transferred voucher.

### `tests/core_logic/security/vulnerabilities.rs`
This file contains tests for various attack vectors and vulnerabilities, ensuring the system's resilience against malicious manipulations.

-   `test_attack_tamper_core_data_and_guarantors`: Tests attacks involving tampering with core voucher data (e.g., nominal value) and guarantor metadata, ensuring validation fails with appropriate errors like `InvalidVoucherHash` or `InvalidSignatureId`.
-   `test_attack_tamper_transaction_history`: Tests an attack where a hacker attempts to tamper with the transaction history (e.g., invalidating a signature in the chain), ensuring that `create_transaction` fails due to prior validation.
-   `test_attack_create_inconsistent_transaction`: Tests attacks involving creating logically inconsistent transactions, such as overspending or inconsistent split amounts, ensuring validation fails with `InsufficientFundsInChain` or other relevant errors.
-   `test_attack_inconsistent_split_transaction`: Tests an attack involving creating a split transaction with inconsistent amounts (e.g., splitting 100 into 30 + 80), ensuring validation fails on such manipulations.
-   `test_attack_init_amount_mismatch`: Ensures that validation fails with `InitAmountMismatch` if the amount in the `init` transaction does not match the voucher's nominal value.
-   `test_attack_negative_or_zero_amount_transaction`: Verifies that validation fails with `NegativeOrZeroAmount` if a transaction attempts to transfer a negative or zero amount.
-   `test_attack_invalid_precision_in_nominal_value`: Checks that validation fails with `InvalidAmountPrecision` if the nominal value has more decimal places than allowed by the standard.
-   `test_attack_full_transfer_amount_mismatch`: Ensures that validation fails with `FullTransferAmountMismatch` if a "transfer" transaction does not transfer the full remaining amount.
-   `test_attack_remainder_in_full_transfer`: Verifies that validation fails if a "transfer" transaction (intended to be a full transfer) incorrectly includes a `sender_remaining_amount`.
-   `test_attack_fuzzing_random_mutations`: A fuzzing test that applies various random and targeted mutations to a voucher (e.g., invalidating signatures, setting negative amounts, moving `init` transactions) and asserts that validation always fails, ensuring robustness against unexpected data.

### `tests/core_logic/lifecycle.rs`
This file contains integration tests for the voucher lifecycle and security, covering creation, validation, and critical security aspects.

-   `test_full_creation_and_validation_cycle`: Tests the complete lifecycle of a voucher, from creation (including rounding of validity date and correct description), through initial validation (failing due to missing guarantors), to final successful validation after adding required guarantor signatures.
-   `test_serialization_deserialization`: Verifies the correct serialization and deserialization of a `Voucher` object to and from JSON, ensuring data integrity.
-   `test_validation_fails_on_invalid_signature`: Ensures that validation fails if a voucher contains an invalid or malformed signature.
-   `test_validation_fails_on_missing_required_field`: Checks that validation fails if a required field (enforced by a content rule in the standard) is missing from the voucher.
-   `test_validation_fails_on_inconsistent_unit`: Verifies that validation fails if the nominal value unit in the voucher is inconsistent with the unit defined in the standard.
-   `test_validation_fails_on_guarantor_count`: Ensures that validation fails if the number of guarantors (based on gender roles) does not meet the requirements defined in the standard.
-   `test_canonical_json_is_deterministic_and_sorted`: Tests that canonical JSON serialization is deterministic and produces alphabetically sorted keys, ensuring consistent hashing.
-   `test_validation_succeeds_with_extra_fields_in_json`: Verifies that validation succeeds even if the JSON representation of a voucher contains extra, unknown fields, demonstrating forward compatibility.
-   `test_split_transaction_cycle_and_balance_check`: Tests the complete cycle of a split transaction, including creation, validation, and verification of spendable balances for both sender and recipient.
-   `test_split_fails_on_insufficient_funds`: Ensures that a split transaction fails if the sender has insufficient funds.
-   `test_fails_to_create_forbidden_transaction_type`: Checks that `create_transaction` fails if an attempt is made to create a transaction type (e.g., "split") that is explicitly forbidden by the standard.
-   `test_split_fails_on_non_divisible_voucher`: Verifies that a split transaction fails if the voucher is marked as non-divisible in its standard.
-   `test_validity_duration_rules`: Tests various validity duration rules, including blocking creation of too-short vouchers (gatekeeper), and failing validation if the voucher's minimum validity rule mismatches the standard.
-   `test_validation_fails_on_tampered_guarantor_signature`: Ensures that validation fails if a guarantor's signature metadata is tampered with, as the `signature_id` will no longer match the re-calculated hash of the metadata.
 -   `test_double_spend_detection_logic`: Tests the core logic of double-spend detection, demonstrating that two individually valid but conflicting transactions (originating from the same `prev_hash` and `sender_id` but with different `t_id`s) can be identified as a double-spend.
 -   `test_secure_voucher_transfer_via_encrypted_bundle`: Tests the secure transfer of a voucher using an encrypted bundle.

### `tests/core_logic/math.rs`
This file contains integration tests for the numerical robustness of transactions.

-   `test_chained_transaction_math_and_scaling`: Tests the arithmetic correctness and scaling of `Decimal` values across a chain of transactions (splits and full transfers), verifying spendable balances for both sender and recipient.
-   `test_transaction_fails_on_excess_precision`: Ensures that a transaction fails if the amount to be sent has more decimal places than allowed by the standard.

### `tests/core_logic/security/standard_validation.rs`
This file contains tests for compliance with and circumvention of validation rules defined in the standard.

-   `test_required_signature_ok`: Verifies that a voucher with a correctly provided mandatory signature (matching role and allowed signer ID) passes validation.
-   `test_fails_on_missing_mandatory_signature`: Ensures that validation fails if a mandatory signature (e.g., "Official Approver") is missing from the voucher.
-   `test_fails_on_signature_from_wrong_signer`: Checks that validation fails if a mandatory signature is provided but is from a signer not listed in the `allowed_signer_ids` for that role.
-   `test_fails_on_wrong_signature_description`: Verifies that validation fails if a mandatory signature is provided but its `role` (description) does not exactly match the required role description in the standard.
-   `test_creator_as_guarantor_attack_fails`: Ensures that a creator cannot act as a guarantor for their own voucher, preventing a specific type of self-endorsement attack.

### `tests/core_logic/security/state_and_collaboration.rs`
This file contains tests for wallet state management and collaboration.

-   `test_wallet_state_management_on_split`: Tests the wallet's state management during a split transaction, ensuring the original voucher instance is replaced by a new active instance with the remainder, and the recipient receives a new active instance.
-   `test_collaborative_fraud_detection_with_fingerprints`: Tests collaborative fraud detection, where two wallets exchange fingerprints, and one wallet detects a verifiable double-spend conflict based on the imported fingerprints.
-   `test_serialization_roundtrip_with_special_chars`: Verifies that a voucher containing special characters in its fields can be successfully serialized to JSON and deserialized back, maintaining data integrity.

### `tests/architecture_tests.rs`
This file serves as the entry point for architecture-related tests, binding modules like `hardening.rs` and `resilience_and_gossip.rs`. It does not contain direct test functions.

### `tests/services_tests.rs`
This file serves as the entry point for service-level tests, binding the `services` module. It does not contain direct test functions.

### `tests/persistence_tests.rs`
This file serves as the main entry point for all persistence tests, binding the `persistence` module. It does not contain direct test functions.

### `tests/core_logic_tests.rs`
This file serves as the entry point for core logic and security tests, binding the `core_logic` module. It does not contain direct test functions.

### `tests/wallet_api_tests.rs`
This file serves as the entry point for all integration tests related to the public high-level `AppService` API, binding the `wallet_api` module. It does not contain direct test functions.

### `tests/validation_tests.rs`
This file serves as the main entry point for all validation and integrity tests of vouchers and standards, binding the `validation` module. It does not contain direct test functions.
