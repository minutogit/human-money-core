# Bericht: Ungetestete Code-Abschnitte (Mutation Testing)

Dieser Bericht listet Code-Stellen auf, die bei den letzten Änderungen in den vergangenen 7 Commits modifiziert wurden, aber laut `cargo mutants` nicht durch bestehende Tests abgesichert sind.

## Liste der ungetesteten Stellen (Surviving Mutants)

| Datei | Zeile | Mutation | Status |
| :--- | :--- | :--- | :--- |
| `src/app_service/app_profile_handler.rs` | 20 | replace `update_public_profile` with `Ok(())` | 🔴 UNGETESTET |
| `src/app_service/app_queries.rs` | 101 | replace `get_allowed_signature_roles_from_standard` with `Ok(vec![])` | 🔴 UNGETESTET |
| `src/app_service/app_queries.rs` | 101 | replace `get_allowed_signature_roles_from_standard` with `Ok(vec!["xyzzy"])` | 🔴 UNGETESTET |
| `src/app_service/app_queries.rs` | 110 | replace `get_public_profile` with `Ok(Default)` | 🔴 UNGETESTET |
| `src/app_service/app_signature_handler.rs` | 51 | replace `open_voucher_signing_request` with `Ok(Default)` | 🔴 UNGETESTET |
| `src/app_service/app_signature_handler.rs` | 59 | delete `!` check (PayloadType validation) | 🔴 UNGETESTET |
| `src/app_service/command_handler.rs` | 99 | Boolean Logik `&&`/`||` in Validierungs-Guard | 🔴 UNGETESTET |
| `src/app_service/command_handler.rs` | 137 | Zeit-Vergleich (Session Timeout in `create_new_voucher`) | 🔴 UNGETESTET |
| `src/app_service/command_handler.rs` | 297/491/614 | Zeit-Vergleich (Session Timeout in diversen Commands) | 🔴 UNGETESTET |
| `src/app_service/lifecycle.rs` | 35 | `is_wallet_unlocked` gibt immer `true`/`false` zurück | 🔴 UNGETESTET |
| `src/models/secure_container.rs` | 124 | `Drop` Implementation (Zeroize) | 🔴 UNGETESTET |
| `src/services/bundle_processor.rs` | 104 | `verify_container_signature` (Security Bypass!) | 🔴 KRITISCH |
| `src/services/bundle_processor.rs` | 117 | `verify_bundle_signature` (Security Bypass!) | 🔴 KRITISCH |
| `src/services/crypto_utils.rs` | 134/136 | `get_short_hash_from_user_id` (Index-Logik) | 🔴 UNGETESTET |
| `src/services/crypto_utils.rs` | 309 | `build_hkdf_info` (Salt/Info Check) | 🔴 UNGETESTET |
| `src/services/crypto_utils.rs` | 338 | `decrypt_recipient_payload` (Bounds Check) | 🔴 UNGETESTET |
| `src/services/crypto_utils.rs` | 817 | `validate_user_id` (Negation Bypass) | 🔴 KRITISCH |
| `src/app_service/app_profile_handler.rs` | 20 | `update_public_profile` (Body Bypass) | 🔴 KRITISCH |
| `src/wallet/queries.rs` | 33/42 | Filter-Logik (Standard & Status) | 🔴 UNGETESTET |
| `src/wallet/transaction_handler.rs` | 306 | `process_encrypted_transaction_bundle` (Equality check) | 🔴 UNGETESTET |
| `src/wallet/transaction_handler.rs` | 471 | `_execute_single_transfer` (Negation Bypass) | 🔴 KRITISCH |
