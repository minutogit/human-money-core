//! # tests/security_audit_module_06_privacy.rs
//!
//! Security Audit — Module 06: Privacy Protection, Protocol Handshakes &
//! Interchange Bundles.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. These tests turn green only after the
//! corresponding remediation has been implemented.
//!
//! Audit scope: src/services/bundle_processor.rs, src/services/secure_container_manager.rs,
//! src/services/jws_profile_service.rs, src/wallet/signature_handler.rs,
//! src/wallet/transaction_handler.rs, src/models/wallet_event.rs.
//!
//! ## Finding Summary
//!
//! | Finding-ID     | Severity | CWE         | Target                                             |
//! |----------------|----------|-------------|----------------------------------------------------|
//! | HMSEC-SA06-01  | High     | 359/202     | services/secure_container_manager.rs:229 (container signature) |
//! | HMSEC-SA06-02  | Critical | 347         | services/bundle_processor.rs::open_and_verify_bundle |
//! | HMSEC-SA06-03  | High     | 311         | services/secure_container_manager.rs:341 (`et = None`) |
//! | HMSEC-SA06-04  | Medium   | 617/125     | wallet/signature_handler.rs:101,167 (`transactions[0]`) |
//! | HMSEC-SA06-05  | Medium   | 359/778     | wallet/transaction_handler.rs:917,454 (event metadata) |
//! | HMSEC-SA06-06  | Medium   | 347/20      | services/jws_profile_service.rs (typ / did parsing) |
//! | HMSEC-SA06-07  | High     | 347         | protocols/trust/1.0/assertion.md (unsigned semantic fields) |
//! | HMSEC-SA06-08  | High     | 359/202     | services/bundle_processor.rs::is_anonymous_bundle (mixed bundles) |
//! | HMSEC-SA06-09  | High     | 347         | signing paths missing container `i` rebinding |
//! | HMSEC-SA06-10  | Medium   | 74/1164     | wallet/transaction_handler.rs (unsanitized display names) |
//! | HMSEC-SA06-11  | High     | 347/20      | voucher_validation/chain.rs (placeholder "none" trap shards) [WH3-06-601] |
//! | HMSEC-SA06-12  | High     | 347/345     | wallet/queries.rs + conflict_handler.rs (unverified endorsements/verdicts) [WH3-06-603] |
//! | HMSEC-SA06-13  | Medium   | 347/345     | conflict_handler.rs::import_proof (unbound suspected_identity) [WH3-06-602] |
//! | HMSEC-SA06-14  | Medium   | 359/345     | services/l2_gateway.rs (unbound L2 anchor metadata) [WH3-06-604] |
//! | HMSEC-SA06-15  | Medium   | 359/202     | conflict_manager.rs (gossip deletable_at linkability) [WH3-06-605] |

use ed25519_dalek::Signature;
use human_money_core::models::profile::{TransactionBundle, UserIdentity};
use human_money_core::models::secure_container::{
    ContainerConfig, EncryptionType, PayloadType, SecureContainer,
};
use human_money_core::models::signature::DetachedSignature;
use human_money_core::models::voucher::{Voucher, VoucherSignature};
use human_money_core::models::voucher_standard_definition::{
    PrivacyMode, VoucherStandardDefinition,
};
use human_money_core::services::crypto::identity::create_user_id;
use human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests;
use human_money_core::services::crypto::{
    encode_base64, get_hash, sign_ed25519, verify_ed25519,
};
use human_money_core::services::jws_profile_service::{
    export_profile_as_jws, verify_and_import_jws_profile,
};
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
use human_money_core::wallet::Wallet;
use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};
use std::collections::HashMap;

/// Configures the FreeTaler standard with a specific privacy mode and returns
/// it together with a standards map ready for transfer calls.
fn setup_standard(
    mode: PrivacyMode,
) -> (
    VoucherStandardDefinition,
    HashMap<String, VoucherStandardDefinition>,
) {
    let mut standard_def = FREETALER_STANDARD.0.clone();
    standard_def.immutable.features.privacy_mode = mode;
    let mut standards_map = HashMap::new();
    standards_map.insert(
        standard_def.immutable.identity.uuid.clone(),
        standard_def.clone(),
    );
    (standard_def, standards_map)
}

/// Creates an in-memory wallet for `identity` holding one fresh voucher of
/// `amount` units under `standard_def` and returns `(wallet, source_instance_id)`.
fn funded_wallet(
    identity: &UserIdentity,
    amount: &str,
    standard_def: &VoucherStandardDefinition,
) -> (Wallet, String) {
    let mut wallet = test_utils::setup_in_memory_wallet(identity);
    let local_id =
        test_utils::add_voucher_to_wallet(&mut wallet, identity, amount, standard_def, true)
            .expect("voucher creation failed");
    (wallet, local_id)
}

/// Performs a transfer `sender -> recipient_id` with the given privacy flag
/// and returns the raw container bytes of the resulting bundle.
fn send_bundle(
    sender_wallet: &mut Wallet,
    sender_identity: &UserIdentity,
    source_instance_id: &str,
    recipient_id: &str,
    use_privacy_mode: Option<bool>,
    standards_map: &HashMap<String, VoucherStandardDefinition>,
) -> Vec<u8> {
    sender_wallet
        .execute_multi_transfer_and_bundle(
            sender_identity,
            standards_map,
            MultiTransferRequest {
                recipient_id: recipient_id.to_string(),
                sources: vec![SourceTransfer {
                    local_instance_id: source_instance_id.to_string(),
                    amount_to_send: "50".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode,
            },
            None,
        )
        .expect("transfer failed")
        .bundle_bytes
}

// =============================================================================
// FINDING HMSEC-SA06-01
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-01
// Severity:      High
// CWE:           CWE-359 (Exposure of Private Information) / CWE-202
// Target:        src/services/secure_container_manager.rs:229-231 — every
//                SecureContainer envelope carries `signature` = Ed25519 sig
//                made with the SENDER'S PERMANENT IDENTITY KEY over the
//                public field `i`, outside the ciphertext.
// Threat Model:  An eavesdropper who never decrypts anything holds a set of
//                candidate public keys (contact list, QR-exchanged profiles).
//                Ed25519 signatures are publicly verifiable: testing
//                verify(P, i, sig) per candidate identifies the sender of an
//                "anonymous" private-mode bundle in O(1) per candidate and
//                links all bundles of the same sender.
// Impact:        Complete de-anonymization of Private Mode transfers via the
//                transport envelope, defeating threat model invariant #1
//                ("plaintext signatures MUST NOT appear in transferred
//                bundles") and the PRIVACY_MATRIX guarantee that sender_sig
//                is absent in private mode. Post-decryption authenticity is
//                unaffected: the inner bundle signature remains authoritative.
// Root Cause:    `create_secure_container` unconditionally signs `container.i`
//                with the permanent key; no privacy context is evaluated;
//                the receive path likewise requires the signature to exist.
// Remediation:   Omit the envelope signature when the transferred transaction
//                chain is anonymous (stealth), keeping `i` verifiable (it is
//                hashed over the empty-signature form). The receiver skips
//                envelope-signature verification when the field is empty and
//                relies on the inner bundle signature after decryption.
// Test Semantics: A private-mode bundle's SecureContainer must contain an
//                 EMPTY `signature`, and NO candidate permanent key (here:
//                 Alice's real key) may verify against `container.i`. The
//                 recipient must still process the bundle successfully.
//                 FAILS on unpatched code (permanent-key signature present).
// =============================================================================
#[test]
fn sa06_01_private_bundle_envelope_must_not_leak_permanent_key_signature() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;
    let (mut alice_wallet, source_id) = funded_wallet(alice, "100", &standard_def);

    // Private-mode transfer Alice -> Bob.
    let bundle_bytes = send_bundle(
        &mut alice_wallet,
        alice,
        &source_id,
        &bob.user_id,
        Some(true),
        &standards_map,
    );

    // Parse the transport envelope (this is ALL an eavesdropper ever sees).
    let container: SecureContainer =
        serde_json::from_slice(&bundle_bytes).expect("container must deserialize");

    // SECURE INVARIANT 1: no permanent-key signature in the public envelope.
    assert!(
        container.signature.is_empty(),
        "HMSEC-SA06-01 VIOLATION: private-mode bundle carries a plaintext \
         envelope signature that acts as a de-anonymization oracle (CWE-359)."
    );

    // SECURE INVARIANT 2: even IF any signature material were present, no
    // candidate permanent identity key may be confirmable against `i`.
    if !container.signature.is_empty() {
        let sig_bytes = bs58_decode_helper(&container.signature);
        let signature = Signature::from_slice(&sig_bytes).expect("sig decodable");
        assert!(
            !verify_ed25519(&alice.public_key, container.i.as_bytes(), &signature),
            "HMSEC-SA06-01 VIOLATION: eavesdropper can attribute the bundle \
             to the sender's permanent key via verify(P, i, sig)."
        );
    }

    // SECURE INVARIANT 3: authenticity must survive — Bob can still process.
    let mut bob_wallet = test_utils::setup_in_memory_wallet(bob);
    bob_wallet
        .process_encrypted_transaction_bundle(bob, &bundle_bytes, None, &standards_map)
        .expect("legitimate private bundle must remain processable");
}

// =============================================================================
// FINDING HMSEC-SA06-02
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-02
// Severity:      Critical
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature)
// Target:        src/services/bundle_processor.rs:92-130 — verification checks
//                "does sender_signature sign the STRING bundle_id?" but never
//                "IS bundle_id the hash of THIS bundle's content?" Neither
//                `bundle_id` nor container `i` is recomputed from received bytes.
// Threat Model:  Anyone who has ever observed one legitimate
//                (bundle_id, sender_signature) tuple — i.e. every past
//                recipient — re-attaches both onto ARBITRARILY MODIFIED bundle
//                content (spoofed notes, timestamp, sender_profile_name,
//                injected forwarded_fingerprints) and wraps it in their own
//                validly signed SecureContainer addressed to a new victim.
// Impact:        Full wrapper-metadata spoofing attributed to the original
//                signer; poisoning of gossip/conflict state via attacker-
//                controlled forwarded fingerprints; phishing via fake display
//                names. The documented contract ("sender_signature ... making
//                the entire bundle tamper-proof") is not enforced.
// Root Cause:    Creation binds content correctly (hash before signing), but
//                the receiving path never recomputes and compares the IDs.
// Remediation:   In `open_and_verify_bundle`: reject unless
//                bundle.bundle_id == hash(canonical_json(bundle with
//                bundle_id="" and sender_signature="")) and analogously
//                container.i == hash(canonical_json(container with i="" and
//                signature="")) BEFORE any signature verification.
// Test Semantics: A mutated bundle carrying a STOLEN but genuinely signed
//                 (bundle_id, sender_signature) pair must be rejected by the
//                 victim wallet. FAILS on unpatched code (bundle accepted).
// =============================================================================
#[test]
fn sa06_02_received_bundle_content_must_match_signed_bundle_id() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;
    let charlie = &ACTORS.charlie.identity;

    // Step 1: Alice legitimately sends to Bob; Bob processes and therefore
    // learns the (bundle_id, sender_signature) tuple.
    let (mut alice_wallet, source_id) = funded_wallet(alice, "100", &standard_def);
    let bundle_bytes = send_bundle(
        &mut alice_wallet,
        alice,
        &source_id,
        &bob.user_id,
        None,
        &standards_map,
    );
    let mut bob_wallet = test_utils::setup_in_memory_wallet(bob);
    let result = bob_wallet
        .process_encrypted_transaction_bundle(bob, &bundle_bytes, None, &standards_map)
        .expect("legitimate bundle must process");
    let stolen_bundle_id = result.header.bundle_id.clone();
    let stolen_signature = result.header.sender_signature.clone();

    // Step 2: THE ATTACK — Bob strips the signed ID pair onto poisoned
    // content addressed to Charlie.
    let poisoned = TransactionBundle {
        bundle_id: stolen_bundle_id,
        sender_id: alice.user_id.clone(),
        recipient_id: charlie.user_id.clone(),
        vouchers: Vec::new(), // value-free delivery vehicle for metadata
        timestamp: "1999-01-01T00:00:00Z".to_string(),
        notes: Some("URGENT: refund agreed, please accept".to_string()),
        sender_signature: stolen_signature,
        forwarded_fingerprints: Vec::new(),
        fingerprint_depths: HashMap::new(),
        sender_profile_name: Some("Alice Support Team".to_string()),
    };

    // Step 3: Bob wraps the poisoned content in his OWN freshly encrypted
    // container for Charlie — but grafts Alice's STOLEN envelope identity
    // (i, signature) onto it. Today nothing re-binds `i` to the actual bytes,
    // so the stolen pair still verifies against Alice's key.
    let original_container: SecureContainer =
        serde_json::from_slice(&bundle_bytes).expect("parse alice's container");
    let payload = serde_json::to_vec(&poisoned).unwrap();
    let mut attack_container = SecureContainer::seal(
        bob,
        &ContainerConfig::TargetDid(
            charlie.user_id.clone(),
            human_money_core::models::secure_container::PrivacyMode::TrialDecryption,
        ),
        &payload,
        PayloadType::TransactionBundle,
    )
    .expect("attacker can always create an encrypted container");
    attack_container.i = original_container.i.clone();
    attack_container.signature = original_container.signature.clone();
    let attack_bytes = serde_json::to_vec(&attack_container).unwrap();

    // Step 4: SECURE INVARIANT — Charlie must reject the spoofed bundle.
    let mut charlie_wallet = test_utils::setup_in_memory_wallet(charlie);
    let outcome = charlie_wallet.process_encrypted_transaction_bundle(
        charlie,
        &attack_bytes,
        None,
        &standards_map,
    );
    assert!(
        outcome.is_err(),
        "HMSEC-SA06-02 VIOLATION: accepted a bundle whose content does not \
         match its signed bundle_id — wrapper spoofing possible (CWE-347). \
         Result: {:?}",
        outcome.map(|r| r.header)
    );
}

// =============================================================================
// FINDING HMSEC-SA06-03
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-03
// Severity:      High
// CWE:           CWE-311 (Missing Encryption of Sensitive Data)
// Target:        src/services/secure_container_manager.rs:62-65 vs :341-344 —
//                the "no plaintext financial payloads" fuse exists ONLY at
//                creation; `open_secure_container` happily base64-decodes
//                `EncryptionType::None` containers typed as TransactionBundle.
// Threat Model:  Any non-library tooling or malicious peer emits a fully
//                plaintext `SecureContainer { et: "none", c: TransactionBundle }`,
//                self-consistently hashed and signed with its own key. Network
//                observers read amounts, counterparties and voucher chains.
// Impact:        The core wallet processes cleartext financial bundles end-to-
//                end, breaking the documented security invariant and providing
//                a zero-crypto delivery vehicle for metadata/gossip poisoning.
// Root Cause:    Asymmetric policy enforcement: creation rejects Cleartext +
//                TransactionBundle, the receive path performs no equivalent
//                check.
// Test Semantics: A self-consistent, correctly signed but UNENCRYPTED
//                 TransactionBundle container must be rejected by
//                 `process_encrypted_transaction_bundle`. FAILS on unpatched
//                 code (bundle accepted).
// =============================================================================
#[test]
fn sa06_03_cleartext_financial_containers_must_be_rejected_on_receipt() {
    human_money_core::set_signature_bypass(true);
    let (_standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let mallory_pk_sk = generate_ed25519_keypair_for_tests(Some("mallory_seed"));
    let mallory_id = create_user_id(&mallory_pk_sk.0, Some("mallory")).unwrap();
    let mallory = UserIdentity {
        user_id: mallory_id,
        signing_key: mallory_pk_sk.1,
        public_key: mallory_pk_sk.0,
    };
    let charlie = &ACTORS.charlie.identity;

    // Attacker-crafted financial bundle, made FULLY self-consistent exactly
    // like honest creation code: bundle_id = hash(content minus id/sig),
    // signed with the attacker's own key (bs58-encoded, mirroring
    // bundle_processor::create_and_encrypt_bundle).
    let mut bundle = TransactionBundle {
        bundle_id: String::new(),
        sender_id: mallory.user_id.clone(),
        recipient_id: charlie.user_id.clone(),
        vouchers: Vec::new(),
        timestamp: human_money_core::services::utils::get_current_timestamp(),
        notes: Some("cleartext payment".to_string()),
        sender_signature: String::new(),
        forwarded_fingerprints: Vec::new(),
        fingerprint_depths: HashMap::new(),
        sender_profile_name: None,
    };
    bundle.bundle_id = get_hash(to_canonical_json(&bundle).unwrap());
    let bundle_sig = sign_ed25519(&mallory.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58_encode_helper(bundle_sig.to_bytes().as_slice());

    // Build the SELF-CONSISTENT cleartext container exactly like honest code:
    // i = hash(canonical(container with i="" and signature="")), then sign i.
    let mut container = SecureContainer {
        protected: String::new(),
        unprotected: None,
        recipients: Vec::new(),
        iv: String::new(),
        ciphertext: encode_base64(&serde_json::to_vec(&bundle).unwrap()),
        tag: String::new(),
        signature: String::new(),
        et: EncryptionType::None,
        salt: None,
        i: String::new(),
        c: PayloadType::TransactionBundle,
    };
    let container_hash = get_hash(to_canonical_json(&container).unwrap());
    container.i = container_hash;
    let sig = sign_ed25519(&mallory.signing_key, container.i.as_bytes());
    container.signature = encode_base64(sig.to_bytes().as_slice());

    let attack_bytes = serde_json::to_vec(&container).unwrap();

    // SECURE INVARIANT: financial payloads must never be accepted unencrypted.
    let mut charlie_wallet = test_utils::setup_in_memory_wallet(charlie);
    let outcome = charlie_wallet.process_encrypted_transaction_bundle(
        charlie,
        &attack_bytes,
        None,
        &standards_map,
    );
    assert!(
        outcome.is_err(),
        "HMSEC-SA06-03 VIOLATION: processed a PLAINTEXT (EncryptionType::None) \
         TransactionBundle — the creation-side encryption fuse is bypassed on \
         receipt (CWE-311). Result: {:?}",
        outcome.map(|r| r.header)
    );
}

// =============================================================================
// FINDING HMSEC-SA06-04
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-04
// Severity:      Medium
// CWE:           CWE-617 / CWE-125 (Reachable Panic on Unvalidated Input)
// Target:        src/wallet/signature_handler.rs:101 and :167 — direct index
//                access `voucher.transactions[0].t_id` on attacker-supplied
//                vouchers.
// Threat Model:  A hostile peer sends a `VoucherForSigning` container whose
//                payload deserializes into a Voucher with an EMPTY
//                transactions list. The guarantor previews it (fine), taps
//                "Sign" — `create_detached_signature_response` indexes [0],
//                panics, and aborts the host app (hard DoS; in WASM the
//                instance traps). In the AppService flow the state was already
//                swapped to Locked, stranding the wallet for the session.
// Impact:        Remote denial-of-service against guarantors/notaries — the
//                trust infrastructure of the system.
// Root Cause:    Structural validation of the request payload is deferred to
//                the client; the core indexes blindly.
// Test Semantics: Signing a voucher with zero transactions MUST return a
//                 graceful Err, never panic. FAILS on unpatched code (panic).
// =============================================================================
#[test]
fn sa06_04_malformed_signing_request_must_not_panic_signer() {
    let guarantor = &ACTORS.guarantor1.identity;

    // Voucher-shaped object WITHOUT transactions (attacker-controlled input).
    let empty_voucher = Voucher {
        transactions: Vec::new(),
        ..Default::default()
    };

    let guarantor_wallet = test_utils::setup_in_memory_wallet(guarantor);
    let signature_data = DetachedSignature::Signature(VoucherSignature {
        role: "guarantor".to_string(),
        ..Default::default()
    });

    // SECURE INVARIANT: graceful error instead of index panic.
    let result = guarantor_wallet.create_detached_signature_response(
        guarantor,
        &empty_voucher,
        signature_data,
        false,
        ContainerConfig::Cleartext,
    );
    assert!(
        result.is_err(),
        "HMSEC-SA06-04 VIOLATION: signing an empty-chain voucher did not \
         produce a graceful error — reachable panic on remote input."
    );
}

// =============================================================================
// ARCHITECTURAL DESIGN REQUIREMENT HMSEC-SA06-05
// -----------------------------------------------------------------------------
// Requirement:   Stealth Mode vs. Local Offline Forensics (Hop-by-Hop Traceability)
// Target:        src/wallet/transaction_handler.rs
// Context:       In Stealth/Privacy Mode, the voucher transaction chain and
//                network transport envelope are anonymized so external observers
//                and downstream chain hops cannot correlate identities.
// Why Essential: In an offline decentralized cash network, double-spend detection
//                relies on hop-by-hop manual forensic reconstruction (A -> B -> C).
//                If a double spend occurs offline, each recipient must be able to
//                prove locally to whom they sent or from whom they received the voucher.
//                Therefore, the local encrypted wallet event log (TransferSent and
//                TransferReceived) MUST retain the direct counterparty DID.
//                This data is private to the owner's sealed storage and is an
//                intentional, vital offline forensic feature, NOT a security leak.
// =============================================================================
#[test]
fn sa06_05_events_must_retain_counterparty_did_in_private_mode_for_offline_forensics() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;
    let (mut alice_wallet, source_id) = funded_wallet(alice, "100", &standard_def);

    let _bundle_bytes = send_bundle(
        &mut alice_wallet,
        alice,
        &source_id,
        &bob.user_id,
        Some(true),
        &standards_map,
    );

    // ARCHITECTURAL INVARIANT (Sender Side):
    // Alice's local TransferSent event MUST retain Bob's direct DID so Alice can
    // prove to whom she transferred the voucher during offline double-spend investigations.
    let sent_event = alice_wallet
        .pending_events
        .iter()
        .find(|e| e.event_type == human_money_core::models::wallet_event::WalletEventType::TransferSent)
        .expect("TransferSent event must be emitted");

    assert_eq!(
        sent_event.bff_data.counterparty_id.as_deref(),
        Some(bob.user_id.as_str()),
        "HMSEC-SA06-05 ARCHITECTURAL VIOLATION: TransferSent event MUST retain the \
         direct counterparty DID ('{}') for local offline forensics and hop-by-hop \
         double-spend investigations, but found: {:?}",
        bob.user_id,
        sent_event.bff_data.counterparty_id
    );

    // ARCHITECTURAL INVARIANT (Receive Side):
    // Bob's local TransferReceived event MUST retain Alice's direct DID so Bob can
    // trace backwards from whom he received the voucher in an offline network.
    let bundle_bytes = send_and_capture_again(alice, bob, &standard_def, &standards_map);
    let mut bob_wallet = test_utils::setup_in_memory_wallet(bob);
    bob_wallet
        .process_encrypted_transaction_bundle(bob, &bundle_bytes, None, &standards_map)
        .expect("private bundle must process");

    let received_event = bob_wallet
        .pending_events
        .iter()
        .find(|e| e.event_type == human_money_core::models::wallet_event::WalletEventType::TransferReceived)
        .expect("TransferReceived event must be emitted");

    assert_eq!(
        received_event.bff_data.counterparty_id.as_deref(),
        Some(alice.user_id.as_str()),
        "HMSEC-SA06-05 ARCHITECTURAL VIOLATION: TransferReceived event MUST retain the \
         direct sender DID ('{}') for local offline forensics and hop-by-hop \
         double-spend investigations, but found: {:?}",
        alice.user_id,
        received_event.bff_data.counterparty_id
    );
}

/// Helper performing a second private transfer (fresh voucher) so the receive
/// side can be tested without disturbing the first wallet's assertions.
fn send_and_capture_again(
    alice: &UserIdentity,
    bob: &UserIdentity,
    standard_def: &VoucherStandardDefinition,
    standards_map: &HashMap<String, VoucherStandardDefinition>,
) -> Vec<u8> {
    let (mut alice_wallet, source_id) = funded_wallet(alice, "100", standard_def);
    send_bundle(
        &mut alice_wallet,
        alice,
        &source_id,
        &bob.user_id,
        Some(true),
        standards_map,
    )
}

// =============================================================================
// FINDING HMSEC-SA06-06
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-06
// Severity:      Medium
// CWE:           CWE-347 / CWE-20 (Improper Input Validation)
// Target:        src/services/jws_profile_service.rs — (a) `typ`/`cty` JWS
//                header members are never validated (only `alg`); (b) the
//                bespoke did:key parser slices decoded[2..34], IGNORING
//                trailing bytes, and rejects prefixed SAI user IDs.
// Threat Model:  (a) Cross-type confusion: the same verifier will guard other
//                artifact classes (e.g. TrustAssertion); accepting arbitrary
//                `typ` values invites header-confusion attacks. (b)
//                `did:key:z<valid><garbage>` maps to the same key but is a
//                DIFFERENT string — malleable identities break equality-based
//                authorization (dedupe maps, creator checks), while legitimate
//                prefixed profiles (`prefix@did:key:z...`) fail import.
// Impact:        Identity aliasing + future protocol confusion in the QR /
//                profile exchange channel.
// Root Cause:    Only `alg` is pinned; DID parsing reimplements instead of
//                delegating to the canonical `get_pubkey_from_user_id`.
// Test Semantics: (1) JWS with tampered `typ` must be rejected. (2) A JWS
//                 whose profile id carries trailing garbage after the valid
//                 multicodec key must be rejected. (3) A prefixed SAI user id
//                 must import SUCCESSFULLY (interop). FAILS partially on
//                 unpatched code ((1),(2) accepted today).
// =============================================================================
#[test]
fn sa06_06_jws_must_reject_tampered_typ_and_noncanonical_did() {
    use human_money_core::models::profile::PublicProfile;

    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("sa06_06_seed"));
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58_encode_helper(&bytes));

    let profile = PublicProfile {
        id: Some(did_key.clone()),
        first_name: Some("Audit".to_string()),
        ..Default::default()
    };
    let jws = export_profile_as_jws(&signing_key, &profile).expect("export failed");

    // Baseline: untampered JWS imports.
    assert!(
        verify_and_import_jws_profile(&jws).is_ok(),
        "test setup: untampered JWS must import"
    );

    // INVARIANT 1: tampered `typ` header must be rejected (type confusion).
    let parts: Vec<&str> = jws.split('.').collect();
    let tampered_header_json = {
        let header_bytes = base64_decode_urlsafe(parts[0]);
        let mut v: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        v["typ"] = serde_json::Value::String("application/trust-assertion+json".to_string());
        serde_json::to_vec(&v).unwrap()
    };
    let tampered_typ_jws = format!(
        "{}.{}.{}",
        base64_encode_urlsafe(&tampered_header_json),
        parts[1],
        parts[2]
    );
    assert!(
        verify_and_import_jws_profile(&tampered_typ_jws).is_err(),
        "HMSEC-SA06-06 VIOLATION: JWS with manipulated 'typ' header passed \
         verification — header confusion possible (CWE-347)."
    );

    // INVARIANT 2: trailing-garbage did:key aliasing must be rejected. The
    // attacker signs their own profile whose id is <valid-key><extra>.
    let mut alias_bytes = bytes.clone();
    alias_bytes.extend_from_slice(b"9mF"); // extra base58 chars appended
    let alias_did = format!("did:key:z{}", bs58_encode_helper(&alias_bytes));
    let alias_profile = PublicProfile {
        id: Some(alias_did),
        first_name: Some("Alias".to_string()),
        ..Default::default()
    };
    let alias_jws = export_profile_as_jws(&signing_key, &alias_profile).expect("export failed");
    assert!(
        verify_and_import_jws_profile(&alias_jws).is_err(),
        "HMSEC-SA06-06 VIOLATION: non-canonical did:key with trailing garbage \
         imported — malleable identity strings break equality logic (CWE-20)."
    );

    // INVARIANT 3 (interop): prefixed SAI user ids must import successfully.
    let prefixed_profile = PublicProfile {
        id: Some(format!("community:fY7@{}", did_key)),
        first_name: Some("Prefixed".to_string()),
        ..Default::default()
    };
    let prefixed_jws =
        export_profile_as_jws(&signing_key, &prefixed_profile).expect("export failed");
    let imported = verify_and_import_jws_profile(&prefixed_jws);
    assert!(
        imported.is_ok(),
        "HMSEC-SA06-06 REGRESSION: legitimate prefixed SAI profile \
         (prefix@did:key) must import for interoperability. Err: {:?}",
        imported.err()
    );
}

// =============================================================================
// FINDING HMSEC-SA06-07
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-07
// Severity:      High
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature)
// Target:        protocols/trust/1.0/assertion.md — the planned schema defines
//                assertion_id = hash(issuer_id + subject_id + timestamp) and
//                issuer_signature as a signature over `assertion_id` ALONE.
//                Consequently `trust_level` and `context` are cryptographically
//                UNPROTECTED. No verifier exists in src/ yet, but
//                PayloadType::TrustAssertion is already routable
//                (src/models/secure_container.rs:23).
// Threat Model:  Anyone who observes ONE legitimate trust assertion can rewrite
//                its semantic payload (escalate "direct" to "endorsement",
//                fabricate context text) while every future spec-conformant
//                verifier still accepts it, because verification binds only
//                the deterministic assertion_id. Trust assertions are the
//                WoT foundation for guarantors/notaries.
// Impact:        Undetectable forgery of trust statements; poisoning of the
//                future Web-of-Trust layer; replay of identical assertions
//                across channels (no nonce/expiry binding).
// Root Cause:    Spec-level design flaw: signature basis excludes all
//                semantically relevant fields. Fixing it AFTER a verifier
//                ships would invalidate every issued assertion.
// Remediation:   REMEDIATED — the spec (protocols/trust/1.0/assertion.md) was
//                hardened BEFORE any verifier shipped: assertion_id is now
//                SHA3-256 over the canonical JSON of ALL semantic fields
//                (issuer_id, subject_id, trust_level, context, timestamp) and
//                issuer_signature covers those bytes, transitively committing
//                every semantic field.
// Test Semantics: Conformance harness for the hardened scheme. Builds a
//                 legitimate assertion (issuer signs the canonical semantic
//                 JSON), verifies it with an inline hardened verifier
//                 (recompute-and-compare + signature over the id), then
//                 tampers with trust_level AND context and asserts that
//                 verification MUST reject. Under the pre-fix v1.0 spec the
//                 naive verifier would have accepted the tampered artifact;
//                 that exploitation branch no longer applies now that the
//                 binding exists.
// =============================================================================
#[test]
fn sa06_07_trust_assertion_signature_must_bind_all_semantic_fields() {
    let (issuer_pk, issuer_sk) = generate_ed25519_keypair_for_tests(Some("sa06_07_issuer_seed"));
    let (subject_pk, _) = generate_ed25519_keypair_for_tests(Some("sa06_07_subject_seed"));
    let issuer_did = create_user_id(&issuer_pk, Some("issuer")).expect("issuer id");
    let subject_did = create_user_id(&subject_pk, Some("subject")).expect("subject id");

    // --- Build a legitimate assertion under the HARDENED spec ---------------
    // assertion_id = SHA3-256 over the canonical JSON of ALL semantic fields;
    // issuer_signature = Ed25519 over the assertion_id string bytes (bs58).
    let timestamp = human_money_core::services::utils::get_current_timestamp();
    let semantic = serde_json::json!({
        "issuer_id": issuer_did,
        "subject_id": subject_did,
        "trust_level": "direct",
        "context": "Local merchant, personally known.",
        "timestamp": timestamp,
    });
    let canonical = to_canonical_json(&semantic).expect("canonical json");
    let assertion_id = get_hash(canonical);
    // Spec: issuer_signature signs the assertion_id, which transitively
    // commits every semantic field.
    let issuer_signature =
        bs58_encode_helper(sign_ed25519(&issuer_sk, assertion_id.as_bytes()).to_bytes().as_slice());

    let legit_assertion = serde_json::json!({
        "assertion_id": assertion_id,
        "issuer_id": issuer_did,
        "subject_id": subject_did,
        "trust_level": "direct",
        "context": "Local merchant, personally known.",
        "timestamp": timestamp,
        "issuer_signature": issuer_signature,
    });

    // --- Inline HARDENED verifier --------------------------------------------
    // Recomputes the assertion_id from the received semantic fields, compares
    // it to the transmitted id, and verifies the signature over the id. ANY
    // divergence rejects (fail-closed).
    let verify_hardened = |assertion: &serde_json::Value| -> bool {
        let semantic = serde_json::json!({
            "issuer_id": assertion["issuer_id"],
            "subject_id": assertion["subject_id"],
            "trust_level": assertion["trust_level"],
            "context": assertion["context"],
            "timestamp": assertion["timestamp"],
        });
        let Ok(canonical) = to_canonical_json(&semantic) else {
            return false;
        };
        let expected_id = get_hash(canonical);
        if assertion["assertion_id"].as_str() != Some(expected_id.as_str()) {
            return false;
        }
        let Ok(sig_bytes) =
            bs58::decode(assertion["issuer_signature"].as_str().unwrap_or_default()).into_vec()
        else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&sig_bytes) else {
            return false;
        };
        verify_ed25519(&issuer_pk, expected_id.as_bytes(), &signature)
    };

    // Positive control: the legitimate assertion verifies under the hardening.
    assert!(
        verify_hardened(&legit_assertion),
        "test setup: hardened verifier must accept the legitimate assertion"
    );

    // --- THE ATTACK: rewrite semantics WITHOUT touching signature material --
    let mut tampered = legit_assertion.clone();
    tampered["trust_level"] = serde_json::Value::String("endorsement".to_string());
    tampered["context"] = serde_json::Value::String(
        "NOT the issuer's statement - injected by attacker".to_string(),
    );

    // SECURE INVARIANT: any mutation of a semantic field breaks the recomputed
    // assertion_id and MUST be rejected. (Under the pre-fix v1.0 spec —
    // signature over an id derived from ids+timestamp only — the naive
    // verifier would have silently accepted this forgery; that gap is closed.)
    assert!(
        !verify_hardened(&tampered),
        "HMSEC-SA06-07 REGRESSION: trust_level/context are not bound by \
         issuer_signature - undetectable trust-assertion forgery (CWE-347)."
    );
}

// =============================================================================
// FINDING HMSEC-SA06-08
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-08
// Severity:      High
// CWE:           CWE-359 (Exposure of Private Information) / CWE-202
// Target:        src/services/bundle_processor.rs::is_anonymous_bundle — the
//                HMSEC-SA06-01 remediation strips the permanent-key envelope
//                signature ONLY when EVERY voucher chain in the bundle is
//                anonymous (`all()` gate). One single non-anonymous chain
//                keeps the Ed25519 signature over container `i`, made with
//                the SENDER'S PERMANENT IDENTITY KEY, publicly verifiable by
//                any eavesdropper holding a candidate public key.
// Threat Model:  A legitimate multi-standard transfer (privacy_mode resolved
//                PER VOUCHER when use_privacy_mode = None) combines a public
//                chain (Public standard, plaintext DIDs) with a stealth chain
//                (Stealth standard, fully anonymous) inside ONE encrypted
//                container. The all-or-nothing gate then leaves the
//                de-anonymization oracle intact for the WHOLE container —
//                including the stealth sub-chain whose entire purpose was
//                transport-level unlinkability. The sender de-anonymizes every
//                co-transferred private chain without any rule violation,
//                purely via a legitim-looking code path (SA06-01 oracle
//                regression).
// Impact:        Transport observers can attribute mixed bundles to the
//                sender's permanent key via verify(P, i, sig) and learn that
//                additional anonymous transfers to unknown parties occurred,
//                defeating invariant #1 ("plaintext signatures MUST NOT appear
//                in transferred [private] bundles") for all mixed traffic.
// Root Cause:    Gate evaluates bundle-level ALL instead of ANY: presence of a
//                single anonymous chain already creates the privacy context
//                that must suppress the permanent-key signature.
// Remediation:   Strip the envelope signature whenever AT LEAST ONE included
//                chain is anonymous (`any()` semantics). Post-decryption
//                authenticity is unaffected: the inner bundle signature stays
//                authoritative and the receive path explicitly accepts
//                unsigned envelopes (open_and_verify_bundle).
// Test Semantics: A combined transfer of one Public + one Stealth voucher
//                 (use_privacy_mode = None) must produce an UNSIGNED
//                 envelope; no candidate permanent key may verify against
//                 container.i; the recipient must still process BOTH vouchers.
//                 FAILS on unpatched code (signature present & attributable).
// =============================================================================
#[test]
fn sa06_08_mixed_visibility_bundle_must_not_carry_permanent_key_envelope_signature() {
    human_money_core::set_signature_bypass(true);

    // Standard A: Public (plaintext DIDs on the chain); Standard B: forced
    // Stealth, under a DISTINCT UUID so both can coexist in one standards map.
    let (public_def, mut standards_map) = setup_standard(PrivacyMode::Public);
    let mut stealth_def = FREETALER_STANDARD.0.clone();
    stealth_def.immutable.features.privacy_mode = PrivacyMode::Stealth;
    stealth_def.immutable.identity.uuid = format!(
        "{}-sa0608-stealth",
        stealth_def.immutable.identity.uuid
    );
    standards_map.insert(
        stealth_def.immutable.identity.uuid.clone(),
        stealth_def.clone(),
    );

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;

    // One wallet, one voucher per visibility class.
    let (mut alice_wallet, public_source) = funded_wallet(alice, "100", &public_def);
    let stealth_source =
        test_utils::add_voucher_to_wallet(&mut alice_wallet, alice, "100", &stealth_def, true)
            .expect("stealth voucher creation failed");

    // Combined multi-source transfer; privacy mode resolved per voucher
    // standard because use_privacy_mode = None.
    let bundle_bytes = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &standards_map,
            MultiTransferRequest {
                recipient_id: bob.user_id.clone(),
                sources: vec![
                    SourceTransfer {
                        local_instance_id: public_source,
                        amount_to_send: "50".to_string(),
                    },
                    SourceTransfer {
                        local_instance_id: stealth_source,
                        amount_to_send: "50".to_string(),
                    },
                ],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("mixed transfer failed")
        .bundle_bytes;

    // Parse the transport envelope (all an eavesdropper ever sees).
    let container: SecureContainer =
        serde_json::from_slice(&bundle_bytes).expect("container must deserialize");

    // SECURE INVARIANT 1: a bundle containing an anonymous chain must NOT
    // carry a plaintext envelope signature (de-anonymization oracle).
    assert!(
        container.signature.is_empty(),
        "HMSEC-SA06-08 VIOLATION: mixed-visibility bundle keeps the \
         permanent-key envelope signature alive because only ONE of the two \
         chains is anonymous — the stealth sub-chain is de-anonymized \
         through the transport layer (CWE-359)."
    );

    // SECURE INVARIANT 2 (defense in depth): even IF signature material were
    // present, no candidate permanent key may confirm against `i`.
    if !container.signature.is_empty() {
        let sig_bytes = bs58_decode_helper(&container.signature);
        let signature = Signature::from_slice(&sig_bytes).expect("sig decodable");
        assert!(
            !verify_ed25519(&alice.public_key, container.i.as_bytes(), &signature),
            "HMSEC-SA06-08 VIOLATION: eavesdropper attributes the whole \
             container — including the stealth sub-chain — to the sender's \
             permanent key via verify(P, i, sig)."
        );
    }

    // SECURE INVARIANT 3: authenticity must survive — Bob processes BOTH
    // vouchers without error (inner bundle signature remains authoritative).
    let mut bob_wallet = test_utils::setup_in_memory_wallet(bob);
    let result = bob_wallet
        .process_encrypted_transaction_bundle(bob, &bundle_bytes, None, &standards_map)
        .expect("legitimate mixed bundle must remain processable");
    assert_eq!(
        result.involved_vouchers.len(),
        2,
        "HMSEC-SA06-08 REGRESSION: stripping the envelope signature must not \
         affect delivery — both vouchers must arrive."
    );
}

// =============================================================================
// FINDING HMSEC-SA06-09
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-09
// Severity:      High
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature)
// Target:        src/app_service/app_signature_handler.rs::open_voucher_signing_request
//                and src/wallet/signature_handler.rs::process_and_attach_signature —
//                unlike the transfer path (open_and_verify_bundle,
//                HMSEC-SA06-02 remediation), neither receive path recomputes
//                container `i` from the received bytes before use.
// Threat Model:  Every AEAD-exempt envelope field (`i`, `signature`,
//                `unprotected`, `salt`, `et`, `c`) can be rewritten by a
//                network attacker without detection: a stolen-but-genuinely-
//                signed `(i, signature)` pair (SA06-02 recipe) re-mounts onto
//                manipulated VoucherForSigning / DetachedSignature containers,
//                and arbitrary `unprotected` metadata reaches host/UI layers
//                unverified. The wrapper-vs-payload binding ("i =
//                hash(content)") that the transfer path enforces simply does
//                not exist here.
// Impact:        Envelope-spoofing class SA06-02 stays exploitable on two of
//                three protocol paths; unauthenticated header metadata can be
//                injected into the trust infrastructure workflow (guarantors/
//                notaries).
// Root Cause:    Fix asymmetry: the integrity rebinding gate was implemented
//                exclusively in bundle_processor::open_and_verify_bundle.
// Remediation:   Rebind `i` on ALL protocol receive paths: reject unless
//                container.i == hash(canonical(container with i="" and
//                signature="")) exactly as during creation
//                (create_secure_container). Honest senders always satisfy
//                this invariant, so no legitimate flow breaks. Cleartext
//                preview semantics are unaffected (content review remains the
//                signer's decision; their resulting signature binds the
//                reviewed content).
// Test Semantics: (1) Signing-request path: a VoucherForSigning container
//                 carrying STOLEN (i, signature) over fresh attacker content
//                 must be REJECTED by open_voucher_signing_request; the
//                 untampered request must still open. (2) Detached-signature
//                 path: grafting response A's (i, signature) onto response B,
//                 and injecting an `unprotected` member onto response B, must
//                 both be REJECTED by process_and_attach_signature; the
//                 untouched response must still attach. FAILS on unpatched
//                 code (all manipulations accepted).
// =============================================================================
#[test]
fn sa06_09_signing_paths_must_rebind_container_integrity_id() {
    human_money_core::set_signature_bypass(true);
    let (flexible_def, _standards_map) = setup_standard(PrivacyMode::Flexible);

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;

    // ---------------------------------------------------------------------
    // PART A — Signing-request path (AppService::open_voucher_signing_request)
    // ---------------------------------------------------------------------
    // Receiver is an AppService profile whose identity differs from the
    // static test actor; resolve its runtime DID first.
    let guarantor_dir = tempfile::tempdir().expect("tempdir");
    let (guarantor_app, _) = test_utils::setup_service_with_profile(
        guarantor_dir.path(),
        &ACTORS.guarantor1,
        "sa0609_guarantor",
        "correct horse battery staple",
    );
    let receiver_did = guarantor_app.with_wallet(|w| w.get_user_id().to_string()).expect("receiver did");

    let (mut alice_wallet, request_local_id) =
        funded_wallet(alice, "100", &flexible_def);

    let legit_request_bytes = alice_wallet
        .create_signing_request(
            alice,
            &request_local_id,
            ContainerConfig::TargetDid(
                receiver_did.clone(),
                human_money_core::models::secure_container::PrivacyMode::TrialDecryption,
            ),
        )
        .expect("legitimate signing request creation failed");

    // Regression guard baseline: the honest request opens fine.
    let opened = guarantor_app.open_voucher_signing_request(&legit_request_bytes, None);
    assert!(
        opened.is_ok(),
        "HMSEC-SA06-09 REGRESSION: honest signing request must remain openable. Err: {:?}",
        opened.err()
    );

    // THE ATTACK: Mallory crafts her OWN VoucherForSigning container encrypted
    // to the guarantor and grafts Alice's STOLEN envelope identity onto it.
    let legit_container: SecureContainer =
        serde_json::from_slice(&legit_request_bytes).expect("parse legit request");
    let stolen_i = legit_container.i.clone();
    let stolen_signature = legit_container.signature.clone();

    let mallory_kp = generate_ed25519_keypair_for_tests(Some("sa06_09_mallory"));
    let mallory = UserIdentity {
        user_id: create_user_id(&mallory_kp.0, Some("mallory")).unwrap(),
        signing_key: mallory_kp.1,
        public_key: mallory_kp.0,
    };
    let poisoned_voucher = Voucher {
        transactions: Vec::new(),
        ..Default::default()
    };
    let mut attack_container = SecureContainer::seal(
        &mallory,
        &ContainerConfig::TargetDid(
            receiver_did.clone(),
            human_money_core::models::secure_container::PrivacyMode::TrialDecryption,
        ),
        &serde_json::to_vec(&poisoned_voucher).unwrap(),
        PayloadType::VoucherForSigning,
    )
    .expect("attacker container creation");
    attack_container.i = stolen_i;
    attack_container.signature = stolen_signature;
    let attack_request_bytes = serde_json::to_vec(&attack_container).unwrap();

    // SECURE INVARIANT 1: content not matching the signed integrity id `i`
    // must be rejected on the preview path.
    let attack_opened = guarantor_app.open_voucher_signing_request(&attack_request_bytes, None);
    assert!(
        attack_opened.is_err(),
        "HMSEC-SA06-09 VIOLATION: signing-request path accepted a container \
         whose content does not match its integrity id `i` — stolen \
         (i, signature) pairs remount freely (CWE-347)."
    );

    // ---------------------------------------------------------------------
    // PART B — Detached-signature path (Wallet::process_and_attach_signature)
    // ---------------------------------------------------------------------
    let voucher_a = alice_wallet
        .voucher_store
        .vouchers
        .values()
        .next()
        .map(|inst| inst.voucher.clone())
        .expect("voucher A present");
    let local_id_b = test_utils::add_voucher_to_wallet(
        &mut alice_wallet,
        alice,
        "100",
        &flexible_def,
        true,
    )
    .expect("voucher B creation failed");
    let voucher_b = alice_wallet
        .voucher_store
        .vouchers
        .get(&local_id_b)
        .map(|inst| inst.voucher.clone())
        .expect("voucher B present");

    let bob_wallet = test_utils::setup_in_memory_wallet(bob);
    let sig_metadata = || {
        DetachedSignature::Signature(VoucherSignature {
            role: "guarantor".to_string(),
            ..Default::default()
        })
    };
    let response_a = bob_wallet
        .create_detached_signature_response(
            bob,
            &voucher_a,
            sig_metadata(),
            true,
            ContainerConfig::TargetDid(
                alice.user_id.clone(),
                human_money_core::models::secure_container::PrivacyMode::TrialDecryption,
            ),
        )
        .expect("response A");
    let response_b = bob_wallet
        .create_detached_signature_response(
            bob,
            &voucher_b,
            sig_metadata(),
            true,
            ContainerConfig::TargetDid(
                alice.user_id.clone(),
                human_money_core::models::secure_container::PrivacyMode::TrialDecryption,
            ),
        )
        .expect("response B");

    // Regression guard baseline: the untouched response attaches fine.
    let attached = alice_wallet.process_and_attach_signature(alice, &response_b, None);
    assert!(
        attached.is_ok(),
        "HMSEC-SA06-09 REGRESSION: untouched detached signature must attach. Err: {:?}",
        attached.err()
    );

    // ATTACK B1: graft response A's (i, signature) onto response B's container.
    let resp_a_container: SecureContainer =
        serde_json::from_slice(&response_a).expect("parse response A");
    let mut b1_container: SecureContainer =
        serde_json::from_slice(&response_b).expect("parse response B");
    b1_container.i = resp_a_container.i.clone();
    b1_container.signature = resp_a_container.signature.clone();
    let b1_bytes = serde_json::to_vec(&b1_container).unwrap();
    let b1_result = alice_wallet.process_and_attach_signature(alice, &b1_bytes, None);
    assert!(
        b1_result.is_err(),
        "HMSEC-SA06-09 VIOLATION: detached-signature path accepted a container \
         wearing a STOLEN (i, signature) pair — wrapper spoofing possible."
    );

    // ATTACK B2: inject an `unprotected` metadata member (AEAD-exempt field)
    // while keeping the container's own (i, signature) — the recomputed
    // integrity id no longer matches and this MUST be detected.
    let mut b2_container: SecureContainer =
        serde_json::from_slice(&response_b).expect("parse response B");
    b2_container.unprotected = Some(serde_json::json!({
        "ui_hint": "attacker-controlled unauthenticated metadata"
    }));
    let _ = to_canonical_json(&b2_container); // ensure canonicalization compiles/works on tampered form
    let b2_bytes = serde_json::to_vec(&b2_container).unwrap();
    let b2_result = alice_wallet.process_and_attach_signature(alice, &b2_bytes, None);
    assert!(
        b2_result.is_err(),
        "HMSEC-SA06-09 VIOLATION: detached-signature path accepted mutated \
         AEAD-exempt envelope metadata (`unprotected`) without detection."
    );
}

// =============================================================================
// FINDING HMSEC-SA06-10
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-10
// Severity:      Medium
// CWE:           CWE-74 (Injection) / CWE-1164 (Irrelevant Code / unverified
//                metadata propagated into trusted context)
// Target:        src/wallet/transaction_handler.rs::process_encrypted_
//                transaction_bundle_inner — `counterparty_name` is taken
//                verbatim from the attacker-controlled
//                TransactionBundle.sender_profile_name and stored in
//                EventBffData.counterparty_name (event feed) plus the
//                persistent BundleMetadataStore.history.
// Threat Model:  Any peer sends a validly signed bundle with an arbitrary
//                sender_profile_name (unbounded length, Unicode control /
//                invisible / bidi-override characters such as U+200D or
//                U+202E). The victim's TRUSTED event feed renders it
//                verbatim: phishing via spoofed display names ("Alice
//                Support Team"), log bloating via 10k-char strings in a
//                permanently growing history. Distinct from the PROTECTED
//                SA06-05 design (counterparty_id DID retention): sanitizing
//                the NAME does not touch the forensic anchor.
// Impact:        Phishing/social engineering inside the trustworthy UI feed;
//                resource exhaustion of the local event log; rendering
//                manipulation via bidi/invisible characters.
// Root Cause:    Receive path propagates remote display metadata without any
//                provenance check, length bound, or character filtering.
// Remediation:   Sanitize at ingestion, immediately after envelope/bundle
//                verification: strip control (Cc) and format/invisible (Cf:
//                ZWJ/ZWNJ/bidi-override/BOM-class) characters and bound the
//                length. Display utility is preserved (clean prefix shown);
//                offline forensics is unaffected because counterparty_id
//                remains untouched (SA06-05 intentional design).
// Test Semantics: A received bundle whose sender_profile_name carries a
//                 10k-character string with ZWJ/pop-directional-format
//                 characters must produce a TransferReceived event whose
//                 counterparty_name is bounded (<=64 chars) and free of
//                 control/format characters; a legitimate short name must be
//                 preserved unchanged. FAILS on unpatched code (raw string).
// =============================================================================
#[test]
fn sa06_10_received_display_name_must_be_sanitized_and_bounded() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let charlie = &ACTORS.charlie.identity;

    // Attacker Mallory sends a legitimately signed bundle whose ONLY payload
    // is a poisoned display name.
    let mallory_kp = generate_ed25519_keypair_for_tests(Some("sa06_10_mallory"));
    let mallory = UserIdentity {
        user_id: create_user_id(&mallory_kp.0, Some("mallory")).unwrap(),
        signing_key: mallory_kp.1,
        public_key: mallory_kp.0,
    };
    let (mut mallory_wallet, source_id) = funded_wallet(&mallory, "100", &standard_def);

    let attacker_name = format!("{}{}Eve{}", "A".repeat(10_000), '\u{200D}', '\u{202E}');
    let attack_bytes = mallory_wallet
        .execute_multi_transfer_and_bundle(
            &mallory,
            &standards_map,
            MultiTransferRequest {
                recipient_id: charlie.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: source_id,
                    amount_to_send: "50".to_string(),
                }],
                notes: None,
                sender_profile_name: Some(attacker_name),
                use_privacy_mode: None,
            },
            None,
        )
        .expect("attack transfer failed")
        .bundle_bytes;

    // Victim processes the bundle.
    let mut charlie_wallet = test_utils::setup_in_memory_wallet(charlie);
    charlie_wallet
        .process_encrypted_transaction_bundle(charlie, &attack_bytes, None, &standards_map)
        .expect("attack bundle must process (name is non-cryptographic metadata)");

    let received_event = charlie_wallet
        .pending_events
        .iter()
        .find(|e| {
            e.event_type == human_money_core::models::wallet_event::WalletEventType::TransferReceived
        })
        .expect("TransferReceived event must be emitted");

    // SECURE INVARIANT 1: bounded length — no unbounded remote strings in
    // the persistent event history.
    let name = received_event.bff_data.counterparty_name.as_ref();
    assert!(
        name.is_some_and(|n| n.chars().count() <= 64),
        "HMSEC-SA06-10 VIOLATION: attacker-controlled display name entered \
         the trusted event feed unbounded ({} chars).",
        name.map(|n| n.chars().count()).unwrap_or(0)
    );

    // SECURE INVARIANT 2: no control / invisible / direction-manipulating
    // characters survive into the UI-facing field.
    let has_forbidden_chars = name.is_some_and(|n| {
        n.chars().any(|c| {
            c.is_control()
                || matches!(c as u32,
                    0x200B..=0x200F       // ZWSP..RLM incl. ZWJ
                    | 0x202A..=0x202E     // bidi embedding/overrides (incl. U+202E)
                    | 0x2060..=0x206F     // word joiner & invisible ops
                    | 0xFEFF              // BOM / zero-width no-break space
                )
        })
    });
    assert!(
        !has_forbidden_chars,
        "HMSEC-SA06-10 VIOLATION: display name contains control/invisible/\
         direction-manipulating characters from the wire."
    );
    // Forensic anchor untouched (SA06-05 protected design).
    assert_eq!(
        received_event.bff_data.counterparty_id.as_deref(),
        Some(mallory.user_id.as_str()),
        "SA06-05 REGRESSION: counterparty DID retention must stay intact."
    );

    // REGRESSION GUARD: legitimate short names are preserved verbatim.
    let (mut alice_wallet, alice_source) = funded_wallet(&ACTORS.alice.identity, "100", &standard_def);
    let legit_bytes = alice_wallet
        .execute_multi_transfer_and_bundle(
            &ACTORS.alice.identity,
            &standards_map,
            MultiTransferRequest {
                recipient_id: charlie.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: alice_source,
                    amount_to_send: "50".to_string(),
                }],
                notes: None,
                sender_profile_name: Some("Alice".to_string()),
                use_privacy_mode: None,
            },
            None,
        )
        .expect("legit transfer failed")
        .bundle_bytes;
    let mut fresh_charlie = test_utils::setup_in_memory_wallet(charlie);
    fresh_charlie
        .process_encrypted_transaction_bundle(charlie, &legit_bytes, None, &standards_map)
        .expect("legit bundle must process");
    let legit_event = fresh_charlie
        .pending_events
        .iter()
        .find(|e| {
            e.event_type == human_money_core::models::wallet_event::WalletEventType::TransferReceived
        })
        .expect("legit TransferReceived event");
    assert_eq!(
        legit_event.bff_data.counterparty_name.as_deref(),
        Some("Alice"),
        "HMSEC-SA06-10 REGRESSION: legitimate display names must pass through \
         sanitization unchanged."
    );
}

// =============================================================================
// FINDING HMSEC-SA06-11 (WH3-06-601)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-11
// Severity:      High
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature) /
//                CWE-20 (Improper Input Validation)
// Target:        src/services/voucher_validation/chain.rs :: trap gate in
//                verify_transactions (~310-353) + validate_privacy_mode
//                (Stealth/Flexible branches) — shard PRESENCE and hygiene
//                (':'/'@') are enforced, but shard AUTHENTICITY is not: the
//                canonical "none" placeholder (l2_gateway::
//                TRAP_NONE_PLACEHOLDER) passes every reception-side check,
//                and the V3 digest happily binds placeholder shards signed by
//                the spender's own ephemeral key. ds_tag re-derivation IS now
//                enforced (fresh fix), so only the placeholder-shard form
//                remains open.
// Threat Model:  A spender replaces their genuine SST shards with
//                TrapData { ds_tag: <correct>, trap_r: "none", trap_s: "none"
//                } and re-signs the HMC_TX_AUTH_V3 digest over the
//                placeholders (they own the ephemeral key, so this is a
//                perfectly valid self-signature). The spend passes L1 chain
//                validation, yet conflict_manager::is_init_fingerprint
//                classifies its fingerprint as genesis ("none" marker):
//                gossip ingress (import_foreign_fingerprints), export filter,
//                cleanup and SST collision extraction all silently skip it.
//                Double-spends of such forks NEVER reach remote victims and
//                identity attribution is mathematically impossible (no real
//                shards exist). The reference l2_client_simulator
//                (cmd_transfer/cmd_double_spend) already emits exactly this
//                lock form ("none"/"none") for spends — first-party tooling
//                anchors the degenerate behavior.
// Impact:        SST attribution ("double-spending provable + autonomous
//                did:key attribution") becomes OPTIONAL: any spender can
//                switch the fraud-evidence channel off by format choice,
//                defeating PRIVACY_MATRIX "Private Mode Integrity: mode ==
//                Private AND trap_data missing/non-context-bound -> INVALID".
// Root Cause:    The trap gate validates structure/hygiene/ds_tag binding but
//                never rejects the genesis-only "none" placeholder on
//                non-init transactions; is_init_fingerprint keys on
//                attacker-controlled shard strings instead of t_type.
// Remediation:   Reject non-init transactions whose trap shards are empty OR
//                equal to TRAP_NONE_PLACEHOLDER (chain.rs trap gate, next to
//                the existing ':'/'@' hygiene check). Cross-module companion:
//                is_init_fingerprint semantics stay reserved for genuine
//                genesis entries.
// Test Semantics: Builds a REAL voucher + transfer, swaps the spend shards to
//                 the "none"/"none" placeholder pair and re-signs the V3
//                 digest over them with the reproduced input-anchor key
//                 (fully self-consistent attack, no test bypass involved in
//                 the final validation). (A) Chain validation MUST reject the
//                 placeholder-shard spend. (B) Its gossip fingerprint MUST
//                 NOT classify as init. FAILS on unpatched code ((A)
//                 accepted with a validly re-signed digest, (B) classified
//                 genesis). Delimitation vs. audit_02_09 (module-02): that
//                 test covers EMPTY-string striping via serde defaults; THIS
//                 test covers the canonical "none" placeholder over the
//                 reception/validation path.
// =============================================================================
#[test]
fn sa06_11_placeholder_shard_spend_must_fail_reception_validation() {
    use human_money_core::services::conflict_manager::{
        create_fingerprint_for_transaction, encrypt_transaction_timestamp,
        is_init_fingerprint,
    };
    use human_money_core::services::l2_gateway::{
        calculate_l2_payload_hash_raw, TRAP_NONE_PLACEHOLDER,
    };
    use human_money_core::test_utils::derive_holder_key;

    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;

    // Honest fixture: Alice spends the FULL voucher to Bob (bypass ON purely
    // for fixture convenience; the attack itself re-signs everything for real).
    let (mut alice_wallet, source_id) = funded_wallet(alice, "100", &standard_def);
    let bundle_bytes = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &standards_map,
            MultiTransferRequest {
                recipient_id: bob.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: source_id,
                    amount_to_send: "100".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("honest transfer failed")
        .bundle_bytes;
    let mut bob_wallet = test_utils::setup_in_memory_wallet(bob);
    bob_wallet
        .process_encrypted_transaction_bundle(bob, &bundle_bytes, None, &standards_map)
        .expect("honest bundle must process");

    let voucher = bob_wallet
        .voucher_store
        .vouchers
        .values()
        .map(|inst| inst.voucher.clone())
        .find(|v| v.transactions.len() > 1)
        .expect("received voucher with init + spend expected");

    let honest_spend = voucher.transactions.last().unwrap().clone();
    let honest_trap = honest_spend.trap_data.as_ref().expect("spend carries trap");
    assert!(
        !honest_trap.trap_r.is_empty()
            && honest_trap.trap_r != TRAP_NONE_PLACEHOLDER
            && !honest_trap.trap_s.is_empty()
            && honest_trap.trap_s != TRAP_NONE_PLACEHOLDER,
        "Precondition broken: honest spend unexpectedly lacks real shards"
    );
    let ds_tag = honest_trap.ds_tag.clone();

    // Reproduce the spend's input-anchor secret key (deterministic "holder"
    // derivation from the creator key + voucher nonce — public anchor data).
    let holder_key = derive_holder_key(&voucher, &alice.signing_key);
    let eph_b58 = honest_spend
        .sender_ephemeral_pub
        .clone()
        .expect("spend reveals sender_ephemeral_pub");
    assert_eq!(
        bs58::encode(holder_key.verifying_key().to_bytes()).into_string(),
        eph_b58,
        "Precondition broken: holder-key derivation does not reproduce the \
         spend's revealed ephemeral pubkey"
    );

    // THE ATTACK: swap BOTH shards to the canonical genesis placeholder and
    // re-sign the HMC_TX_AUTH_V3 digest over ("none"/"none"). t_id preimage
    // excludes trap_data, so the chain id stays untouched.
    let mut attacked = voucher.clone();
    {
        let layer2_voucher_id =
            human_money_core::services::l2_gateway::extract_layer2_voucher_id(&attacked)
                .expect("layer2 voucher id");
        let spend = attacked.transactions.last_mut().unwrap();
        let trap = spend.trap_data.as_mut().unwrap();
        trap.trap_r = TRAP_NONE_PLACEHOLDER.to_string();
        trap.trap_s = TRAP_NONE_PLACEHOLDER.to_string();

        let eph_bytes: [u8; 32] = bs58::decode(&eph_b58)
            .into_vec()
            .expect("eph base58")
            .try_into()
            .expect("eph len");
        let t_id_bytes: [u8; 32] = bs58::decode(&spend.t_id)
            .into_vec()
            .expect("t_id base58")
            .try_into()
            .expect("t_id len");
        let encrypted_timestamp =
            encrypt_transaction_timestamp(spend).expect("timestamp encryption");

        // The honest flexible-mode spend carries a real privacy guard; its
        // canonical commitment is part of the V3 digest and must stay bound
        // for the re-signed attack fixture to remain chain-consistent.
        let guard_commitment = human_money_core::services::l2_gateway::privacy_guard_commitment(
            spend.privacy_guard.as_deref(),
        );
        let payload_hash = calculate_l2_payload_hash_raw(
            &layer2_voucher_id,
            &ds_tag,
            &t_id_bytes,
            &eph_bytes,
            TRAP_NONE_PLACEHOLDER,
            TRAP_NONE_PLACEHOLDER,
            encrypted_timestamp,
            spend.deletable_at.as_deref(),
            guard_commitment.as_str(),
        );
        let l2_sig = human_money_core::services::crypto::sign_ed25519(
            &holder_key,
            &payload_hash,
        );
        spend.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());
    }

    // Real cryptographic validation from here on (no bypass).
    human_money_core::set_signature_bypass(false);

    // Control: the HONEST chain validates under full verification.
    assert!(
        human_money_core::validate_voucher_against_standard(&voucher, &standard_def).is_ok(),
        "Precondition broken: honest voucher must validate"
    );

    // SECURE INVARIANT A: a non-init transaction carrying the genesis
    // "none"/"none" placeholder shards MUST fail reception validation.
    let outcome = human_money_core::validate_voucher_against_standard(&attacked, &standard_def);
    assert!(
        outcome.is_err(),
        "HMSEC-SA06-11 VIOLATION: accepted a SPEND transaction whose SST trap \
         shards were replaced with the canonical {:?} placeholder pair — SST \
         attribution is optional by format choice (CWE-347). Result: {:?}",
        TRAP_NONE_PLACEHOLDER,
        outcome.err()
    );

    // SECURE INVARIANT B: the resulting gossip fingerprint MUST NOT classify
    // as genesis — otherwise ingress/cleanup/extraction silently skip it.
    let fp = create_fingerprint_for_transaction(
        attacked.transactions.last().unwrap(),
        &attacked,
    )
    .expect("fingerprint creation");
    assert!(
        !is_init_fingerprint(&fp),
        "HMSEC-SA06-11 VIOLATION: is_init_fingerprint classified a PLACEHOLDER-\
         SHARD SPEND fingerprint as genesis — gossip ingress purges it and \
         remote victims never learn of the double-spend fork."
    );
}

/// Shared Wave-3 fixture: builds an importable "gossip soft proof" about an
/// `ephemeral:`-identified double-spender. Two synthetic forks share one fork
/// point and one revealed ephemeral key (single recomputed ds_tag), satisfying
/// every import gate (structure, reporter signature, proof-id consistency;
/// the did:key attribution gate is skipped because the offender identifier is
/// not a did:key). No local voucher context exists, so the proof is stored as
/// an unverified witness note — exactly the transit scenario under audit.
/// `eph_seed` derives the offender's ephemeral key so callers can produce
/// DISTINCT offender identities within one wallet.
fn build_sa06_soft_proof(eph_seed: u8, seed_suffix: &str, reporter_identity: &UserIdentity) ->
    human_money_core::models::conflict::ProofOfDoubleSpend
{
    use human_money_core::models::voucher::{Transaction, TrapData};
    use human_money_core::services::crypto::get_hash_from_slices;

    let prev_hash = get_hash(format!("sa06-fork-{seed_suffix}"));
    let prev_bytes = bs58::decode(&prev_hash).into_vec().expect("fork base58");
    let eph = [eph_seed; 32];
    let eph_b58 = bs58_encode_helper(&eph);
    let ds_tag = get_hash_from_slices(&[&prev_bytes, &eph]);

    let mk_tx = |seed: u8| {
        let mut tx = Transaction {
            trap_data: Some(TrapData {
                ds_tag: ds_tag.clone(),
                trap_r: bs58_encode_helper(&[seed; 32]),
                trap_s: bs58_encode_helper(&[seed.wrapping_add(0x80); 32]),
            }),
            ..Default::default()
        };
        tx.t_id = get_hash(format!("sa06-tid-{seed_suffix}-{seed}"));
        tx.prev_hash = prev_hash.clone();
        tx.t_type = "transfer".to_string();
        tx.amount = "5".to_string();
        tx.t_time = if seed == 1 {
            "2026-01-01T00:00:00Z"
        } else {
            "2026-01-02T00:00:00Z"
        }
        .to_string();
        tx.recipient_id = ACTORS.bob.identity.user_id.clone();
        tx.sender_ephemeral_pub = Some(eph_b58.clone());
        tx
    };

    human_money_core::services::conflict_manager::create_proof_of_double_spend(
        format!("ephemeral:{eph_b58}"),
        prev_hash.clone(),
        vec![mk_tx(1), mk_tx(2)],
        "2099-01-01T00:00:00Z".to_string(),
        reporter_identity,
        false,
    )
    .expect("soft proof fixture creation")
}

// =============================================================================
// FINDING HMSEC-SA06-12 (WH3-06-603, cross-ref A-01 ownership)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-12
// Severity:      High
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature) /
//                CWE-345 (Insufficient Verification of Data Authenticity)
// Target:        src/wallet/queries.rs :: check_reputation (~458-477: status
//                flips to Resolved when resolutions is non-empty OR
//                layer2_verdict is present) +
//                src/wallet/conflict_handler.rs :: add_resolution_endorsement
//                (~230-252: only proof-id existence + id dedupe) +
//                import_proof (never touches resolutions/layer2_verdict).
//                ResolutionEndorsement.victim_signature
//                (src/models/conflict.rs:265) and Layer2Verdict.server_signature
//                (:291) have NO verifier anywhere in src/ (grep-confirmed).
// Threat Model:  Anyone holding ONE legitimate unresolved proof object (or
//                able to build a soft proof with an ephemeral offender) either
//                (a) attaches a self-made ResolutionEndorsement whose
//                victim_signature was produced by an ATTACKER key while
//                claiming the real victim's victim_id, or (b) imports a proof
//                carrying an arbitrary Layer2Verdict with a bogus
//                server_signature. On every importing wallet, check_reputation
//                flips the genuine offender from KnownOffender to Resolved —
//                network-wide reputation laundering through unverified
//                signatures.
// Impact:        The implicit Web-of-Trust is overridden by unauthenticated
//                data: trust-status transitions (the system's central fraud
//                memory) happen without ANY cryptographic verification.
// Root Cause:    Signature fields exist and are dutifully CREATED
//                (create_and_sign_resolution_endorsement), but no read path
//                ever verifies them; resolution state hangs on mere presence.
// Remediation:   Verify victim_signature over endorsement_id against
//                victim_id's permanent key (and bind victim_id to the proof's
//                recipients) before counting an endorsement; verify
//                server_signature over the verdict hash against a trusted L2
//                key before honoring a verdict. Unverifiable entries must not
//                influence check_reputation.
// Test Semantics: Imports two well-formed soft proofs (offenders E1/E2),
//                 baseline-asserts KnownOffender for both, then (a) attaches a
//                 forged endorsement (attacker-signed, victim_id claimed) and
//                 (b) imports a proof with an embedded forged L2 verdict. The
//                 reputation for BOTH offenders MUST remain KnownOffender.
//                 FAILS on unpatched code (both flip to Resolved).
// =============================================================================
#[test]
fn sa06_12_unverified_endorsements_and_verdicts_must_not_flip_reputation() {
    use human_money_core::models::conflict::{Layer2Verdict, TrustStatus};
    use human_money_core::services::utils::get_current_timestamp;

    human_money_core::set_signature_bypass(true);

    let attacker_kp = generate_ed25519_keypair_for_tests(Some("sa06_12_mallory"));
    let attacker = UserIdentity {
        user_id: create_user_id(&attacker_kp.0, Some("mallory")).unwrap(),
        signing_key: attacker_kp.1,
        public_key: attacker_kp.0,
    };
    let mut wallet = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);

    // -------------------------------------------------------------------
    // PRONG 1: forged ResolutionEndorsement (victim_signature by ATTACKER)
    // -------------------------------------------------------------------
    let proof_1 = build_sa06_soft_proof(0x42, "603-endorse", &ACTORS.hacker.identity);
    let offender_1 = proof_1.offender_id.clone();
    let proof_id_1 = proof_1.proof_id.clone();

    wallet
        .import_proof(proof_1)
        .expect("well-formed soft proof must import (baseline)");
    // Baseline control: unresolved proof => KnownOffender.
    assert!(
        matches!(wallet.check_reputation(&offender_1), TrustStatus::KnownOffender(_)),
        "Precondition broken: fresh unresolved proof must yield KnownOffender"
    );

    // THE ATTACK: attacker signs the endorsement with their OWN key but
    // claims the REAL victim identity (bob). No verifier ever notices.
    let mut forged_endorsement =
        human_money_core::services::conflict_manager::create_and_sign_resolution_endorsement(
            &proof_id_1,
            &attacker,
            None,
        )
        .expect("endorsement creation");
    forged_endorsement.victim_id = ACTORS.bob.identity.user_id.clone();

    let _ = wallet.add_resolution_endorsement(forged_endorsement);

    // SECURE INVARIANT 1: reputation MUST NOT flip to Resolved based on an
    // endorsement whose victim_signature does not verify against victim_id.
    assert!(
        matches!(wallet.check_reputation(&offender_1), TrustStatus::KnownOffender(_)),
        "HMSEC-SA06-12 VIOLATION: check_reputation returned Resolved after an \
         ATTACKER-SIGNED endorsement (claiming victim '{}') was attached — \
         victim_signature is never verified (CWE-347).",
        ACTORS.bob.identity.user_id
    );

    // -------------------------------------------------------------------
    // PRONG 2: forged Layer2Verdict smuggled through import_proof
    // -------------------------------------------------------------------
    let mut proof_2 = build_sa06_soft_proof(0x43, "603-verdict", &ACTORS.hacker.identity);
    let offender_2 = proof_2.offender_id.clone();
    let winner_t_id = proof_2.conflicting_transactions[0].t_id.clone();
    proof_2.layer2_verdict = Some(Layer2Verdict {
        server_id: "forged-l2-server".to_string(),
        verdict_timestamp: get_current_timestamp(),
        valid_transaction_id: winner_t_id,
        server_signature: "FORGED_SERVER_SIGNATURE".to_string(),
    });

    wallet
        .import_proof(proof_2)
        .expect("verdict-bearing soft proof must import (baseline: no check)");

    // SECURE INVARIANT 2: an unverifiable L2 verdict MUST NOT override the
    // local maximum-caution assessment.
    assert!(
        matches!(wallet.check_reputation(&offender_2), TrustStatus::KnownOffender(_)),
        "HMSEC-SA06-12 VIOLATION: check_reputation honored a FORGED \
         layer2_verdict (server_signature '{}' never verified) and flipped \
         the offender to Resolved.",
        "FORGED_SERVER_SIGNATURE"
    );
}

// =============================================================================
// FINDING HMSEC-SA06-13 (WH3-06-602)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-13
// Severity:      Medium
// CWE:           CWE-347 / CWE-345 (unbound advisory metadata in a signed
//                object)
// Target:        src/wallet/conflict_handler.rs :: import_proof (~294-360:
//                gates 1-4 never read suspected_identity) +
//                src/services/conflict_manager.rs :: verify_reporter_signature
//                (~360-383: signature covers ONLY proof_id =
//                hash(offender || fork_point_prev_hash)).
// Threat Model:  reporter_signature does not cover suspect_identity (nor
//                report_timestamp, affected_voucher_name, ...). For proofs
//                with ephemeral:/anonymous offenders the attribution gate is
//                skipped entirely, so an in-transit attacker (or malicious
//                gossiper) injects suspected_identity = Some(<innocent
//                third-party did:key>) into an otherwise validly signed proof.
//                The import stores it verbatim and list_conflicts /
//                get_proof_of_double_spend serve the fabricated suspect DID
//                straight into the conflict UI — defamation/framing via the
//                trusted advisory channel, undetectably editable per hop.
// Impact:        Arbitrarily settable "suspect" display in the security UI;
//                violates the documented semantics ("mirrors offender_id upon
//                successful extraction") without breaking any signature.
// Root Cause:    Signature basis too narrow (same root error class as
//                SA06-07): semantic fields of a portable signed object are
//                not bound, and the import gate does not normalize the
//                advisory against the bound extraction.
// Remediation:   On import either (a) reject proofs whose suspected_identity
//                diverges from the cryptographically verified SST extraction /
//                offender linkage, or (b) neutralize the field to None unless
//                it was re-derived locally from the colliding shards.
// Test Semantics: Builds a correctly reporter-signed soft proof, THEN sets
//                 suspected_identity to an innocent third-party did:key
//                 (post-signature tampering that no current gate detects) and
//                 imports it. SOLL: import rejects OR the stored advisory is
//                 neutralized (None / exact offender mirror). FAILS on
//                 unpatched code (accepted verbatim, served back to the UI).
// =============================================================================
#[test]
fn sa06_13_suspected_identity_must_be_bound_or_neutralized_on_import() {
    human_money_core::set_signature_bypass(true);

    let innocent_third_party = &ACTORS.charlie.identity;
    let mut wallet = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);

    // Validly signed proof (reporter signature covers proof_id only).
    let mut tampered = build_sa06_soft_proof(0x44, "602", &ACTORS.hacker.identity);
    let proof_id = tampered.proof_id.clone();
    let offender = tampered.offender_id.clone();

    // THE ATTACK: rewrite the advisory AFTER signing — the reporter signature
    // stays valid because it never covered the field.
    tampered.suspected_identity = Some(innocent_third_party.user_id.clone());

    let outcome = wallet.import_proof(tampered);

    // SECURE INVARIANT: the advisory must not be arbitrarily settable via
    // transit. Either the import is rejected outright, or the stored value
    // is neutralized to None / the exact offender mirror (documented
    // semantics: mirrors offender_id only upon verified extraction).
    let neutralized = match (&outcome, wallet.get_proof_of_double_spend(&proof_id)) {
        (Err(_), _) => true,
        (Ok(()), Ok(stored)) => match stored.suspected_identity.as_deref() {
            None => true,
            Some(s) => s == offender,
        },
        (Ok(()), Err(e)) => panic!(
            "HMSEC-SA06-13: import claimed success but proof '{}' unreadable: {}",
            proof_id, e
        ),
    };
    assert!(
        neutralized,
        "HMSEC-SA06-13 VIOLATION: accepted a proof whose advisory \
         suspected_identity was rewritten in transit to an innocent third \
         party ('{}') — the field is unbound by reporter_signature and never \
         validated on import (CWE-347).",
        innocent_third_party.user_id
    );
}

// =============================================================================
// FINDING HMSEC-SA06-14 (WH3-06-604)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-14
// Severity:      Medium
// CWE:           CWE-359 (Exposure of Private Information) / CWE-345
// Target:        src/services/l2_gateway.rs :: generate_lock_request
//                (~82-111 decode, ~140-158 emission of
//                receiver_ephemeral_pub_hash / change_ephemeral_pub_hash) vs
//                calculate_l2_payload_hash_raw (~280-299: the canonical V3
//                digest does NOT bind these two fields).
// Threat Model:  Every spend lock request publishes the anchor hashes of BOTH
//                output branches (payment + change) to the L2 server (and any
//                MITM). The fields are (a) NOT consumed server-side by the
//                protocol (the reference l2_client_simulator sends None
//                everywhere and passes the compliance sequence), (b) NOT part
//                of the authenticating digest, so they are swappable without
//                breaking the signature (wrapper-vs-payload gap on the L2
//                leg). An observer learns the topology/split-degree of every
//                otherwise-anonymous spend and can reconstruct/correlate the
//                output graph across lock requests.
// Impact:        Metadata-minimization violation on the L2 channel
//                (family/topology linkability of anonymous spends) plus an
//                unauthenticated, entangled field pair on the wire.
// Root Cause:    Fields were copied 1:1 from the transaction into the request
//                without a consumer contract nor digest binding.
// Remediation:   EITHER drop both fields from L2LockRequest (reference-client
//                equivalence proves entitability) OR length-prefix-bind them
//                into calculate_l2_payload_hash_raw so any mutation breaks
//                the layer2_signature.
// Test Semantics: Builds a split-form spend transaction carrying both anchor
//                 hashes, generates the lock request and inspects the sent
//                 structure. SOLL (disjunctive, admits both remediations):
//                 the request contains NEITHER anchor hash, OR the payload
//                 digest CHANGES when an anchor hash is mutated. FAILS on
//                 unpatched code (fields present AND digest-independent).
// =============================================================================
#[test]
fn sa06_14_l2_lock_request_anchors_must_be_absent_or_digest_bound() {
    use human_money_core::models::voucher::{Transaction, TrapData};
    use human_money_core::services::crypto::get_hash_from_slices;
    use human_money_core::services::l2_gateway::{
        calculate_l2_payload_hash, generate_lock_request,
    };
    use human_money_core::services::utils::get_current_timestamp;

    human_money_core::set_signature_bypass(true);

    // Split-form spend transaction: payment branch + change branch.
    let prev_b58 = get_hash("sa06-14-prev");
    let prev_bytes = bs58::decode(&prev_b58).into_vec().expect("prev base58");
    let eph = [0x21u8; 32];
    let eph_b58 = bs58_encode_helper(&eph);
    let ds_tag = get_hash_from_slices(&[&prev_bytes, &eph]);

    let tx = Transaction {
        t_id: get_hash("sa06-14-tid"),
        prev_hash: prev_b58,
        t_type: "split".to_string(),
        t_time: get_current_timestamp(),
        amount: "5".to_string(),
        sender_remaining_amount: Some("5".to_string()),
        recipient_id: ACTORS.bob.identity.user_id.clone(),
        sender_ephemeral_pub: Some(eph_b58),
        receiver_ephemeral_pub_hash: Some(bs58_encode_helper(&[0xA1u8; 32])),
        change_ephemeral_pub_hash: Some(bs58_encode_helper(&[0xB2u8; 32])),
        layer2_signature: Some(bs58_encode_helper(&[0xAAu8; 64])),
        trap_data: Some(TrapData {
            ds_tag,
            trap_r: bs58_encode_helper(&[0x01u8; 32]),
            trap_s: bs58_encode_helper(&[0x02u8; 32]),
        }),
        ..Default::default()
    };

    let req = generate_lock_request("sa06-14-voucher", &tx, &[0x33u8; 32])
        .expect("lock request generation");

    // Precondition (documents the leak): both branch anchors are on the wire.
    // NOTE: intentionally NOT a hard assert — the minimization remediation
    // legitimately removes the fields entirely.
    let anchors_present = req.receiver_ephemeral_pub_hash.is_some()
        || req.change_ephemeral_pub_hash.is_some();

    // SECURE INVARIANT (disjunctive Soll):
    //   (a) METADATA MINIMIZATION: the request must NOT contain receiver-/
    //       change-anchor-derived metadata, OR
    //   (b) AUTHENTICATED BINDING: if present, mutating any anchor hash MUST
    //       change the canonical V3 payload digest (signature coverage).
    let digest_binding = if anchors_present {
        let baseline = calculate_l2_payload_hash(&req);
        let mut tampered = req.clone();
        if let Some(h) = tampered.receiver_ephemeral_pub_hash.as_mut() {
            h[0] ^= 0xFF;
        }
        if let Some(h) = tampered.change_ephemeral_pub_hash.as_mut() {
            h[0] ^= 0xFF;
        }
        calculate_l2_payload_hash(&tampered) != baseline
    } else {
        false
    };

    assert!(
        !anchors_present || digest_binding,
        "HMSEC-SA06-14 VIOLATION: the outgoing L2LockRequest carries \
         receiver_ephemeral_pub_hash/change_ephemeral_pub_hash that are (a) \
         superfluous plaintext topology metadata on the wire (the reference \
         simulator transmits none) and (b) NOT covered by the \
         HMC_TX_AUTH_V3 digest — unauthenticated and linkable across spends \
         (CWE-359/CWE-345)."
    );
}

// =============================================================================
// FINDING HMSEC-SA06-15 (WH3-06-605)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA06-15
// Severity:      Medium
// CWE:           CWE-359 (Exposure of Private Information) / CWE-202
// Target:        src/services/conflict_manager.rs ::
//                create_fingerprint_for_transaction (~29-57 month-rounding,
//                ~97-101 spend assignment) + export_own_fingerprints
//                (~648-654: verbatim serialization into the gossip wire
//                blob).
// Threat Model:  For every spend the fingerprint's deletable_at is the
//                month-end rounding of voucher.valid_until. All transactions
//                of one voucher family (splits, onward transfers, change
//                branches) share the IDENTICAL string, and the export blob
//                publishes it verbatim to gossip peers. A network observer
//                clusters private-mode spends by equal deletable_at values
//                into origin-voucher families and additionally learns the
//                validity month — linkability of exactly the kind Private
//                Mode must prevent (gossip-channel sibling of the
//                unblinded-metadata class). The month rounding defeats
//                exact-time attribution but not family correlation.
// Impact:        Voucher-family linkability across otherwise unlinkable
//                anonymous spends via passive gossip observation.
// Root Cause:    The LOCAL retention deadline (legitimate: cleanup parses
//                RFC3339) doubles as the WIRE field without channel
//                separation or generalization.
// Remediation:   Channel separation: publish a generalized/neutral retention
//                marker (or per-fingerprint randomized deadline with
//                equivalent cleanup semantics) in exported fingerprints;
//                keep the exact voucher-derived value strictly local.
// Test Semantics: Chains one voucher through two independent spenders (Alice
//                 -> Bob -> Charlie), exports BOTH wallets' own-fingerprint
//                 gossip blobs, extracts the spend fingerprints from the wire
//                 format and compares their deletable_at strings. SOLL: two
//                 family spends must NOT publish the same coarse voucher-
//                 derived timestamp. FAILS on unpatched code (identical,
//                 parseable month-rounded string on both blobs).
// =============================================================================
#[test]
fn sa06_15_gossip_wireformat_must_not_link_family_spends_via_deletable_at() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Public);

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;
    let charlie = &ACTORS.charlie.identity;

    // Hop 1: Alice spends the FULL voucher to Bob (Public mode keeps DIDs on
    // the chain so both spend fingerprints land in the owners' own-history).
    let (mut alice_wallet, source_id) = funded_wallet(alice, "100", &standard_def);
    let bundle_1 = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &standards_map,
            MultiTransferRequest {
                recipient_id: bob.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: source_id,
                    amount_to_send: "100".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("hop-1 transfer failed")
        .bundle_bytes;

    // Hop 2: Bob receives and re-spends the SAME voucher family to Charlie.
    let mut bob_wallet = test_utils::setup_in_memory_wallet(bob);
    bob_wallet
        .process_encrypted_transaction_bundle(bob, &bundle_1, None, &standards_map)
        .expect("hop-1 bundle must process");
    let bob_source = bob_wallet
        .voucher_store
        .vouchers
        .values()
        .find(|inst| matches!(inst.status, human_money_core::VoucherStatus::Active))
        .map(|inst| inst.local_instance_id.clone())
        .expect("bob holds an active voucher");
    let _bundle_2 = bob_wallet
        .execute_multi_transfer_and_bundle(
            bob,
            &standards_map,
            MultiTransferRequest {
                recipient_id: charlie.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: bob_source,
                    amount_to_send: "100".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("hop-2 transfer failed");

    // Rebuild + export the GOSSIP WIRE blobs of both family members.
    alice_wallet.scan_and_rebuild_fingerprints().unwrap();
    bob_wallet.scan_and_rebuild_fingerprints().unwrap();
    let blob_a = alice_wallet.export_own_fingerprints().expect("export A");
    let blob_b = bob_wallet.export_own_fingerprints().expect("export B");

    let history_a: HashMap<String, Vec<human_money_core::models::conflict::TransactionFingerprint>> =
        serde_json::from_slice(&blob_a).expect("blob A deserializes");
    let history_b: HashMap<String, Vec<human_money_core::models::conflict::TransactionFingerprint>> =
        serde_json::from_slice(&blob_b).expect("blob B deserializes");

    // Spend fingerprints carry real shards (genesis entries use "none").
    let is_spend = |fp: &human_money_core::models::conflict::TransactionFingerprint| {
        !fp.trap_r.is_empty()
            && fp.trap_r != "none"
            && !fp.trap_s.is_empty()
            && fp.trap_s != "none"
    };
    let spend_a = history_a
        .values()
        .flatten()
        .find(|fp| is_spend(fp))
        .expect("alice's export must contain her spend fingerprint");
    let spend_b = history_b
        .values()
        .flatten()
        .find(|fp| is_spend(fp))
        .expect("bob's export must contain his spend fingerprint");

    // The published values look like coarse RFC3339 timestamps (month-end
    // rounding of the shared voucher.valid_until).
    let looks_like_rfc3339 =
        |s: &str| s.len() >= 20 && s.as_bytes()[10] == b'T' && s.ends_with('Z');

    // SECURE INVARIANT: family spends must not publish the SAME coarse
    // voucher-derived deletion timestamp — otherwise gossip observers link
    // the whole voucher family across hops (CWE-359).
    let linked = spend_a.deletable_at == spend_b.deletable_at
        && looks_like_rfc3339(&spend_a.deletable_at);
    assert!(
        !linked,
        "HMSEC-SA06-15 VIOLATION: gossip wireformat links two spends of the \
         SAME voucher family via the identical voucher-derived deletable_at \
         string ('{}' == '{}') — time anonymization does not prevent family \
         correlation.",
        spend_a.deletable_at,
        spend_b.deletable_at
    );
}

// --- small local encoding helpers -------------------------------------------

fn bs58_encode_helper(bytes: &[u8]) -> String {    bs58::encode(bytes).into_string()
}

fn bs58_decode_helper(s: &str) -> Vec<u8> {
    // Envelope signatures are Base64url (see crypto::encode_base64).
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap_or_default()
}

fn base64_encode_urlsafe(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_decode_urlsafe(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap_or_default()
}
