//! # Security Audit — Module 02: Cryptography, Identity & Forward Secrecy
//!
//! Dedicated fail-first audit tests for the cryptographic core of
//! `human_money_core`. Every finding test asserts the **secure invariant**
//! (Soll-Verhalten). On unpatched code each finding test MUST fail,
//! thereby proving the vulnerability (`cargo nextest run` -> FAIL).
//!
//! ---------------------------------------------------------------------------
//! AUDIT METADATA (standardized docblock)
//! ---------------------------------------------------------------------------
//!
//! ```text
//! Finding-ID:     HMC-SEC-02-01
//! Title:          Missing non-contributory shared-secret rejection in
//!                 decrypt_recipient_payload (asymmetric DH hardening)
//! Severity:       HIGH
//! CWE:            CWE-325 (Missing Required Cryptographic Step)
//! Target:         src/services/crypto_dh.rs::decrypt_recipient_payload
//! Threat Model:   Active attacker (MITM / malicious bundle crafter) can replace
//!                 the `privacy_guard` ephemeral X25519 public key with a
//!                 low-order point (e.g. all-zero curve point). The recipient
//!                 decrypts with their STATIC identity-derived key.
//! Impact:         The DH exchange becomes non-contributory: the shared secret
//!                 collapses to a value fully known to the attacker
//!                 (d*0 = 0 for all recipients), so an attacker can forge a
//!                 validly-decryptable `privacy_guard` containing an
//!                 attacker-chosen `next_key_seed` (RecipientPayload poisoning),
//!                 grief receivers into unusable stealth anchors, and violate
//!                 RFC 7748 Section 6.2 input-validation requirements.
//! Root Cause:     The encryption path (`perform_diffie_hellman`) correctly
//!                 rejects non-contributory results via
//!                 `shared_secret.was_contributory()`, but the decryption path
//!                 calls `StaticSecret::diffie_hellman()` directly and never
//!                 validates the shared secret.
//! Remediation:    After the DH in `decrypt_recipient_payload`, reject exchanges
//!                 whose shared secret is not contributory (all-zero /
//!                 low-order result), mirroring `perform_diffie_hellman`.
//! Test Semantics: Asserts that a hand-forged privacy_guard built under a
//!                 low-order (all-zero) ephemeral key is REJECTED.
//!                 FAIL on unpatched code = vulnerability proven.
//! ```
//!
//! ```text
//! Finding-ID:     HMC-SEC-02-02
//! Title:         Identity parser desync — signature validation accepts
//!                non-canonical signer IDs that validate_user_id rejects
//! Severity:      MEDIUM
//! CWE:           CWE-20 (Improper Input Validation) /
//!                CWE-172 (Encoding Error)
//! Target:        src/services/voucher_validation/signatures.rs::verify_signatures
//!                src/services/crypto_identity.rs::get_pubkey_from_user_id
//! Threat Model:  An attacker submits voucher signatures whose `signer_id` uses
//!                alias representations that are grammatically impossible to
//!                produce via `create_user_id` (e.g. multiple '@' separators,
//!                which `get_pubkey_from_user_id` silently tolerates through
//!                `rfind('@')` while `validate_user_id` rejects them).
//! Impact:        Violates the deterministic-canonicalization invariant of the
//!                Public Key Firewall: malformed identity strings enter signed
//!                containers, enable UI/display spoofing ("looks like" another
//!                party's prefixed account while resolving to the attacker's
//!                raw key) and poison Layer-2 fingerprint correlation, because
//!                the same cryptographic identity circulates under
//!                non-canonical aliases.
//! Root Cause:    `is_signature_valid`/`verify_signatures` resolve the public
//!                key with lenient `get_pubkey_from_user_id` but never enforce
//!                the canonical grammar check `validate_user_id`.
//! Remediation:   Reject any `signer_id` (and creator identity) that fails
//!                `validate_user_id` before key extraction in signature
//!                validation paths.
//! Test Semantics: Builds a cryptographically VALID guarantor signature whose
//!                signer_id contains a double-'@' alias. Asserts validation
//!                rejects it. FAIL on unpatched code = vulnerability proven.
//! ```
//!
//! ```text
//! Finding-ID:     HMC-SEC-02-04
//! Title:          Creator attribution is not cryptographically bound to the
//!                 creator-role signature
//! Severity:       HIGH
//! CWE:            CWE-347 (Improper Verification of Cryptographic Signature)
//!                 / CWE-345 (Insufficient Verification of Data Authenticity)
//! Target:         src/services/voucher_validation/signatures.rs::verify_signatures
//! Threat Model:   An attacker builds a fully self-consistent voucher whose
//!                 `creator_profile.id` names the VICTIM's did:key (a plain
//!                 string that feeds into the voucher_id hash), while the
//!                 creator-role signature itself is produced under the
//!                 ATTACKER's own permanent key. Every validation stage
//!                 passes: voucher hash binding (content includes the victim
//!                 id), signature_id re-computation, Ed25519 verification,
//!                 raw-key dedupe (single entry) and the role whitelist
//!                 (role == "creator" bypasses it entirely).
//! Impact:         Guaranty/reputation fraud: vouchers circulate claiming
//!                 the victim created/guaranteed them. Two "creator"
//!                 signatures under different keys are equally possible
//!                 because the role is never reconciled against
//!                 `voucher.creator_profile.id`.
//! Root Cause:     `verify_signatures` validates each `VoucherSignature`
//!                 only against the key embedded in its own `signer_id`;
//!                 the intended binding check (dead error variant
//!                 `ValidationError::CreatorAsAdditionalSigner`) was never
//!                 wired into the validation loop.
//! Remediation:    For every signature with role == "creator", require that
//!                 the signer's raw 32-byte public key matches the key
//!                 resolved from `voucher.creator_profile.id` (key comparison,
//!                 not string comparison, so root vs. prefixed SAI of the
//!                 SAME key remains legitimate). Fail closed when the
//!                 profile carries no id.
//! Test Semantics: Builds a cryptographically valid creator signature under
//!                 the attacker key inside a voucher attributed to the
//!                 victim. Asserts verify_signatures REJECTS it.
//!                 FAIL on unpatched code = vulnerability proven.
//! ```

//! ```text
//! Finding-ID:     HMC-SEC-02-03 (regression guard)
//! Title:          Ed25519 scalar malleability must be rejected by verification
//! Severity:       INFO (invariant guard)
//! CWE:            CWE-347 (Improper Verification of Cryptographic Signature)
//! Target:         src/services/crypto_utils.rs::verify_ed25519 (ed25519-dalek)
//! Threat Model:   Signature re-encoding attack: given a valid signature (R, s),
//!                 an attacker derives (R, s + L) which naive verifiers accept
//!                 as a DIFFERENT valid signature over the same message.
//! Impact:         If accepted, replay/duplicate-detection keyed on signature
//!                 byte strings can be bypassed and seals/signatures can be
//!                 re-encoded without invalidating them.
//! Test Semantics: Asserts verify_ed25519 REJECTS s+L malleated signatures.
//!                 This documents the verified-secure baseline of the
//!                 ed25519-dalek 2.x dependency; it is expected to PASS.
//! ```

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar as CurveScalar;
use ed25519_dalek::Signature as EdSignature;
use hkdf::Hkdf;
use human_money_core::models::conflict::TransactionFingerprint;
use human_money_core::models::profile::UserIdentity;
use human_money_core::models::voucher::TrapData;
use human_money_core::models::voucher_standard_definition::{
    ImmutableIssuance, ImmutableZone, VoucherStandardDefinition,
};
use human_money_core::services::trap_manager::{
    compute_sst_challenge, compute_trap_message_mu, compute_tau, extract_sst_identity,
    generate_sst_trap, hash_to_scalar, verify_sst_witness, TrapWitness,
};
use human_money_core::services::crypto::constants::HKDF_X25519_EXCHANGE_LABEL;
use human_money_core::services::crypto::{
    create_user_id, decrypt_recipient_payload, ed25519_pub_to_x25519, encrypt_data,
    encrypt_recipient_payload, encode_base64, generate_ed25519_keypair_for_tests,
    get_hash_from_slices, get_hash, sign_ed25519, validate_user_id, verify_ed25519,
};
use human_money_core::services::voucher_validation::verify_signatures;
use human_money_core::{to_canonical_json, Transaction, Voucher, VoucherSignature, SealSyncState, WalletSeal};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Namespace wrapper so the mandated suite filter
/// `cargo nextest run security_audit_module_02` selects every finding test
/// of this module (mirrors the security_audit_module_01 convention).
mod security_audit_module_02 {
    use super::*;


    // ===========================================================================
    // HMC-SEC-02-01 — Non-contributory DH in privacy_guard decryption
    // ===========================================================================

    /// Forges a `privacy_guard` whose ephemeral public key is the all-zero
    /// (low-order) X25519 curve point and asserts the recipient REJECTS it.
    #[test]
    fn audit_02_01_forged_privacy_guard_with_low_order_ephemeral_key_must_be_rejected() {
        let recipient_plaintext = b"{\"next_key_seed\":\"legit-seed-from-real-sender\"}";
        let attacker_plaintext = b"{\"next_key_seed\":\"ATTACKER-CONTROLLED-SEED\"}";

        // --- Setup: legitimate sender -> recipient channel ---
        let (recipient_pk, recipient_sk) = generate_ed25519_keypair_for_tests(Some("audit-02-01-recipient"));
        let recipient_id =
            create_user_id(&recipient_pk, None).expect("Root user id creation must succeed");

        // Sanity: the honest roundtrip works before we forge anything.
        let honest_guard =
            encrypt_recipient_payload(recipient_plaintext, &recipient_pk, &recipient_id)
                .expect("Honest encryption must succeed");
        let honest_opened =
            decrypt_recipient_payload(&honest_guard, &recipient_sk, &recipient_id)
                .expect("Honest decryption must succeed");
        assert_eq!(honest_opened, recipient_plaintext.to_vec());

        // --- Attack: build a guard under the all-zero low-order public key ---
        let zero_pk_bytes = [0u8; 32];
        let zero_pk = X25519PublicKey::from(zero_pk_bytes);

        // The attacker computes the shared secret WITHOUT the recipient's key:
        // any scalar times the zero point is the neutral element.
        let probe_secret = StaticSecret::from([0x42u8; 32]);
        let collapsed_shared = probe_secret.diffie_hellman(&zero_pk);
        assert_eq!(
            collapsed_shared.as_bytes(),
            &[0u8; 32],
            "Precondition broken: zero-point DH did not collapse to the neutral element"
        );

        // Mirror build_hkdf_info exactly: LABEL | recipient_id | sorted(pk_a, pk_b).
        let recipient_x = ed25519_pub_to_x25519(&recipient_pk);
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(HKDF_X25519_EXCHANGE_LABEL);
        info.extend_from_slice(b"|");
        info.extend_from_slice(recipient_id.as_bytes());
        info.extend_from_slice(b"|");
        let (key_a, key_b) = if recipient_x.as_bytes() < zero_pk.as_bytes() {
            (recipient_x.as_bytes(), zero_pk.as_bytes())
        } else {
            (zero_pk.as_bytes(), recipient_x.as_bytes())
        };
        info.extend_from_slice(key_a);
        info.extend_from_slice(key_b);

        let hkdf = Hkdf::<Sha256>::new(None, collapsed_shared.as_bytes());
        let mut attacker_key = [0u8; 32];
        hkdf.expand(&info, &mut attacker_key)
            .expect("HKDF expansion with valid lengths must succeed");

        let forged_ciphertext = encrypt_data(&attacker_key, attacker_plaintext)
            .expect("Attacker-side AEAD encryption must succeed");

        // Wire format: [ephemeral_pk (32)] + [nonce + ciphertext].
        let mut forged_guard_bytes = Vec::with_capacity(32 + forged_ciphertext.len());
        forged_guard_bytes.extend_from_slice(&zero_pk_bytes);
        forged_guard_bytes.extend_from_slice(&forged_ciphertext);
        let forged_guard = encode_base64(&forged_guard_bytes);

        // --- SOLL-VERHALTEN: the forged guard MUST be rejected ---
        match decrypt_recipient_payload(&forged_guard, &recipient_sk, &recipient_id) {
            Ok(poisoned) => panic!(
                "SECURITY VIOLATION HMC-SEC-02-01: decrypt_recipient_payload accepted a \
                 privacy_guard derived from a NON-CONTRIBUTORY (low-order) DH exchange. \
                 An attacker could inject this attacker-controlled RecipientPayload: {:?}",
                String::from_utf8_lossy(&poisoned)
            ),
            Err(_) => {
                // Secure behavior: low-order / non-contributory input rejected.
            }
        }
    }

    // ===========================================================================
    // HMC-SEC-02-02 — Canonical identity firewall for signature validation
    // ===========================================================================

    /// A cryptographically valid guarantor signature carrying a NON-CANONICAL
    /// signer_id (double-'@' alias impossible to produce via `create_user_id`)
    /// must be rejected by voucher signature validation.
    #[test]
    fn audit_02_02_non_canonical_signer_id_must_be_rejected_in_signature_validation() {
        const INIT_T_ID: &str = "audit_02_02_init_transaction_id";
        const VOUCHER_ID: &str = "audit_02_02_voucher_id";

        let (attacker_pk, attacker_sk) =
            generate_ed25519_keypair_for_tests(Some("audit-02-02-attacker"));
        let did_key = create_user_id(&attacker_pk, None).expect("Root did:key must be creatable");

        // Alias representation that the system itself considers INVALID...
        let malformed_signer_id = format!("evil@evil@{}", did_key);
        assert!(
            !validate_user_id(&malformed_signer_id),
            "Precondition broken: test alias unexpectedly passes validate_user_id"
        );
        // ...but which the lenient parser still resolves to the attacker's key.
        assert!(human_money_core::services::crypto::get_pubkey_from_user_id(
            &malformed_signer_id
        )
        .is_ok());

        // Build a fully VALID detached-style signature bound to the alias string.
        let mut sig = VoucherSignature {
            voucher_id: VOUCHER_ID.to_string(),
            signature_id: String::new(),
            signer_id: malformed_signer_id.clone(),
            signature: String::new(),
            signature_time: "2026-01-01T00:00:00Z".to_string(),
            role: "guarantor".to_string(),
            details: None,
        };
        sig.signature_id = get_hash_from_slices(&[
            to_canonical_json(&sig).expect("Canonical JSON must serialize").as_bytes(),
            INIT_T_ID.as_bytes(),
        ]);
        let digital_sig = sign_ed25519(&attacker_sk, sig.signature_id.as_bytes());
        sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();

        let voucher = Voucher {
            voucher_id: VOUCHER_ID.to_string(),
            creation_date: "2025-01-01T00:00:00Z".to_string(),
            transactions: vec![Transaction {
                t_id: INIT_T_ID.to_string(),
                ..Default::default()
            }],
            signatures: vec![sig],
            ..Default::default()
        };

        let standard = VoucherStandardDefinition {
            immutable: ImmutableZone {
                issuance: ImmutableIssuance {
                    additional_signatures_range: vec![1, 1],
                    allowed_signature_roles: vec!["guarantor".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        // --- SOLL-VERHALTEN: non-canonical identities MUST NOT pass validation ---
        match verify_signatures(&voucher, &standard) {
            Ok(()) => panic!(
                "SECURITY VIOLATION HMC-SEC-02-02: verify_signatures accepted a voucher \
                 signature whose signer_id '{}' violates the canonical identity grammar \
                 (validate_user_id == false). Non-canonical alias representations bypass \
                 the Public Key Firewall.",
                malformed_signer_id
            ),
            Err(_) => {
                // Secure behavior: canonical identity enforcement active.
            }
        }
    }

    // ===========================================================================
    // HMC-SEC-02-03 — Ed25519 malleability regression guard (verified secure)
    // ===========================================================================

    /// Asserts that `verify_ed25519` rejects malleated signatures (s' = s + L).
    /// This documents the verified-secure baseline; it is expected to PASS.
    #[test]
    fn audit_02_03_ed25519_scalar_malleability_must_be_rejected() {
        // Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
        // (little-endian byte representation).
        const GROUP_ORDER_L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];

        let message = b"HMC security audit module 02 - malleability probe";
        let (public_key, signing_key) =
            generate_ed25519_keypair_for_tests(Some("audit-02-03-malleability"));

        let original = sign_ed25519(&signing_key, message);
        assert!(verify_ed25519(&public_key, message, &original));

        // Craft s' = s + L (little-endian addition, no wraparound possible since
        // s < L < 2^253 => s + L < 2^254).
        let mut raw = original.to_bytes();
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = raw[32 + i] as u16 + GROUP_ORDER_L[i] as u16 + carry;
            raw[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "Malleated scalar must not overflow 256 bits");

        let malleated = EdSignature::from_bytes(&raw);

        // --- SOLL-VERHALTEN: the re-encoded signature MUST be rejected ---
        assert!(
            !verify_ed25519(&public_key, message, &malleated),
            "SECURITY VIOLATION HMC-SEC-02-03: verify_ed25519 accepted a malleated \
             signature (s + L). Signature bytes are not canonical, breaking \
             replay/duplicate detection keyed on signature encodings."
        );
    }

    // ===========================================================================
    // HMC-SEC-02-04 — Creator attribution must be cryptographically bound
    // ===========================================================================

    /// A voucher attributing creation to a VICTIM's did:key while carrying a
    /// cryptographically valid creator-role signature under the ATTACKER's key
    /// must be rejected by `verify_signatures`.
    #[test]
    fn audit_02_04_forged_creator_attribution_must_be_rejected_in_signature_validation() {
        const INIT_T_ID: &str = "audit_02_04_init_transaction_id";
        const VOUCHER_ID: &str = "audit_02_04_voucher_id";

        let (victim_pk, _) = generate_ed25519_keypair_for_tests(Some("audit-02-04-victim"));
        let victim_did =
            create_user_id(&victim_pk, None).expect("Victim root did:key must be creatable");

        let (attacker_pk, attacker_sk) =
            generate_ed25519_keypair_for_tests(Some("audit-02-04-attacker"));
        let attacker_did =
            create_user_id(&attacker_pk, None).expect("Attacker root did:key must be creatable");

        assert_ne!(
            victim_pk.as_bytes(),
            attacker_pk.as_bytes(),
            "Precondition broken: victim and attacker keys must differ"
        );

        // Fully self-consistent creator signature UNDER THE ATTACKER KEY...
        let mut sig = VoucherSignature {
            voucher_id: VOUCHER_ID.to_string(),
            signature_id: String::new(),
            signer_id: attacker_did.clone(),
            signature: String::new(),
            signature_time: "2026-01-01T00:00:00Z".to_string(),
            role: "creator".to_string(),
            details: None,
        };
        sig.signature_id = get_hash_from_slices(&[
            to_canonical_json(&sig).expect("Canonical JSON must serialize").as_bytes(),
            INIT_T_ID.as_bytes(),
        ]);
        let digital_sig = sign_ed25519(&attacker_sk, sig.signature_id.as_bytes());
        sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();

        // ...embedded in a voucher whose creator PROFILE names the VICTIM.
        let voucher = Voucher {
            voucher_id: VOUCHER_ID.to_string(),
            creation_date: "2025-01-01T00:00:00Z".to_string(),
            transactions: vec![Transaction {
                t_id: INIT_T_ID.to_string(),
                ..Default::default()
            }],
            signatures: vec![sig],
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(victim_did.clone()),
                ..Default::default()
            },
            ..Default::default()
        };

        let standard = VoucherStandardDefinition {
            immutable: ImmutableZone {
                issuance: ImmutableIssuance {
                    additional_signatures_range: vec![0, 5],
                    allowed_signature_roles: vec!["guarantor".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        // --- SOLL-VERHALTEN: forged creator attribution MUST NOT pass ---
        match verify_signatures(&voucher, &standard) {
            Ok(()) => panic!(
                "SECURITY VIOLATION HMC-SEC-02-04: verify_signatures accepted a voucher \
                 attributed to creator '{}' while its creator-role signature is bound to \
                 the DIFFERENT key '{}'. Creator attribution is not cryptographically \
                 anchored (guaranty/reputation fraud vector).",
                victim_did, attacker_did
            ),
            Err(_) => {
                // Secure behavior: creator-role signatures must resolve to the
                // exact key named in creator_profile.id.
            }
        }
    }

    // ===========================================================================
    // HMC-SEC-02-05 — Seal fork detection at unverifiable nonce distance
    // ===========================================================================

    /// Builds a deterministic test identity for seal scenarios.
    fn audit_02_05_identity(seed: &str) -> UserIdentity {
        let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some(seed));
        let user_id = create_user_id(&public_key, None).expect("Root did:key must be creatable");
        UserIdentity {
            signing_key,
            public_key,
            user_id,
        }
    }

    /// PENDING ARCHITECTURAL FIX (do not silently delete): a divergent seal chain
    /// whose nonce is more than +1 ahead of the local chain CANNOT be verified
    /// against the local hash chain, yet `compare_seals` optimistically reports
    /// `RemoteIsNewer`/`LocalIsNewer` ("nonce ordering" heuristic). This swallows
    /// genuine multi-device forks (cloned wallet / restored backup) that the
    /// documented ForkDetected hard-lock invariant (models/seal.rs) exists to
    /// catch. Closing the gap without breaking legitimate multi-step catch-up
    /// requires fetching and walking intermediate seals from Layer 2 — an
    /// architectural redesign beyond this module's scope. Until then this test
    /// asserts the secure invariant and stays ignored.
    #[test]
    #[ignore = "pending architectural fix - see report"]
    fn audit_02_05_divergent_chain_at_unverifiable_nonce_distance_must_be_fork() {
        let identity = audit_02_05_identity("audit-02-05-seal");

        // Common genesis: both devices start from the same base seal (nonce 0).
        let base = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("audit-02-05-base-state"),
            "device_a",
        )
        .expect("Base seal creation must succeed");

        // Local branch: one honest transaction -> nonce 1.
        let local = base.update(
            &identity,
            &get_hash("audit-02-05-local-state"),
            "device_a",
        )
        .expect("Local seal update must succeed");

        // Remote branch: five honest transactions from the SAME base -> nonce 5.
        let mut remote = base.update(
            &identity,
            &get_hash("audit-02-05-remote-state-1"),
            "device_b",
        )
        .expect("Remote seal update must succeed");
        for i in 2..=5 {
            remote = remote.update(
                &identity,
                &get_hash(format!("audit-02-05-remote-state-{}", i)),
                "device_b",
            )
            .expect("Remote seal update must succeed");
        }

        assert_eq!(local.payload.tx_nonce, 1);
        assert_eq!(remote.payload.tx_nonce, 5);
        assert_ne!(
            remote.payload.prev_seal_hash,
            local.compute_hash().expect("Seal hash must compute"),
            "Precondition broken: chains unexpectedly link up"
        );

        // --- SOLL-VERHALTEN: an unverifiable divergent chain MUST be a fork ---
        assert_eq!(
            WalletSeal::compare_seals(&local, &remote),
            SealSyncState::ForkDetected,
            "SECURITY VIOLATION HMC-SEC-02-05: compare_seals resolved a divergent \
             chain at nonce distance > +1 as 'newer' instead of ForkDetected. The \
             multi-device fork hard lock is bypassed whenever the distance exceeds \
             direct verifiability."
        );
    }

    /// Control (expected to PASS): a direct-successor divergence (nonce exactly
    /// +1) whose prev_seal_hash does not reference the local seal MUST be
    /// reported as ForkDetected. Pins the strict branch so the pending
    /// architectural fix cannot regress it.
    #[test]
    fn audit_02_05_control_direct_successor_divergence_must_be_fork() {
        let identity = audit_02_05_identity("audit-02-05-seal-control");

        let local = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("audit-02-05-control-local"),
            "device_a",
        )
        .expect("Local base seal creation must succeed");

        // Divergent sibling genesis on another device, advanced by one step.
        let sibling_base = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("audit-02-05-control-sibling"),
            "device_b",
        )
        .expect("Sibling base seal creation must succeed");
        let remote = sibling_base.update(
            &identity,
            &get_hash("audit-02-05-control-remote"),
            "device_b",
        )
        .expect("Remote seal update must succeed");

        assert_eq!(remote.payload.tx_nonce, local.payload.tx_nonce + 1);
        assert_eq!(
            WalletSeal::compare_seals(&local, &remote),
            SealSyncState::ForkDetected,
            "Direct-successor divergence must keep triggering ForkDetected."
        );
    }

    // ===========================================================================
    // HMC-SEC-02-06 — Empty-prefix / separator-less identity aliases
    // ===========================================================================

    /// Identity strings of the form `:<checksum>@did:key:z...` (empty prefix)
    /// or `<checksum>@did:key:z...` (missing ':' separator) are grammatically
    /// impossible to produce via `create_user_id`, yet the validator accepted
    /// them: the empty-prefix form skips ALL prefix grammar checks and its
    /// checksum binds to "" + did (publicly computable), while
    /// `get_prefix_from_user_id` maps the empty-prefix form to None — making it
    /// an ALIAS representation of the root identity. Same vulnerability class
    /// as the remediated double-'@' parser desync (HMC-SEC-02-02), reached
    /// through a different parser path.
    #[test]
    fn audit_02_06_empty_prefix_and_separator_less_aliases_must_be_rejected() {
        let (pk, _) = generate_ed25519_keypair_for_tests(Some("audit-02-06-forge"));
        let did = create_user_id(&pk, None).expect("Root did:key must be creatable");
        assert!(validate_user_id(&did), "Precondition broken: root id must validate");

        // Mirror the checksum derivation exactly: last 3 base58 chars of
        // SHA3-256(prefix || did_key_part). For both attack forms prefix = "",
        // so any third party can compute a matching checksum.
        let hash = get_hash(did.as_bytes());
        let checksum = &hash[hash.len() - 3..];

        // Attack form A: empty-prefix form ':checksum@did:key:...'
        let empty_prefix_form = format!(":{}@{}", checksum, did);

        // Attack form B: separator-less form 'checksum@did:key:...' claiming an
        // arbitrary prefix name under a checksum derived from the EMPTY prefix.
        let separator_less_form = format!("{}@{}", checksum, did);

        // Documented aliasing effect of form A on the UNPATCHED code path basis:
        // get_prefix_from_user_id treats it as a root-equivalent identity.
        assert_eq!(
            human_money_core::services::crypto::identity::get_prefix_from_user_id(&empty_prefix_form),
            None,
            "Precondition: the empty-prefix form resolves as a root alias"
        );

        // --- SOLL-VERHALTEN: neither alias form MAY pass validation ---
        assert!(
            !validate_user_id(&empty_prefix_form),
            "SECURITY VIOLATION HMC-SEC-02-06: validate_user_id accepted the \
             empty-prefix form '{}'. It bypasses the canonical grammar (no valid \
             prefix exists that could produce it) and aliases to the ROOT identity.",
            empty_prefix_form
        );
        assert!(
            !validate_user_id(&separator_less_form),
            "SECURITY VIOLATION HMC-SEC-02-06: validate_user_id accepted the \
             separator-less form '{}' which claims an arbitrary prefix name under \
             a checksum computed against the empty prefix.",
            separator_less_form
        );

        // Positive control: the honestly produced prefixed ID still validates.
        let honest = create_user_id(&pk, Some("audit-context")).expect("Prefix id must be creatable");
        assert!(validate_user_id(&honest), "Honest prefixed id must remain valid");
    }

    // ===========================================================================
    // HMC-SEC-02-07 — Mutation-gap regression guards (expected to PASS)
    // ===========================================================================

    /// ```text
    /// Finding-ID:     HMC-SEC-02-07 (regression guards / mutant killers)
    /// Title:          Identity grammar, HKDF SAI-binding and short-hash index
    ///                 logic lack behavioral pinning (surviving mutants)
    /// Severity:       MEDIUM
    /// CWE:            CWE-345 (Insufficient Verification of Data Authenticity)
    /// Target:         src/services/crypto_identity.rs::validate_user_id
    ///                 src/services/crypto_dh.rs::build_hkdf_info
    ///                 src/services/crypto_utils.rs::get_short_hash_from_user_id
    /// Threat Model:   Mutation analysis reports surviving mutants in three
    ///                 clusters: (a) inverted/skipped prefix grammar checks in
    ///                 validate_user_id, (b) removed recipient_id binding or
    ///                 broken pk canonical ordering in build_hkdf_info (would
    ///                 enable cross-SAI key reuse), (c) corrupted tail-copy
    ///                 index logic in get_short_hash_from_user_id silently
    ///                 collapsing peer heuristics to constant values.
    /// Impact:         Without behavioral pins, security-relevant refactors can
    ///                 silently disable the canonical identity firewall, the
    ///                 SAI separation of DH-derived keys, or deterministic peer
    ///                 tracking without any failing test.
    /// Root Cause:     Test gap, not a code defect: no assertions existed that
    ///                 fail when these checks are mutated away.
    /// Remediation:    Pin the secure behavior with deterministic invariant
    ///                 assertions so every listed mutant class is killed.
    /// Test Semantics: Control/regression suite asserting the SECURE baseline.
    ///                 Expected to PASS on correct code; any failure indicates
    ///                 a regression introduced by refactoring.
    /// ```
    #[test]
    fn audit_02_07_identity_hkdf_and_short_hash_invariants_are_pinned() {
        // --- (a) Canonical grammar negation class: validate_user_id ---
        let (pk, _) = generate_ed25519_keypair_for_tests(Some("audit-02-07-grammar"));
        let honest_prefixed =
            create_user_id(&pk, Some("audit-context")).expect("Prefixed id must be creatable");

        // Uppercase prefixes are unproducible (create_user_id lowercases input)
        // and MUST be rejected by the validator.
        let uppercased = {
            let at = honest_prefixed.find('@').expect("'@' separator must exist");
            format!("{}{}", honest_prefixed[..at].to_uppercase(), &honest_prefixed[at..])
        };
        assert!(
            !validate_user_id(&uppercased),
            "REGRESSION HMC-SEC-02-07a: validate_user_id accepted an uppercase \
             prefix, which create_user_id can never produce."
        );

        // A checksum computed over a DIFFERENT did part must not validate for a
        // substituted key (did/checksum swap attack).
        let (other_pk, _) = generate_ed25519_keypair_for_tests(Some("audit-02-07-other"));
        let other_did = create_user_id(&other_pk, None).expect("Root did:key must be creatable");
        let at = honest_prefixed.find('@').unwrap();
        let swapped_did = format!("{}@{}", &honest_prefixed[..at], other_did);
        assert!(
            !validate_user_id(&swapped_did),
            "REGRESSION HMC-SEC-02-07a: validate_user_id accepted an id whose \
             checksum was not derived from its did:key payload."
        );

        // --- (b) HKDF info SAI-binding and canonical key ordering ---
        let (ed_a, sk_a) = generate_ed25519_keypair_for_tests(Some("audit-02-07-hkdf-a"));
        let (ed_b, _) = generate_ed25519_keypair_for_tests(Some("audit-02-07-hkdf-b"));
        let x_a = ed25519_pub_to_x25519(&ed_a);
        let x_b = ed25519_pub_to_x25519(&ed_b);

        // Symmetry: sender and receiver must derive identical context strings.
        assert_eq!(
            human_money_core::services::crypto::build_hkdf_info(&x_a, &x_b, "sai:one"),
            human_money_core::services::crypto::build_hkdf_info(&x_b, &x_a, "sai:one"),
            "REGRESSION HMC-SEC-02-07b: build_hkdf_info lost argument-order symmetry"
        );
        // Sensitivity: different SAI contexts MUST produce different info strings,
        // otherwise keys derived for one account alias are reused across SAIs.
        assert_ne!(
            human_money_core::services::crypto::build_hkdf_info(&x_a, &x_b, "sai:one"),
            human_money_core::services::crypto::build_hkdf_info(&x_a, &x_b, "sai:two"),
            "REGRESSION HMC-SEC-02-07b: build_hkdf_info ignored the recipient_id \
             (SAI-binding removed)"
        );

        // End-to-end: decrypting under a WRONG recipient_id must fail closed.
        let plaintext = b"{\"next_key_seed\":\"audit-02-07\"}";
        let guard = encrypt_recipient_payload(plaintext, &ed_a, "sai:correct")
            .expect("Honest encryption must succeed");
        assert!(
            decrypt_recipient_payload(&guard, &sk_a, "sai:wrong").is_err(),
            "REGRESSION HMC-SEC-02-07b: decrypt_recipient_payload succeeded with a \
             recipient_id differing from the encryption-time SAI binding"
        );
        // Honest control: correct recipient_id still round-trips.
        assert_eq!(
            decrypt_recipient_payload(&guard, &sk_a, "sai:correct")
                .expect("Honest decryption must succeed"),
            plaintext.to_vec(),
            "Honest round-trip broke while wrong-id rejection is pinned"
        );

        // --- (c) Short-hash index logic pinned against a reference computation ---
        let user_id = "audit-context:some-checksum@did:key:zAudit0207Peer";
        let short_hash =
            human_money_core::services::crypto::get_short_hash_from_user_id(user_id);

        // Reference: SHA3-256 -> Base58 string -> decode -> LAST 4 bytes.
        let mut hasher = sha3::Sha3_256::new();
        use sha2::Digest as _;
        hasher.update(user_id.as_bytes());
        let raw32: [u8; 32] = hasher.finalize().into();
        let decoded = bs58::decode(bs58::encode(raw32).into_string())
            .into_vec()
            .expect("Reference Base58 round-trip must succeed");
        let expected_tail: [u8; 4] = decoded[decoded.len() - 4..]
            .try_into()
            .expect("Reference tail slice must be exactly 4 bytes");

        assert_ne!(short_hash, [0u8; 4], "Short hash must never collapse to all zeros");
        assert_eq!(
            short_hash, expected_tail,
            "REGRESSION HMC-SEC-02-07c: get_short_hash_from_user_id deviates from \
             the documented 'last 4 bytes' derivation"
        );
    }

    // ===========================================================================
    // HMC-SEC-02-08 — Off-line fabricated SST shards evade EUF-CMA attribution
    // ===========================================================================

    // ```text
    // Finding-ID:     HMC-SEC-02-08
    // Title:          Off-line fabricated shard pairs evade the SST EUF-CMA
    //                 attribution; junk extraction becomes a definitive did:key
    //                 offender claim
    // Severity:       HIGH
    // CWE:            CWE-347 (Improper Verification of Cryptographic Signature)
    //                 / CWE-345 (Insufficient Verification of Data Authenticity)
    // Target:         src/services/trap_manager.rs::reconstruct_identity (~389-437)
    //                 src/wallet/conflict_handler.rs::verify_and_create_proof (~749-767)
    //
    // Threat Model & Exploitation:
    //   A modified-client double-spender publishes fork B entirely off-line:
    //   they pick arbitrary (R_B, s_B) values (or even a Schnorr-valid line
    //   under their own key) instead of running generate_sst_trap. Gossip
    //   collision analysis parses shards with only "decompressable point +
    //   canonical scalar" checks, so the fabricated pair reconstructs a junk
    //   masking point M_R-hat. The extracted identity point x_hat is therefore
    //   an arbitrary curve element - yet conflict_handler accepts any
    //   VerifyingKey-parseable point as the DEFINITIVE offender did:key.
    //
    // Impact Analysis:
    //   (a) The real double-spender evades did:key attribution completely:
    //       replacing ONE honest fork with a fabricated one turns every
    //       extraction into a random junk identity ("extraction IS the proof"
    //       only holds under honest shard generation).
    //   (b) The signed ProofOfDoubleSpend store is poisoned with meaningless,
    //       random offender identities (reputation noise) while the protocol
    //       declares them EUF-CMA-proven.
    //   Framing a CHOSEN innocent victim remains impossible (that direction of
    //   the invariant holds), but un-attributable evasion is free.
    //
    // Root Cause:
    //   reconstruct_identity never validates that the reconstructed masking
    //   point M_R-hat or the extracted identity x_hat live in the prime-order
    //   subgroup (torsion-free). Honest shards always satisfy this: M_R comes
    //   from hash_to_curve (prime-order output) and real keys are clamped
    //   scalars times the basepoint. The consumer additionally treats a bare
    //   VerifyingKey::from_bytes success as definitive attribution without any
    //   corroboration requirement.
    //
    // Remediation Strategy:
    //   1. Primitive level (this module): reject torsion-carrying M_R-hat /
    //      x_hat in reconstruct_identity. Kills the naive garbage-shard class.
    //   2. Protocol level (PENDING architectural decision): a Schnorr-valid
    //      off-line line under the spender's own key is indistinguishable from
    //      an honest line without knowledge of x; definitive attribution needs
    //      a corroboration policy (e.g. n>=3 full-set consistency or downgrade
    //      to suspected_identity). Tracked as CONFIRMED-PENDING.
    //
    // Test Semantics (Fail-First):
    //   Part 1 (active): a collision between an honest fork and a naive junk
    //     fork must NOT yield a usable Ed25519 identity. FAIL on unpatched
    //     code = vulnerability proven.
    //   Part 2 (ignored): a fully Schnorr-valid off-line line passes
    //     verify_sst_witness and poisons extraction; requires the protocol-
    //     level fix above.
    // ```

    /// Derives deterministic 32-byte test material by counter-repeating SHA3-256.
    fn audit_02_08_deterministic_bytes(label: &str, counter: u8) -> [u8; 32] {
        use sha2::Digest as _;
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(label.as_bytes());
        hasher.update([counter]);
        hasher.finalize().into()
    }

    /// Naive off-line fabrication: a junk shard pair must not produce a usable
    /// offender identity through autonomous SST extraction.
    #[test]
    fn audit_02_08_offline_fabricated_junk_collision_must_not_yield_usable_offender_identity() {
        use human_money_core::services::crypto::get_hash;

    let (_payer_pk, payer_sk) =
        generate_ed25519_keypair_for_tests(Some("audit-02-08-junk-spender"));
        let ds_tag = get_hash("audit-02-08-input-state");
        let eph: [u8; 32] = audit_02_08_deterministic_bytes("audit-02-08-eph", 0);

        // Honest fork A generated with the REAL spend routine.
        let t_id_a = get_hash("audit-02-08-tid-a");
        let (trap_a, _) = generate_sst_trap(&payer_sk, &ds_tag, &eph, &t_id_a)
            .expect("Honest trap generation must succeed");
        let fp_a = TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id: t_id_a,
            trap_r: trap_a.trap_r.clone(),
            trap_s: trap_a.trap_s.clone(),
            ..Default::default()
        };

        // Off-line junk fork B: pick compressed bytes until they decode into a
        // torsion-carrying curve point (deterministic counter loop).
        let mut junk_point: Option<(EdwardsPoint, String)> = None;
        for counter in 0..u8::MAX {
            let candidate = audit_02_08_deterministic_bytes("audit-02-08-junk-r", counter);
            if let Some(point) = CompressedEdwardsY::from_slice(&candidate)
                .expect("32 bytes are a valid encoding length")
                .decompress()
                && !point.is_torsion_free() {
                    junk_point = Some((point, bs58::encode(candidate).into_string()));
                    break;
                }
        }
        let (junk_r_point, junk_r_b58) =
            junk_point.expect("Precondition broken: no torsion-carrying test point found");

        // Canonical scalar encoding (< group order), e.g. 0x0101...01.
        let junk_s_bytes = [0x01u8; 32];
        assert!(
            CurveScalar::from_canonical_bytes(junk_s_bytes).into_option().is_some(),
            "Precondition broken: junk scalar fixture is not canonical"
        );

        let fp_b = TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id: get_hash("audit-02-08-tid-b"),
            trap_r: junk_r_b58,
            trap_s: bs58::encode(junk_s_bytes).into_string(),
            ..Default::default()
        };

        // Sanity: both fingerprints claim the same collision context.
        assert_ne!(fp_a.trap_r, fp_b.trap_r);

        // --- SOLL-VERHALTEN: the junk collision MUST NOT yield a usable identity ---
        match extract_sst_identity(&ds_tag, &eph, &fp_a, &fp_b) {
            Err(_) => {
                // Secure behavior: fabricated/torsion-carrying reconstruction
                // rejected at the primitive level.
            }
            Ok(x_hat) => {
                let pk_bytes = x_hat.compress().to_bytes();
                if ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).is_ok() {
                    panic!(
                        "SECURITY VIOLATION HMC-SEC-02-08: extract_sst_identity accepted \
                         a collision containing an OFF-LINE FABRICATED junk shard and \
                         produced a parseable Ed25519 identity point. conflict_handler \
                         promotes exactly such points to the DEFINITIVE offender did:key \
                         of a signed ProofOfDoubleSpend — misattribution/reputation \
                         poisoning with zero cryptographic meaning. Junk R_B decoded to \
                         torsion-free={}.",
                        junk_r_point.is_torsion_free()
                    );
                }
            }
        }

        // Document the primitive precondition used by the remediation: honest
        // shard points are ALWAYS torsion-free (subgroup-closed arithmetic), so
        // the subgroup guard cannot break legitimate collisions.
        let honest_r_bytes: [u8; 32] = bs58::decode(&trap_a.trap_r)
            .into_vec()
            .expect("Honest shard must be valid Base58")
            .try_into()
            .expect("Honest shard point must be 32 bytes");
        let honest_point = CompressedEdwardsY::from_slice(&honest_r_bytes)
            .expect("32 bytes are a valid encoding length")
            .decompress()
            .expect("Honest shard point must decompress");
        assert!(
            honest_point.is_torsion_free(),
            "Honest shard points must remain torsion-free for the subgroup guard"
        );
    }

    /// PENDING PROTOCOL DECISION (do not silently delete): a modified-client
    /// double-spender can fabricate a fork whose line carries a VALID Schnorr
    /// signature under their own (payer) key plus freshly solved masking values.
    /// verify_sst_witness verifies signature validity + internal shard
    /// consistency, but CANNOT check the deterministic derivation of M_R/m_s
    /// (those bind to the private key x). Consequently the L1 handover accepts
    /// the fabricated line and gossip extraction yields a junk identity that the
    /// current conflict handler still promotes to a definitive offender did:key.
    /// Closing this requires a protocol-level corroboration policy (e.g. n>=3
    /// full-set consistency before definitive attribution, or documented
    /// downgrade semantics) — beyond primitive-level hardening.
    #[test]
    #[ignore = "pending architectural/protocol decision - see report"]
    fn audit_02_08_schnorr_valid_offline_line_passes_l1_witness_and_poisons_attribution() {
        use human_money_core::services::crypto::{get_hash, get_secret_scalar};

        let (payer_pk, payer_sk) =
            generate_ed25519_keypair_for_tests(Some("audit-02-08-schnorr-spender"));
        let payer_did =
            create_user_id(&payer_pk, None).expect("Root did:key must be creatable");
        let ds_tag = get_hash("audit-02-08-input-state-s");
        let eph: [u8; 32] = audit_02_08_deterministic_bytes("audit-02-08-eph-s", 1);
        let mu = compute_trap_message_mu(&ds_tag, &eph);

        // Honest fork A.
        let t_id_a = get_hash("audit-02-08-tid-a-s");
        let (trap_a, _) = generate_sst_trap(&payer_sk, &ds_tag, &eph, &t_id_a)
            .expect("Honest trap generation must succeed");
        let _ = trap_a;

        // Fully fabricated fork B carrying a VALID Schnorr signature under the
        // attacker's own key:
        let t_id_b = get_hash("audit-02-08-tid-b-s");
        let x = get_secret_scalar(&payer_sk);
        let tau_b = compute_tau(&ds_tag, &t_id_b);

        let r_star = hash_to_scalar(b"audit-02-08 fresh nonce r*");
        let r_sig_star = r_star * ED25519_BASEPOINT_POINT;
        let c_star = compute_sst_challenge(&mu, &r_sig_star);
        let s_sig_star = r_star + c_star * x;

        // Choose the published shard on the main subgroup so every reconstructed
        // value stays torsion-free (defeats subgroup guards by design).
        let k = hash_to_scalar(b"audit-02-08 shard selector k");
        let r_b = k * ED25519_BASEPOINT_POINT;
        let s_b = hash_to_scalar(b"audit-02-08 shard response s_b");

        let m_r_star = (r_b - r_sig_star) * tau_b.invert();
        let m_s_star = (s_b - s_sig_star) * tau_b.invert();

        let witness_b = TrapWitness {
            r_sig: bs58::encode(r_sig_star.compress().as_bytes()).into_string(),
            s_sig: bs58::encode(s_sig_star.as_bytes()).into_string(),
            m_r: bs58::encode(m_r_star.compress().as_bytes()).into_string(),
            m_s: bs58::encode(m_s_star.as_bytes()).into_string(),
        };
        let trap_b = TrapData {
            ds_tag: ds_tag.clone(),
            trap_r: bs58::encode(r_b.compress().as_bytes()).into_string(),
            trap_s: bs58::encode(s_b.as_bytes()).into_string(),
        };

        // --- SOLL-VERHALTEN: the L1 handover MUST reject the fabricated line ---
        match verify_sst_witness(&witness_b, &trap_b, &payer_did, &ds_tag, &eph, &t_id_b) {
            Ok(()) => panic!(
                "SECURITY VIOLATION HMC-SEC-02-08: verify_sst_witness accepted an \
                 OFF-LINE FABRICATED trap line whose masking values were solved from \
                 arbitrary shard choices. The recipient's fraud-prevention gate (R5) \
                 cannot distinguish it from an honest line, enabling attribution \
                 evasion via junk-extraction poisoning."
            ),
            Err(_) => {
                // Secure behavior after the protocol-level corroboration fix.
            }
        }
    }

    // =======================================================================
    // HMC-SEC-02-09 — Shard striping via serde defaults
    // =======================================================================

    // ```text
    // Finding-ID:     HMC-SEC-02-09
    // Title:          Spends with empty trap_r/trap_s (serde default) pass the
    //                 full chain validation and masquerade as init fingerprints
    // Severity:       MEDIUM
    // CWE:            CWE-20 (Improper Input Validation) /
    //                 CWE-436 (Interpretation Conflict)
    // Target:         src/models/voucher.rs::TrapData (~94-98, serde(default))
    //                 src/services/voucher_validation/chain.rs::verify_transactions (~310-353)
    //                 src/services/conflict_manager.rs::is_init_fingerprint (~184-189)
    //
    // Threat Model & Exploitation:
    //   TrapData.trap_r/trap_s carry #[serde(default)], so {"ds_tag": "<ok>"}
    //   deserializes to EMPTY shard strings. Chain validation enforces only
    //   ds_tag correctness plus ':'/'@' hygiene — neither applies to "" — and
    //   binds the empty strings legitimately into the HMC_TX_AUTH_V3 digest.
    //   A double-spender therefore strips THEIR OWN spend shards completely,
    //   re-signs the digest over ""/"", and publishes a shard-less spend.
    //
    // Impact Analysis:
    //   create_fingerprint_for_transaction copies the empty shards and
    //   is_init_fingerprint classifies the SPEND fingerprint as GENESIS:
    //   gossip export filter, ingress gate, cleanup and collision extraction
    //   participation all silently skip it. The entire SST deanonymization
    //   feature is switchable off by omission, and two incompatible
    //   representations for "no trap" exist ("none" placeholder vs. empty
    //   string) with different security semantics (grammar desync).
    //
    // Root Cause:
    //   Shard presence/format is never enforced for non-init transactions;
    //   the init classification hangs on attacker-controlled, unvalidated
    //   fields instead of t_type/ds_tag structure.
    //
    // Remediation Strategy (cross-module, PENDING):
    //   chain.rs must reject non-init transactions whose trap shards are
    //   empty or the "none" placeholder; is_init_fingerprint semantics stay
    //   reserved for genuine genesis entries. Files belong to module-01
    //   ownership (chain.rs / conflict_manager.rs / models/voucher.rs).
    //
    // Test Semantics (Fail-First):
    //   Builds a REAL wallet voucher + transfer, strips the spend shards to
    //   "" and re-signs the V3 digest over the stripped values. Asserts the
    //   chain validation REJECTS it and that the resulting fingerprint is
    //   NOT classified as init. FAIL on unpatched code = vulnerability proven.
    // ```

    /// PENDING CROSS-MODULE FIX (do not silently delete): both remediation
    /// sites live outside module-02's file ownership (chain.rs shard-presence
    /// validation, models/voucher.rs serde attributes, conflict_manager.rs
    /// init classification — module-01 territory). Fail-first was proven on
    /// unpatched code: the chain validation accepted the stripped spend with
    /// a validly re-signed V3 digest over ""/"" and is_init_fingerprint
    /// classified it as genesis. This test asserts the secure invariants.
    ///
    /// UN-IGNORED (Wave 3 finalization): all remediation sites have landed —
    /// chain.rs `validate_shard_structure` rejects shard-less spends (A-04),
    /// `create_fingerprint_for_transaction` emits the VOID_SPEND_SHARD_MARKER
    /// for malformed spends (A-06) and `is_init_fingerprint` no longer
    /// equates empty shards with genesis (A-00, WH3-00-902).
    #[test]
    fn audit_02_09_stripped_shard_spend_passes_chain_validation_and_masquerades_as_init() {
        use human_money_core::services::conflict_manager::{
            create_fingerprint_for_transaction, encrypt_transaction_timestamp,
            is_init_fingerprint,
        };
        use human_money_core::services::crypto::identity::get_prefix_from_user_id;
        use human_money_core::services::crypto::keys::derive_ephemeral_key_pair;
        use human_money_core::services::l2_gateway::{
            calculate_l2_payload_hash_raw, extract_layer2_voucher_id, privacy_guard_commitment,
        };
        use human_money_core::NewVoucherData;
        use human_money_core::test_utils::{
            generate_signed_standard_toml, setup_service_with_profile, ACTORS, FREETALER_STANDARD,
        };
        use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
        use human_money_core::models::profile::PublicProfile;
        use human_money_core::ValueDefinition;
        use std::collections::HashMap;
        use tempfile::tempdir;

        const PASSWORD: &str = "audit-password";

        let dir = tempdir().expect("tempdir must succeed");
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;

        let (mut alice, _) =
            setup_service_with_profile(dir.path(), &ACTORS.alice, "A9", PASSWORD);
        let (mut bob, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "B9", PASSWORD);

        let id_alice = alice.with_wallet(|w| w.get_user_id().to_string()).expect("alice id");
        let id_bob = bob.with_wallet(|w| w.get_user_id().to_string()).expect("bob id");

        alice.unlock_session(PASSWORD, 300).expect("unlock alice");
        alice
            .create_new_voucher(
                &standard_toml,
                NewVoucherData {
                    nominal_value: ValueDefinition {
                        amount: "100".to_string(),
                        ..Default::default()
                    },
                    creator_profile: PublicProfile {
                        id: Some(id_alice.clone()),
                        ..Default::default()
                    },
                    validity_duration: Some("P4Y".to_string()),
                    ..Default::default()
                },
                Some(PASSWORD),
            )
            .expect("voucher creation failed");

        let summaries = alice
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .expect("summaries");
        let local_id = summaries[0].local_instance_id.clone();

        let mut standards_map = HashMap::new();
        standards_map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.clone(),
        );

        let request = MultiTransferRequest {
            recipient_id: id_bob.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        };
        let result = alice
            .create_transfer_bundle(request, &standards_map, None, Some(PASSWORD))
            .expect("transfer creation failed");
        bob.unlock_session(PASSWORD, 300).expect("unlock bob");
        bob.receive_bundle(&result.bundle_bytes, &standards_map, None, Some(PASSWORD), false)
            .expect("honest transfer must be accepted");

        // Extract bob's real spend transaction (public chain data).
        let (bob_wallet, _) = bob.get_unlocked_mut_for_test();
        let instance = bob_wallet.voucher_store.vouchers.values().next().unwrap();
        let voucher = instance.voucher.clone();
        assert_eq!(voucher.transactions.len(), 2, "init + spend expected");
        let honest_spend = voucher.transactions.last().unwrap().clone();
        let honest_trap = honest_spend.trap_data.as_ref().expect("spend carries trap");
        assert!(
            !honest_trap.trap_r.is_empty() && !honest_trap.trap_s.is_empty(),
            "Precondition broken: honest spend unexpectedly lacks shards"
        );
        let ds_tag = honest_trap.ds_tag.clone();

        // The serde-default desync primitive: {"ds_tag": ...} alone yields
        // empty shard strings (striping vector documented).
        let striped: TrapData =
            serde_json::from_str(&format!(r#"{{"ds_tag":"{}"}}"#, ds_tag)).expect("deser");
        assert!(
            striped.trap_r.is_empty() && striped.trap_s.is_empty(),
            "Precondition: serde defaults produce empty shards"
        );

        // Build the STRIPPED attack variant: same transaction, empty shards,
        // layer2_signature re-signed over the V3 digest binding ""/"".
        let mut stripped = honest_spend.clone();
        {
            let t = stripped.trap_data.as_mut().unwrap();
            t.trap_r = String::new();
            t.trap_s = String::new();
        }
        // t_id preimage excludes trap_data -> unchanged; re-sign L2 proof.
        let eph_b58 = stripped.sender_ephemeral_pub.clone().expect("spend eph pub");
        let eph_bytes: [u8; 32] = bs58::decode(&eph_b58)
            .into_vec()
            .expect("eph base58")
            .try_into()
            .expect("eph len");
        let t_id_bytes: [u8; 32] = bs58::decode(&stripped.t_id)
            .into_vec()
            .expect("t_id base58")
            .try_into()
            .expect("t_id len");
        let encrypted_timestamp =
            encrypt_transaction_timestamp(&stripped).expect("timestamp encryption");

        let payload_hash = calculate_l2_payload_hash_raw(
            &extract_layer2_voucher_id(&voucher).expect("voucher id"),
            &ds_tag,
            &t_id_bytes,
            &eph_bytes,
            "",
            "",
            encrypted_timestamp,
            stripped.deletable_at.as_deref(),
            &privacy_guard_commitment(stripped.privacy_guard.as_deref()),
        );

        // The input anchor key of the spend is alice's deterministic
        // "holder" ephemeral key (rederived by rederive_secret_seed Case C;
        // its public hash anchors init.receiver_ephemeral_pub_hash).
        let nonce_bytes = bs58::decode(&voucher.voucher_nonce)
            .into_vec()
            .expect("nonce base58");
        let prefix = get_prefix_from_user_id(&id_alice);
        let (input_secret, _input_pub) = derive_ephemeral_key_pair(
            &ACTORS.alice.identity.signing_key,
            &nonce_bytes,
            "holder",
            prefix,
        )
        .expect("input anchor derivation");
        assert_eq!(
            bs58::encode(input_secret.verifying_key().to_bytes()).into_string(),
            eph_b58,
            "Precondition broken: input anchor derivation does not reproduce \
             the spend's sender_ephemeral_pub"
        );
        let l2_sig = sign_ed25519(&input_secret, &payload_hash);
        stripped.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());

        // Control: the HONEST chain validates.
        assert!(
            human_money_core::validate_voucher_against_standard(&voucher, standard_def).is_ok(),
            "Precondition broken: honest voucher must validate"
        );

        // --- SOLL-VERHALTEN A: the stripped spend MUST fail chain validation ---
        let mut attacked = voucher.clone();
        *attacked.transactions.last_mut().unwrap() = stripped;
        match human_money_core::validate_voucher_against_standard(&attacked, standard_def) {
            Ok(()) => panic!(
                "SECURITY VIOLATION HMC-SEC-02-09: validate_voucher_against_standard \
                 accepted a SPEND transaction whose trap shards were stripped to \
                 empty strings (serde-default desync). The double-spender can \
                 suppress all gossip detection value by omitting shards and \
                 re-signing the V3 digest over \"\"/\"\"."
            ),
            Err(_) => {
                // Secure behavior: shard-less spends rejected at L1.
            }
        }

        // --- SOLL-VERHALTEN B: the stripped spend MUST NOT classify as init ---
        let mut fp_source = voucher.clone();
        *fp_source.transactions.last_mut().unwrap() = honest_spend.clone();
        {
            let t = fp_source
                .transactions
                .last_mut()
                .unwrap()
                .trap_data
                .as_mut()
                .unwrap();
            t.trap_r = String::new();
            t.trap_s = String::new();
        }
        let fp = create_fingerprint_for_transaction(
            fp_source.transactions.last().unwrap(),
            &fp_source,
        )
        .expect("fingerprint creation");
        assert!(
            !is_init_fingerprint(&fp),
            "SECURITY VIOLATION HMC-SEC-02-09: is_init_fingerprint classified a \
             STRIPPED SPEND fingerprint as genesis ('init'). Export filter, \
             ingress gate, cleanup and extraction participation all silently \
             skip it — the SST feature is disabled by omission."
        );
    }

    // =======================================================================
    // HMC-SEC-02-10 — Small-order did:key identities & JWE DH without
    //                 contributory check
    // =======================================================================

    // ```text
    // Finding-ID:     HMC-SEC-02-10
    // Title:          Small-order did:key identities accepted as payment
    //                 targets; JWE container path derives KEKs from raw,
    //                 non-contributory DH results
    // Severity:       MEDIUM
    // CWE:            CWE-325 (Missing Required Cryptographic Step) /
    //                 CWE-20 (Improper Input Validation)
    // Target:         src/services/crypto_identity.rs::get_pubkey_from_user_id (~216-255)
    //                 src/services/secure_container_manager.rs::create_secure_container (105, 124, 315)
    //
    // Threat Model & Exploitation:
    //   After the SA02-01 fix only the two privacy-guard DH directions reject
    //   non-contributory exchanges. The JWE container path calls raw X25519
    //   DH at three sites and feeds the result straight into derive_kek
    //   (no contributory check, no HKDF/SAI binding). The identity parser
    //   accepts ANY decompressable Ed25519 point as a did:key, including
    //   small-order points. An attacker hands the victim a "payment address"
    //   did:key whose multicodec payload encodes a small-order point; the
    //   victim creates a bundle container via TargetDid and the shared
    //   secret collapses to an attacker-computable constant.
    //
    // Impact Analysis:
    //   Confidentiality of the complete financial bundle is lost: any third
    //   party recomputes kek = HKDF(zero-shared-secret) without secrets and
    //   unwraps the CEK from the JWE recipient entry. Violates the documented
    //   SA02-01 invariant ("non-contributory DH must never yield derivable
    //   keys") at a non-migrated site.
    //
    // Root Cause:
    //   get_pubkey_from_user_id performs only grammar/multicodec/length
    //   checks; group-membership of the encoded point is never validated.
    //
    // Remediation Strategy:
    //   Enforce torsion-free (prime-order subgroup) membership for every
    //   Ed25519 identity key resolved through get_pubkey_from_user_id.
    //   Honestly generated keys are always clamped-scalar multiples of the
    //   basepoint and therefore pass; small-order and mixed-torsion points
    //   fail closed everywhere the firewall is consulted (including
    //   create_secure_container's TargetDid resolution).
    //
    // Test Semantics (Fail-First):
    //   Builds validly-encoded did:key strings for the order-2 and order-1
    //   Edwards points and asserts key resolution REJECTS them. Additionally
    //   proves impact end-to-end: while creation succeeds, a third party
    //   decrypts the full container payload using only public data.
    //   FAIL on unpatched code = vulnerability proven.
    // ```

    #[test]
    fn audit_02_10_small_order_did_key_identities_must_be_rejected_by_key_resolution() {
        use human_money_core::models::secure_container::{
            ContainerConfig, PayloadType, PrivacyMode, SecureContainer,
        };
        use human_money_core::services::crypto::symmetric::{
            decrypt_data, decrypt_data_with_aad,
        };
        use human_money_core::services::crypto::{
            decode_base64, ed25519_pub_to_x25519,
        };

        // Order-2 Edwards point (0,-1): y = p-1, encoding [0xec, 0xff*30, 0x7f].
        let mut order2_bytes = [0xffu8; 32];
        order2_bytes[0] = 0xec;
        order2_bytes[31] = 0x7f;
        // Order-1 Edwards point (identity): (0,1), encoding [1, 0*31].
        let identity_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0x01;
            b
        };

        for (label, point_bytes) in [("order-2", &order2_bytes), ("order-1", &identity_bytes)] {
            let compressed =
                CompressedEdwardsY::from_slice(point_bytes).expect("encoding length");
            let point = compressed
                .decompress()
                .unwrap_or_else(|| panic!("Precondition broken: {label} point must decompress"));
            assert!(
                point.is_small_order(),
                "Precondition broken: {label} fixture is not a small-order point"
            );

            // Validly encoded malicious did:key with correct multicodec prefix.
            let mut mc = vec![0xedu8, 0x01];
            mc.extend_from_slice(point_bytes);
            let malicious_did = format!("did:key:z{}", bs58::encode(&mc).into_string());

            // --- SOLL-VERHALTEN: the identity firewall MUST reject it ---
            match human_money_core::services::crypto::get_pubkey_from_user_id(
                &malicious_did,
            ) {
                Err(_) => {
                    // Secure behavior after the subgroup guard lands.
                }
                Ok(small_pk) => {
                    // Document the collapse precondition that makes this
                    // exploitable before failing (fail-first proof).
                    let u = ed25519_pub_to_x25519(&small_pk);
                    panic!(
                        "SECURITY VIOLATION HMC-SEC-02-10: get_pubkey_from_user_id \
                         accepted the {label} small-order did:key '{}'. The \
                         resulting X25519 u-coordinate is {:?}; any DH exchange \
                         against it collapses to attacker-computable constants \
                         (JWE container confidentiality lost).",
                        malicious_did,
                        u.as_bytes()
                    );
                }
            }
        }

        // End-to-end impact probe on the UNPATCHED path: if container creation
        // still succeeds for a small-order target, a third party must be able
        // to recover the payload without any secret. Once the firewall fix
        // lands, creation fails closed and the probe reports secure behavior.
        let (victim_pk, victim_sk) =
            generate_ed25519_keypair_for_tests(Some("audit-02-10-victim"));
        let victim_identity = UserIdentity {
            signing_key: victim_sk,
            public_key: victim_pk,
            user_id: create_user_id(&victim_pk, None).expect("victim did"),
        };

        let mut mc = vec![0xedu8, 0x01];
        mc.extend_from_slice(&order2_bytes);
        let malicious_did = format!("did:key:z{}", bs58::encode(&mc).into_string());
        let secret_payload = br#"{"financial_bundle":"TOP SECRET transfer data"}"#;

        match SecureContainer::seal(
            &victim_identity,
            &ContainerConfig::TargetDid(malicious_did.clone(), PrivacyMode::CleartextRouting),
            secret_payload,
            PayloadType::TransactionBundle,
        ) {
            Err(_) => {
                // Secure behavior: TargetDid resolution rejects the
                // small-order identity, container creation fails closed.
            }
            Ok(container) => {
                // Attacker-side break (public data only):
                // 1. DH against the order-2 point collapses to zero.
                let recipient_entry = container
                    .recipients
                    .first()
                    .expect("container carries recipient entries");
                let wrapped_cek =
                    decode_base64(&recipient_entry.encrypted_key).expect("wrapped cek b64");

                // esk_priv * U_small == O for EVERY ephemeral scalar, so the
                // shared secret is the all-zero string for everyone.
                let collapsed_shared = [0u8; 32];
                // Mirror derive_kek exactly (HKDF-SHA256, fixed info).
                let hk = Hkdf::<Sha256>::new(None, &collapsed_shared);
                let mut kek = [0u8; 32];
                hk.expand(b"secure-container-kek", &mut kek)
                    .expect("hkdf expand");

                // 2. Unwrap the content encryption key.
                let cek_vec = decrypt_data(&kek, &wrapped_cek)
                    .expect("ATTACKER unwrapped the CEK from the collapsed KEK");
                let cek: [u8; 32] = cek_vec
                    .try_into()
                    .expect("CEK length must be 32 bytes");

                // 3. Decrypt the financial payload with AAD binding.
                let iv = decode_base64(&container.iv).expect("iv b64");
                let ciphertext = decode_base64(&container.ciphertext).expect("ct b64");
                let tag = decode_base64(&container.tag).expect("tag b64");
                let plaintext = decrypt_data_with_aad(&cek, &iv, &ciphertext, &tag, container.protected.as_bytes())
                    .expect("ATTACKER decrypted the bundle payload");

                panic!(
                    "SECURITY VIOLATION HMC-SEC-02-10: create_secure_container \
                     accepted a SMALL-ORDER target did:key '{}' and a third party \
                     recovered the payload '{}' WITHOUT ANY SECRET (KEK derived \
                     from the collapsed non-contributory DH result).",
                    malicious_did,
                    String::from_utf8_lossy(&plaintext)
                );
            }
        }
    }

    // =======================================================================
    // HMC-SEC-02-11 — layer2_voucher_id unbound in the HMC_TX_AUTH_V3 digest
    // =======================================================================

    // ```text
    // Finding-ID:     HMC-SEC-02-11
    // Title:          L2 lock signatures do not bind the voucher id — lock
    //                 entries are context-free transplantable between vouchers
    // Severity:       MEDIUM
    // CWE:            CWE-347 (Improper Verification of Cryptographic Signature)
    //                 / CWE-345 (Insufficient Verification of Data Authenticity)
    // Target:         src/services/l2_gateway.rs::calculate_l2_payload_hash_raw (~280-299)
    //                 src/services/l2_gateway.rs::process_l2_verdict (~371-433)
    //
    // Threat Model & Exploitation:
    //   The V3 digest binds (challenge_ds_tag, t_id, sender_ephemeral_pub,
    //   trap shards, encrypted_timestamp, deletable_at) but NOT the
    //   layer2_voucher_id. A validly signed lock entry observed anywhere on
    //   the network can therefore be replicated inside a Verified verdict for
    //   a DIFFERENT voucher: a malicious/MITM L2 server relabels
    //   lock_entry.layer2_voucher_id to the victim's voucher and feeds it to
    //   process_l2_verdict. The mathematical signature check succeeds because
    //   the voucher reference lives only in the caller-side string comparison
    //   (check 0) and in an optional ephemeral-key comparison.
    //
    // Impact Analysis:
    //   A single authentic lock authorization is replayable against every
    //   voucher sharing a queryable challenge tag: quarantine decisions can
    //   be driven by evidence that cryptographically never referenced the
    //   affected container. Violates payload completeness ("the digest
    //   authorizes THIS transaction for THIS voucher"), same class as the
    //   remediated HMC-SEC-06-01 bundle-id rebinding.
    //
    // Root Cause:
    //   layer2_voucher_id was deliberately excluded from the digest for API
    //   stability (comment at chain.rs ~583), not as a security decision;
    //   external L2 servers must migrate anyway (V3 breaking change).
    //
    // Remediation Strategy (REMEDIATED):
    //   calculate_l2_payload_hash_raw now binds layer2_voucher_id into the
    //   HMC_TX_AUTH_V3 digest (all signers/verifiers migrated with the V3
    //   breaking change), so a relabeled entry fails signature verification
    //   inside process_l2_verdict.
    //
    // Test Semantics (Remediation Verified):
    //   Creates an authentic, correctly signed lock entry for voucher "A"
    //   whose signature is bound to its voucher id, relabels it to voucher
    //   "B" and processes it as a Verified verdict for "B" WITH full
    //   ephemeral-key pinning. SOLL: Err — the signature over the relabeled
    //   voucher id fails verification in process_l2_verdict.
    // ```

    #[test]
    fn audit_02_11_lock_entry_signature_without_voucher_binding_must_not_quarantine_foreign_voucher() {
        use ed25519_dalek::{Signature as EdSig, Signer, SigningKey, VerifyingKey};
        use human_money_core::models::layer2_api::{
            L2LockEntry, L2ResponseEnvelope, L2Verdict,
        };
        use human_money_core::services::crypto::get_hash_from_slices;
        use human_money_core::services::l2_gateway::{
            calculate_l2_payload_hash_raw, process_l2_verdict, VerdictAction,
        };
        use sha2::{Digest, Sha256};

        // --- Server (trusted key material for envelope authenticity) ---
        let server_sk = SigningKey::from_bytes(&{
            let mut s = [0u8; 32];
            s[..16].copy_from_slice(b"audit-02-11-serv");
            s
        });
        let server_pk = server_sk.verifying_key().to_bytes();

        // --- Spender's authentic lock over voucher "A" ---
        let spender_sk = SigningKey::from_bytes(&{
            let mut s = [0u8; 32];
            s[..16].copy_from_slice(b"audit-02-11-spen");
            s
        });
        let spender_pk = spender_sk.verifying_key().to_bytes();
        let t_id_bytes: [u8; 32] =
            human_money_core::services::crypto::get_raw_hash_from_slices(&[
                b"audit-02-11-tid",
            ]);
        let ds_tag = get_hash_from_slices(&[b"audit-02-11", b"prev-hash-input"]);
        let trap_r = bs58::encode([0x11u8; 32]).into_string();
        let trap_s = bs58::encode([0x22u8; 32]).into_string();
        let encrypted_timestamp: u128 = 0xdead_beef_u128;
        let deletable_at: Option<String> = None;

        let payload_hash = calculate_l2_payload_hash_raw(
            "voucher-A-of-spender",
            &ds_tag,
            &t_id_bytes,
            &spender_pk,
            &trap_r,
            &trap_s,
            encrypted_timestamp,
            deletable_at.as_deref(),
            "",
        );
        let l2_signature = spender_sk.sign(&payload_hash).to_bytes();

        // Sanity: the signature IS mathematically valid for its own fields.
        {
            let vk = VerifyingKey::from_bytes(&spender_pk).expect("spender pk");
            assert!(
                verify_ed25519(&vk, &payload_hash, &EdSig::from_bytes(&l2_signature)),
                "Precondition broken: fixture lock signature invalid"
            );
        }

        // --- Transplant: relabel the authentic entry onto voucher "B" ---
        let transplanted = L2LockEntry {
            layer2_voucher_id: "voucher-B-of-victim".to_string(), // RELABELED
            t_id: t_id_bytes,
            sender_ephemeral_pub: spender_pk,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: l2_signature,
            trap_r: Some(trap_r.clone()),
            trap_s: Some(trap_s.clone()),
            encrypted_timestamp,
            deletable_at,
            privacy_guard: None,
        };

        let verdict = L2Verdict::Verified { lock_entry: transplanted };
        let verdict_bytes = serde_json::to_vec(&verdict).expect("verdict serialization");
        let mut verdict_hasher = Sha256::new();
        verdict_hasher.update(&verdict_bytes);
        let envelope = L2ResponseEnvelope {
            verdict,
            server_signature: server_sk.sign(&verdict_hasher.finalize()).to_bytes(),
        };
        let envelope_bytes = serde_json::to_vec(&envelope).expect("envelope serialization");

        // Victim wallet context: querying about ITS transaction on voucher B,
        // expecting the spender's ephemeral key (full key pinning active!).
        let local_t_id_of_victim = bs58::encode(get_hash("audit-02-11-victim-tid"))
            .into_string();
        let outcome = process_l2_verdict(
            &envelope_bytes,
            &server_pk,
            &local_t_id_of_victim,
            &ds_tag,
            Some(&bs58::encode(spender_pk).into_string()),
            "voucher-B-of-victim",
        );

        // --- SOLL-VERHALTEN: the transplant MUST NOT quarantine voucher B ---
        match outcome {
            Ok(action) => {
                let action_desc = match action {
                    VerdictAction::ConfirmLocal => "ConfirmLocal".to_string(),
                    VerdictAction::TriggerQuarantine(t) => format!("TriggerQuarantine({})", t),
                    VerdictAction::TriggerSync { sync_point } => {
                        format!("TriggerSync({})", sync_point)
                    }
                };
                panic!(
                    "SECURITY VIOLATION HMC-SEC-02-11: process_l2_verdict accepted a \
                     transplanted lock entry (action {}) whose signature never bound \
                     the victim voucher id 'voucher-B-of-victim'.",
                    action_desc
                );
            }
            Err(_) => {
                // Secure behavior: signature over relabeled voucher id fails.
            }
        }
    }
}
