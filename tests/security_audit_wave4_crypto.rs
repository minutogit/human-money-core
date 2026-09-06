//! # Security Audit Wave 4 — Module 02 Crypto Findings (Phase B, Fail-First)
//!
//! Dedicated fail-first tests for the Audit-Wave 4 hypotheses against the
//! cryptographic core. Every finding test asserts the **secure invariant**
//! (Soll-Verhalten). On vulnerable/unpatched code each finding test MUST
//! FAIL, thereby proving the defect (`cargo nextest run` -> FAIL).
//!
//! ---------------------------------------------------------------------------
//! AUDIT METADATA (standardized docblock)
//! ---------------------------------------------------------------------------
//!
//! ```text
//! Finding-ID:     AUDIT-W4-CRY-302 (hypothesis WH4-02-302)
//! Title:          ContainerConfig::Password("") seals SecureContainers under
//!                 a publicly derivable key — missing HMSEC-SA05-10 guard parity
//! Severity:       MEDIUM
//! CWE:            CWE-521 (Weak Password Requirements)
//!                 / CWE-1392 (Use of Default Credentials)
//! Target:         src/services/secure_container_manager.rs:177-198
//!                 (create_secure_container, ContainerConfig::Password branch)
//!                 src/services/crypto_symmetric.rs:206-234
//!                 (encrypt_symmetric_password, no entropy floor)
//! Threat Model:   HMSEC-SA05-10 closed exactly this class for the voucher
//!                 archive ("seal-time guard rejects empty passwords"). The
//!                 sister sink SecureContainer was never migrated: a host app
//!                 forwarding "" (production caller:
//!                 app_service/standard_container_handler.rs:387 via
//!                 export_voucher_standard) obtains a container whose key
//!                 derives deterministically via PBKDF2-HMAC-SHA512("", salt),
//!                 with the salt stored NEXT TO the ciphertext in the envelope.
//!                 Any offline scanner knowing the public format decrypts the
//!                 exported artifact within seconds — it leaves the wallet
//!                 effectively unencrypted, without warning.
//! Impact:         Confidentiality of every password-sealed export collapses
//!                 to obfuscation for hosts that forward "". Violates the
//!                 documented invariant that no exchange/at-rest artifact may
//!                 be sealed under an empty or entropy-less secret.
//! Root Cause:     No empty-password guard anywhere on the SecureContainer
//!                 symmetric path; unlike the archive, nothing fails closed.
//! Remediation:    Reject empty passwords in create_secure_container's
//!                 Password branch with a typed error (e.g.
//!                 ContainerManagerError::WeakSecret) before any byte is
//!                 encrypted; optionally mirror the guard inside
//!                 encrypt_symmetric_password for defense in depth.
//! Test Semantics: Asserts create_secure_container(.., Password("")) yields
//!                 Err while the positive control Password("pin1234") stays
//!                 Ok and round-trips. FAILS on unpatched code (seals happily
//!                 under the empty-password key) = vulnerability proven.
//! ```
//!
//! ```text
//! Finding-ID:     AUDIT-W4-CRY-301 (+ WH4-06-704 combined hardening proof)
//! Title:          Low-order attacker-controlled epk on the JWE decrypt path
//!                 must never yield decryptable payload (non-contributory DH
//!                 firewall + context-free KEK derivation)
//! Severity:       MEDIUM
//! CWE:            CWE-325 (Missing Required Cryptographic Step) / CWE-20
//! Target:         src/services/secure_container_manager.rs:300-333
//!                 (open_secure_container: epk extraction + raw DH +
//!                 was_contributory skip), :389-395 (derive_kek: context-free
//!                 HKDF label b"secure-container-kek" — binds neither epk nor
//!                 recipient identity, contrast build_hkdf_info)
//! Threat Model:   On the decrypt path the X25519 counterparty comes from the
//!                 base64 `epk` field of the Protected Header and is fully
//!                 attacker-controlled; the did:key NonPrimeOrderKey firewall
//!                 (HMC-SEC-02-10) fires only during did:key resolution on the
//!                 CREATE side and structurally never on this path. An
//!                 attacker crafts a minimal container with epk = [0u8;32]:
//!                 the DH collapses to [0u8;32] for EVERY victim, making
//!                 kek = HKDF(b"secure-container-kek", [0u8;32]) publicly
//!                 computable; the attacker wraps their own CEK under it so
//!                 trial decryption accepts the container as "addressed to"
//!                 the victim. Financial bundles stay damped by the inner
//!                 bundle signature, but non-bundle payload types
//!                 (DetachedSignature / VoucherForSigning envelopes) and the
//!                 recipient-authenticity semantics break.
//! Impact:         If accepted, breaks the invariant "a container can only be
//!                 decrypted by its intended recipients" (SA02-01): a
//!                 non-contributory DH leads to derivable keys.
//! Root Cause:     epk is length-checked only; security depends solely on the
//!                 was_contributory() skip at :326. Additionally derive_kek
//!                 (:389) binds no context (no epk/recipient), diverging from
//!                 perform_diffie_hellman/decrypt_recipient_payload which bind
//!                 recipient_id + both public keys into the HKDF info.
//! Remediation:    Require was_contributory() enforcement on ALL decrypt-path
//!                 DH results (fail closed); bind epk + recipient id into
//!                 derive_kek's HKDF info (parity with build_hkdf_info) and
//!                 zeroize intermediate KEK/shared-secret material.
//! Test Semantics: Crafts a fully self-consistent container (consistent
//!                 integrity id `i`, valid attacker signature, CEK wrapped
//!                 under the publicly computable low-order KEK, payload
//!                 AEAD-bound to the protected header) and asserts
//!                 open_secure_container REJECTS it with the
//!                 recipient-mismatch error — proving the contributory guard
//!                 fired AFTER successful parsing. Panics with an explicit
//!                 SECURITY VIOLATION if a regression ever lets the forged
//!                 container decrypt.
//! ```

use hkdf::Hkdf;
use human_money_core::models::profile::UserIdentity;
use human_money_core::models::secure_container::{
    ContainerConfig, EncryptionType, JweRecipient, PayloadType, PrivacyMode, SecureContainer,
};
use human_money_core::services::crypto::symmetric::{encrypt_data, encrypt_data_with_aad};
use human_money_core::services::crypto::{
    create_user_id, encode_base64, generate_ed25519_keypair_for_tests, get_hash, sign_ed25519,
};
use human_money_core::to_canonical_json;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Builds a deterministic test identity for the Wave 4 scenarios.
fn wave4_identity(seed: &str) -> UserIdentity {
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = create_user_id(&public_key, None).expect("Root did:key must be creatable");
    UserIdentity {
        user_id,
        signing_key,
        public_key,
    }
}

/// Namespace wrapper so the suite filter
/// `cargo nextest run --test security_audit_wave4_crypto` selects every
/// finding test of this module (mirrors the security_audit_module_02 convention).
mod security_audit_wave4_crypto {
    use super::*;

    // ===========================================================================
    // AUDIT-W4-CRY-302 — Empty password in ContainerConfig::Password
    // ===========================================================================

    /// `ContainerConfig::Password("")` must be rejected before any byte is
    /// sealed; a real PIN remains a working positive control.
    #[test]
    fn audit_w4_cry_302_create_secure_container_with_empty_password_must_be_rejected() {
        let sender = wave4_identity("w4-cry-302-sender");
        let payload = br#"{"voucher":"sensitive-export-content"}"#;

        // --- SOLL-VERHALTEN: the empty-password seal MUST be rejected ---
        let attack = SecureContainer::seal(
            &sender,
            &ContainerConfig::Password(String::new()),
            payload,
            PayloadType::VoucherForSigning,
        );
        assert!(
            attack.is_err(),
            "SECURITY VIOLATION AUDIT-W4-CRY-302: create_secure_container accepted \
             ContainerConfig::Password(\"\") and sealed the payload under \
             PBKDF2-HMAC-SHA512(\"\", salt) — a key every offline scanner can derive \
             in seconds given the public envelope format (salt travels NEXT TO the \
             ciphertext). Parity invariant with HMSEC-SA05-10: no exchange/at-rest \
             artifact may ever be sealed under an empty or entropy-less secret \
             (CWE-521/CWE-1392)."
        );

        // Positive control (must keep passing after the fix): a real PIN seals
        // and reopens end-to-end.
        let control = SecureContainer::seal(
            &sender,
            &ContainerConfig::Password("pin1234".to_string()),
            payload,
            PayloadType::VoucherForSigning,
        )
        .expect("Positive control failed: a non-empty password must remain usable");
        let reopened = control.open(&sender, Some("pin1234"))
            .expect("Positive control failed: PIN-sealed payload must reopen");
        assert_eq!(reopened, payload.to_vec(), "PIN round-trip must stay intact");
    }

    // ===========================================================================
    // AUDIT-W4-CRY-301 (+ WH4-06-704) — Low-order epk on the JWE decrypt path
    // ===========================================================================

    /// A forged container whose ephemeral public key is the all-zero (low-order)
    /// X25519 point — with the CEK wrapped under the PUBLICLY computable
    /// collapsed KEK — must never decrypt for the victim. Pins the
    /// `was_contributory()` enforcement on `open_secure_container`'s decrypt
    /// path (regression shield for the HMC-SEC-02-10 adjacent hardening).
    #[test]
    fn audit_w4_cry_301_forged_low_order_epk_container_must_not_decrypt_for_victim() {
        let victim = wave4_identity("w4-cry-301-victim");

        // --- Precondition: the attack math collapses DH to the neutral element ---
        let zero_pk = X25519PublicKey::from([0u8; 32]);
        let probe_secret = StaticSecret::from([0x42u8; 32]);
        let collapsed = probe_secret.diffie_hellman(&zero_pk);
        assert_eq!(
            collapsed.as_bytes(),
            &[0u8; 32],
            "Precondition broken: zero-point DH did not collapse to the neutral element"
        );

        // --- Honest control: genuine containers still open for the victim ---
        let honest_sender = wave4_identity("w4-cry-301-honest-sender");
        let honest_payload = b"honest voucher-for-signing payload";
        let honest = SecureContainer::seal(
            &honest_sender,
            &ContainerConfig::TargetDid(victim.user_id.clone(), PrivacyMode::TrialDecryption),
            honest_payload,
            PayloadType::VoucherForSigning,
        )
        .expect("Honest container creation must succeed");
        assert_eq!(
            honest.open(&victim, None)
                .expect("Honest decryption for the intended recipient must succeed"),
            honest_payload.to_vec(),
            "Honest round-trip broke while the forgery scenario is exercised"
        );

        // --- Attack: forge a minimal container under the public low-order KEK ---
        let attacker = wave4_identity("w4-cry-301-attacker");

        let epk_zero = [0u8; 32];
        let protected_header = serde_json::json!({
            "alg": "ECDH-ES+A256KW",
            "enc": "C20P",
            "typ": PayloadType::VoucherForSigning.to_didcomm_uri(),
            "epk": encode_base64(&epk_zero),
        });
        let protected_json = serde_json::to_string(&protected_header)
            .expect("Protected header serialization must succeed");
        let protected_b64 = encode_base64(protected_json.as_bytes());

        // The KEK is PUBLICLY computable: shared secret collapses to [0u8;32]
        // for every victim, and derive_kek applies a static HKDF label.
        let mut kek = [0u8; 32];
        Hkdf::<Sha256>::new(None, &[0u8; 32])
            .expand(b"secure-container-kek", &mut kek)
            .expect("HKDF expansion with valid lengths must succeed");

        let cek = [42u8; 32]; // attacker-chosen payload key
        let wrapped_cek = encrypt_data(&kek, &cek)
            .expect("Attacker-side CEK wrapping under the public KEK must succeed");

        let attack_payload = br#"{"forged":"ATTACKER-CHOSEN-PAYLOAD"}"#;
        let (iv, ciphertext, tag) =
            encrypt_data_with_aad(&cek, attack_payload, protected_b64.as_bytes())
                .expect("Attacker-side payload AEAD must succeed");

        let mut forged = SecureContainer {
            protected: protected_b64.clone(),
            unprotected: None,
            recipients: vec![JweRecipient {
                // No kid => Trial Decryption: the victim MUST attempt this entry.
                header: None,
                encrypted_key: encode_base64(&wrapped_cek),
            }],
            iv: encode_base64(&iv),
            ciphertext: encode_base64(&ciphertext),
            tag: encode_base64(&tag),
            signature: String::new(),
            et: EncryptionType::Asymmetric,
            salt: None,
            i: String::new(),
            c: PayloadType::VoucherForSigning,
        };

        // Make the forgery maximally realistic: consistent integrity id `i`
        // (recomputed exactly like create_secure_container) plus a VALID
        // attacker signature. Envelope chains are anonymous (SA06-01), so the
        // signature provides no trust anchor — mirrors honest envelopes.
        let canonical = to_canonical_json(&forged).expect("Canonical JSON must serialize");
        forged.i = get_hash(canonical.as_bytes());
        let attacker_sig = sign_ed25519(&attacker.signing_key, forged.i.as_bytes());
        forged.signature = encode_base64(&attacker_sig.to_bytes());

        // --- SOLL-VERHALTEN: the forged low-order-epk container MUST be rejected ---
        match forged.open(&victim, None) {
            Ok(opened) => panic!(
                "SECURITY VIOLATION AUDIT-W4-CRY-301: open_secure_container accepted a \
                 container forged under a NON-CONTRIBUTORY (low-order) epk. The DH \
                 collapsed to [0u8;32], the KEK was publicly derivable via \
                 HKDF(b\"secure-container-kek\", [0u8;32]), and the attacker-chosen \
                 payload decrypted as: {:?}. 'Only intended recipients can decrypt' \
                 (SA02-01) is broken.",
                String::from_utf8_lossy(&opened)
            ),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("not in the list of recipients"),
                    "AUDIT-W4-CRY-301 hardening drift: the forged container was rejected \
                     for the WRONG reason ('{}'). Expected the recipient-mismatch error \
                     produced by the was_contributory() skip AFTER successful protected-\
                     header parsing and CEK decoding — an incidental parse failure would \
                     void this hardening proof.",
                    msg
                );
            }
        }
    }
}
