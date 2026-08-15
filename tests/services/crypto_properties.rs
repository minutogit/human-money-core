// tests/services/crypto_properties.rs
// cargo test --test services_tests
//!
//! Property and boundary tests for `src/services/crypto_utils.rs`.
//!
//! These tests verify the fundamental invariants (correctness, determinism,
//! input validation) of the cryptographic utility functions. They complement the
//! general integration tests in `crypto.rs` with more precise edge-case scenarios:
//!
//! - **Completeness**: Are all valid inputs processed correctly?
//! - **Rejection**: Are invalid inputs reliably rejected?
//! - **Determinism**: Do functions always produce the same result for identical inputs?
//! - **Commutativity**: Is the argument order irrelevant where expected?
//! - **Error messages**: Do error types contain descriptive text for end users/logging?
//!
//! Run: `cargo test --test services_tests services::crypto_properties`

use human_money_core::MnemonicLanguage;
use human_money_core::services::crypto_utils::{
    UserIdError, create_user_id, decrypt_data, generate_ed25519_keypair_for_tests,
    generate_mnemonic, validate_user_id,
};

// =============================================================================
// Mnemonic Generation
// =============================================================================

/// All five word counts supported by the BIP-39 standard (12, 15, 18, 21, 24)
/// must generate a phrase with exactly that word count.
///
/// Background: BIP-39 defines entropy lengths from 128–256 bits in 32-bit increments,
/// which corresponds to word counts 12, 15, 18, 21, and 24. Each of these is an
/// independent, supported use case.
#[test]
fn test_mnemonic_generation_covers_all_bip39_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let valid_counts = [12usize, 15, 18, 21, 24];
    for &count in &valid_counts {
        let mnemonic = generate_mnemonic(count, MnemonicLanguage::English)
            .unwrap_or_else(|_| panic!("generate_mnemonic({count}) should succeed"));
        let word_count_actual = mnemonic.split_whitespace().count();
        assert_eq!(
            word_count_actual, count,
            "generate_mnemonic({count}) produced {word_count_actual} words, expected {count}"
        );
    }
    Ok(())
}

/// Word counts that do not correspond to a BIP-39 entropy multiple (e.g. 11, 13, 0)
/// must be rejected with an error.
#[test]
fn test_mnemonic_generation_rejects_unsupported_sizes() {
    assert!(generate_mnemonic(11, MnemonicLanguage::English).is_err(), "11 words is not a BIP-39 size");
    assert!(generate_mnemonic(13, MnemonicLanguage::English).is_err(), "13 words is not a BIP-39 size");
    assert!(generate_mnemonic(0,  MnemonicLanguage::English).is_err(), "0 words makes no sense");
}

// =============================================================================
// Short Hash of User IDs
// =============================================================================

/// `get_short_hash_from_user_id` serves as a compact heuristic identifier for known peers.
/// The following invariants must hold:
/// - Deterministic (same ID -> same hash)
/// - Unique (different IDs -> different hashes, statistically)
/// - Fixed 4-byte output (no empty, trivial, or variable return value)
#[test]
fn test_short_hash_is_deterministic_unique_and_fixed_size() {
    use human_money_core::services::crypto_utils::get_short_hash_from_user_id;

    let hash_alice = get_short_hash_from_user_id("alice@did:key:z6MkTest1");
    let hash_bob   = get_short_hash_from_user_id("bob@did:key:z6MkTest2");

    // Different IDs -> different hashes (no constant return value)
    assert_ne!(hash_alice, hash_bob, "Different user IDs must produce different short hashes");

    // Deterministic: same input -> same hash
    let hash_alice_again = get_short_hash_from_user_id("alice@did:key:z6MkTest1");
    assert_eq!(hash_alice, hash_alice_again, "Short hash must be deterministic");

    // No trivial constants as return value
    assert_ne!(hash_alice, [0u8; 4], "Short hash must not be all-zero");
    assert_ne!(hash_alice, [1u8; 4], "Short hash must not be all-one");

    // Output length is always exactly 4 bytes, regardless of input length
    let hash_single_char = get_short_hash_from_user_id("x");
    assert_eq!(hash_single_char.len(), 4, "Short hash must always be exactly 4 bytes");
}

// =============================================================================
// HKDF Info Vector (build_hkdf_info)
// =============================================================================

/// The HKDF info vector must contain both key bytes and the label.
/// It must not be empty and must differ for different key pairs.
///
/// Background: `build_hkdf_info` encodes both public keys into a deterministic,
/// order-independent context string for the HKDF-Expand step during DH key exchange.
#[test]
fn test_hkdf_info_contains_key_material_and_differs_per_keypair() {
    use human_money_core::services::crypto_utils::{build_hkdf_info, generate_ephemeral_x25519_keypair};

    let (pk1, _) = generate_ephemeral_x25519_keypair();
    let (pk2, _) = generate_ephemeral_x25519_keypair();

    let info = build_hkdf_info(&pk1, &pk2, "test-id");

    // Non-empty vector
    assert!(!info.is_empty(), "HKDF info must not be empty");
    // Must contain the label (32 bytes) plus at least one key (32 bytes)
    assert!(info.len() > 32, "HKDF info must include label + key material (> 32 bytes)");

    // Different keys -> different info vector
    let (pk3, _) = generate_ephemeral_x25519_keypair();
    let info_different = build_hkdf_info(&pk1, &pk3, "test-id");
    assert_ne!(info, info_different, "Different key pairs must produce different HKDF info");
}

/// The info vector must be identical regardless of argument order
/// (commutativity). This is necessary so sender and recipient can derive the same
/// symmetric key without coordinating the order in advance.
#[test]
fn test_hkdf_info_is_independent_of_argument_order() {
    use human_money_core::services::crypto_utils::{
        build_hkdf_info, ed25519_pub_to_x25519, generate_ed25519_keypair_for_tests,
    };

    let (ed_a, _) = generate_ed25519_keypair_for_tests(Some("hkdf-key-aaaaa"));
    let (ed_b, _) = generate_ed25519_keypair_for_tests(Some("hkdf-key-zzzzz"));
    let pk_a = ed25519_pub_to_x25519(&ed_a);
    let pk_b = ed25519_pub_to_x25519(&ed_b);

    let info_ab = build_hkdf_info(&pk_a, &pk_b, "test-id");
    let info_ba = build_hkdf_info(&pk_b, &pk_a, "test-id");

    assert_eq!(
        info_ab, info_ba,
        "build_hkdf_info must produce the same result regardless of argument order"
    );

    // At least one of the keys must be found as a byte sequence in the result
    let contains_a = info_ab.windows(32).any(|w| w == pk_a.as_bytes());
    let contains_b = info_ab.windows(32).any(|w| w == pk_b.as_bytes());
    assert!(
        contains_a || contains_b,
        "HKDF info must contain actual key bytes, not placeholder data"
    );
}

// =============================================================================
// Minimum Length for Encrypted Recipient Payloads
// =============================================================================

/// An encrypted Privacy Guard package consists of an ephemeral public key
/// (32 bytes) followed by nonce + ciphertext (min. 12 bytes). Inputs below this
/// threshold of 44 bytes must be rejected immediately with an error
/// before decryption is attempted.
///
/// Edge cases with various lengths below the threshold verify that the check
/// is implemented correctly (e.g. not using subtraction instead of addition).
#[test]
fn test_recipient_payload_decryption_requires_minimum_byte_length() {
    use base64::Engine as _;
    use human_money_core::services::crypto_utils::{decrypt_recipient_payload, generate_ed25519_keypair_for_tests};
    let engine = base64::engine::general_purpose::STANDARD;

    let (_, sk) = generate_ed25519_keypair_for_tests(Some("min-length-test"));

    // 43 bytes = 32 + 11 -> 1 byte missing for the nonce
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 43]), &sk, "test-id").is_err(),
        "43 bytes (one short) must be rejected"
    );

    // 20 bytes -> far below the boundary
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 20]), &sk, "test-id").is_err(),
        "20 bytes must be rejected"
    );

    // 21 bytes -> still too short
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 21]), &sk, "test-id").is_err(),
        "21 bytes must be rejected"
    );

    // 0 bytes -> empty input must be rejected
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 0]), &sk, "test-id").is_err(),
        "empty input must be rejected"
    );
}

// =============================================================================
// Nonce Prefix in Symmetric Decryption
// =============================================================================

/// `decrypt_data` expects a prepended 12-byte nonce (ChaCha20-Poly1305).
/// Inputs under 12 bytes must be rejected with `InvalidLength`.
/// Inputs of 12 bytes or more pass the length check and fail only at
/// AEAD verification (different error type: `DecryptionFailed`).
///
/// The differing error behavior for 11 vs. 12 bytes is the relevant invariant:
/// It demonstrates that the length check uses an exact, correct threshold.
#[test]
fn test_symmetric_decryption_distinguishes_length_error_from_decryption_error() {
    use chacha20poly1305::aead::{OsRng, rand_core::RngCore};

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    // 11 bytes -> too short for a nonce -> InvalidLength
    let err_11 = decrypt_data(&key, &[0u8; 11]).unwrap_err();
    let err_str_11 = format!("{err_11:?}");
    assert!(
        err_str_11.contains("InvalidLength") || err_str_11.contains("nonce") || err_str_11.contains("12"),
        "Input shorter than NONCE_SIZE must produce an InvalidLength error, got: {err_str_11}"
    );

    // 12 bytes -> nonce OK, but no ciphertext -> DecryptionFailed (not InvalidLength)
    let err_12 = decrypt_data(&key, &[0u8; 12]).unwrap_err();
    let err_str_12 = format!("{err_12:?}");
    assert!(
        !err_str_12.contains("InvalidLength"),
        "Exactly 12 bytes must pass length check and fail with DecryptionFailed, not InvalidLength. \
         Got: {err_str_12}"
    );

    // Empty input -> must also fail
    assert!(decrypt_data(&key, &[]).is_err(), "Empty input must fail");
}

// =============================================================================
// Prefix Validation During User ID Creation
// =============================================================================

/// The prefix of a user ID may be at most 63 characters long.
/// Exactly 63 characters are allowed; from 64 characters onward, `PrefixTooLong` is returned.
#[test]
fn test_user_id_prefix_length_is_enforced_at_63_chars() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("length-boundary"));

    let result_63 = create_user_id(&pub_key, Some(&"a".repeat(63)));
    assert!(result_63.is_ok(), "63-char prefix must be accepted, got: {:?}", result_63.err());

    let result_64 = create_user_id(&pub_key, Some(&"a".repeat(64)));
    assert!(
        matches!(result_64, Err(UserIdError::PrefixTooLong(_))),
        "64-char prefix must be rejected as PrefixTooLong, got: {:?}", result_64
    );
}

/// The prefix may only contain lowercase letters (a–z), digits (0–9), and hyphens (-).
/// Uppercase letters are automatically converted to lowercase.
/// Spaces, '@', special characters, etc. are not allowed.
#[test]
fn test_user_id_prefix_only_allows_lowercase_digits_and_hyphens() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("charset-test"));

    // Uppercase letters are normalized via to_lowercase -> valid
    let result_upper = create_user_id(&pub_key, Some("ABC"));
    assert!(result_upper.is_ok(), "Uppercase 'ABC' is normalized to 'abc' and must be accepted");

    // Space -> invalid
    let result_space = create_user_id(&pub_key, Some("my prefix"));
    assert!(
        matches!(result_space, Err(UserIdError::InvalidPrefixChars)),
        "Space in prefix must be rejected as InvalidPrefixChars, got: {:?}", result_space
    );

    // '@' character -> invalid (collides with the ID format delimiter)
    let result_at = create_user_id(&pub_key, Some("pre@fix"));
    assert!(
        matches!(result_at, Err(UserIdError::InvalidPrefixChars)),
        "'@' in prefix must be rejected as InvalidPrefixChars, got: {:?}", result_at
    );
}

/// Hyphens at the start or end of the prefix are not allowed,
/// as they would result in confusing or hard-to-read IDs ("-account:...").
/// Each of these positions must be rejected independently.
#[test]
fn test_user_id_prefix_cannot_start_or_end_with_hyphen() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("hyphen-position"));

    let r_leading = create_user_id(&pub_key, Some("-prefix"));
    assert!(
        matches!(r_leading, Err(UserIdError::InvalidPrefixStartEnd)),
        "Leading hyphen must be rejected, got: {:?}", r_leading
    );

    let r_trailing = create_user_id(&pub_key, Some("prefix-"));
    assert!(
        matches!(r_trailing, Err(UserIdError::InvalidPrefixStartEnd)),
        "Trailing hyphen must be rejected, got: {:?}", r_trailing
    );

    // Hyphen in the middle is allowed (common separator in context names)
    let r_middle = create_user_id(&pub_key, Some("my-prefix"));
    assert!(r_middle.is_ok(), "Hyphen in the middle must be accepted, got: {:?}", r_middle.err());
}

/// Consecutive delimiters (`--`) are not allowed, as they do not represent a reasonable naming pattern
/// and could lead to parsing ambiguities.
#[test]
fn test_user_id_prefix_cannot_contain_consecutive_hyphens() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("consec-hyphens"));

    let r_double = create_user_id(&pub_key, Some("my--prefix"));
    assert!(
        matches!(r_double, Err(UserIdError::PrefixHasConsecutiveSeparators)),
        "Double hyphen '--' must be rejected, got: {:?}", r_double
    );

    // Colons are also disallowed as characters
    assert!(create_user_id(&pub_key, Some(":prefix")).is_err(),  "Leading ':' must fail");
    assert!(create_user_id(&pub_key, Some("ab::cd")).is_err(),   "'::' must fail");
    assert!(create_user_id(&pub_key, Some("prefix:")).is_err(),  "Trailing ':' must fail");

    // Single hyphen remains allowed
    let r_single = create_user_id(&pub_key, Some("my-prefix"));
    assert!(r_single.is_ok(), "Single hyphen must still be accepted");
}

// =============================================================================
// Validation of Existing User IDs
// =============================================================================

/// `validate_user_id` must reject clearly structurally invalid strings
/// and accept a valid ID. In addition, a tampered checksum
/// must be detected (integrity protection).
#[test]
fn test_user_id_validation_rejects_malformed_input_and_detects_tampering() {
    // 1. Structurally invalid strings must be rejected
    assert!(!validate_user_id(""),              "Empty string must fail");
    assert!(!validate_user_id("not-a-user-id"), "Plain string must fail");
    assert!(!validate_user_id("only@one"),      "Missing DID part must fail");
    assert!(!validate_user_id("a@@did:key:z"), "Double '@' must fail");
    assert!(!validate_user_id("x@NOTADID"),    "Non-DID suffix must fail");

    // 2. Root account (pure did:key) must be accepted
    let (pub_key_root, _) = generate_ed25519_keypair_for_tests(Some("root-ok"));
    let root_id = create_user_id(&pub_key_root, None).unwrap();
    assert!(validate_user_id(&root_id), "Root account ID must be valid");

    // 3. Correct prefix ID must be accepted
    let (pub_key_prefix, _) = generate_ed25519_keypair_for_tests(Some("validate-ok"));
    let valid_id = create_user_id(&pub_key_prefix, Some("test")).unwrap();
    assert!(validate_user_id(&valid_id), "Correctly generated prefix ID must be valid");

    // Tampered checksum must be detected and rejected
    let mut tampered = valid_id.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(!validate_user_id(&tampered), "Tampered checksum must be detected and rejected");
}

/// A prefix with more than 63 characters in a manually constructed ID
/// (which can never be generated by `create_user_id`) must also be rejected
/// by `validate_user_id`.
///
/// This ensures that the length limitation is enforced not only during creation,
/// but also during validation of incoming IDs.
#[test]
fn test_user_id_validation_enforces_prefix_length_limit() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("pfx-len-validate"));

    // Valid ID with max 63-char prefix must be accepted
    let valid_id = create_user_id(&pub_key, Some(&"a".repeat(63))).unwrap();
    assert!(validate_user_id(&valid_id), "Max-length (63-char) prefix must be valid");

    // Manually constructed ID with 64-char prefix must be rejected
    let at_pos     = valid_id.find('@').unwrap();
    let did_part   = &valid_id[at_pos..];
    let last_colon = valid_id[..at_pos].rfind(':').unwrap();
    let checksum   = &valid_id[last_colon + 1..at_pos];
    let oversized  = format!("{}:{}{}", "a".repeat(64), checksum, did_part);
    assert!(!validate_user_id(&oversized), "Over-length prefix ID must be rejected by validator");
}

/// Each individual prefix format rule must independently trigger rejection.
/// In particular: leading hyphen, trailing hyphen, and consecutive hyphens
/// must each be sufficient on their own.
///
/// Background: The rules are connected with OR. If they were connected with AND,
/// multiple errors would have to occur simultaneously — which is rarer in practice
/// and would hide errors.
#[test]
fn test_user_id_validation_each_prefix_rule_independently_triggers_rejection() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("indep-rules"));
    let valid_id   = create_user_id(&pub_key, Some("valid")).unwrap();
    let at_pos     = valid_id.find('@').unwrap();
    let did_part   = &valid_id[at_pos..];
    let last_colon = valid_id[..at_pos].rfind(':').unwrap();
    let checksum   = &valid_id[last_colon + 1..at_pos];

    // Leading hyphen only -> must reject
    assert!(
        !validate_user_id(&format!("-valid:{checksum}{did_part}")),
        "Leading hyphen alone must trigger rejection"
    );

    // Trailing hyphen only -> must reject
    assert!(
        !validate_user_id(&format!("valid-:{checksum}{did_part}")),
        "Trailing hyphen alone must trigger rejection"
    );

    // Double hyphen only -> must reject
    assert!(
        !validate_user_id(&format!("val--id:{checksum}{did_part}")),
        "Double hyphen alone must trigger rejection"
    );

    // Original valid ID still passes (positive control)
    assert!(validate_user_id(&valid_id), "Original valid ID must still pass");
}

/// Hyphens and digits are explicitly allowed in the prefix.
/// This verifies that these permitted characters are not mistakenly blocked.
#[test]
fn test_user_id_validation_accepts_hyphens_and_digits_in_prefix() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("allowed-charset"));

    // Digits in prefix -> allowed
    let id_digit = create_user_id(&pub_key, Some("pre1fix")).unwrap();
    assert!(validate_user_id(&id_digit), "Prefix containing a digit must be valid");

    // Hyphen in the middle -> allowed
    let id_hyphen = create_user_id(&pub_key, Some("my-account")).unwrap();
    assert!(
        validate_user_id(&id_hyphen),
        "Prefix 'my-account' with a middle hyphen must be valid"
    );

    // Multiple hyphens (non-consecutive) -> allowed
    let id_multi = create_user_id(&pub_key, Some("my-long-id")).unwrap();
    assert!(validate_user_id(&id_multi), "Prefix 'my-long-id' with multiple hyphens must be valid");

    // Invalid characters in constructed IDs -> must be rejected
    assert!(!validate_user_id("pre@fix:abc@did:key:zabc"), "Prefix with '@' must be rejected");
    assert!(!validate_user_id("pre fix:abc@did:key:zabc"), "Prefix with space must be rejected");
}

// =============================================================================
// Error Messages (Display & Error::source)
// =============================================================================

/// All variants of `UserIdError` must provide a non-empty, readable error message.
/// This is important for meaningful feedback to users and developers.
#[test]
fn test_user_id_error_variants_have_descriptive_messages() {
    let errors = [
        UserIdError::PrefixTooLong(100),
        UserIdError::InvalidPrefixChars,
        UserIdError::InvalidPrefixStartEnd,
        UserIdError::PrefixHasConsecutiveSeparators,
    ];
    for e in &errors {
        let msg = format!("{e}");
        assert!(
            !msg.is_empty(),
            "Display for {e:?} must not be an empty string"
        );
    }
}

/// `GetPubkeyError` must provide a readable error message for all variants.
/// For variants that wrap a cause (`DecodingFailed`, `ConversionFailed`),
/// `Error::source()` must return `Some` so that the causal chain can be traced.
/// All other variants should return `None`.
#[test]
fn test_get_pubkey_error_has_readable_messages_and_correct_cause_chain() {
    use human_money_core::services::crypto_utils::GetPubkeyError;
    use std::error::Error;

    // Display must provide a non-empty message for all terminal variants
    for e in [
        GetPubkeyError::InvalidPrefix,
        GetPubkeyError::InvalidDidFormat,
        GetPubkeyError::InvalidMulticodec,
        GetPubkeyError::InvalidLength(10),
    ] {
        assert!(!format!("{e}").is_empty(), "Display for {e:?} must not be empty");
    }

    // Variants without cause -> source() == None
    assert!(GetPubkeyError::InvalidPrefix.source().is_none(),    "No source for InvalidPrefix");
    assert!(GetPubkeyError::InvalidDidFormat.source().is_none(), "No source for InvalidDidFormat");
    assert!(GetPubkeyError::InvalidMulticodec.source().is_none(),"No source for InvalidMulticodec");
    assert!(GetPubkeyError::InvalidLength(0).source().is_none(), "No source for InvalidLength");

    // DecodingFailed wraps a bs58 error -> source() must forward the cause
    let decode_err = bs58::decode("!invalid!").into_vec().unwrap_err();
    let e_decode = GetPubkeyError::DecodingFailed(decode_err);
    assert!(
        e_decode.source().is_some(),
        "DecodingFailed must expose its wrapped error via source()"
    );
}

// =============================================================================
// Curve Derivations (ed25519_pk_to_curve_point)
// =============================================================================

/// `ed25519_pk_to_curve_point` converts an Ed25519 verification key
/// into a point on the Edwards25519 curve. This function is used,
/// among other things, for cryptographic trap computations.
///
/// Invariants:
/// - Different keys -> different curve points (no collision)
/// - Same key -> always the same point (determinism)
#[test]
fn test_curve_point_derivation_is_injective_and_deterministic() {
    use human_money_core::services::crypto_utils::{
        ed25519_pk_to_curve_point, generate_ed25519_keypair_for_tests,
    };

    let (pub_key_a, _) = generate_ed25519_keypair_for_tests(Some("curve-key-a"));
    let (pub_key_b, _) = generate_ed25519_keypair_for_tests(Some("curve-key-b"));

    let point_a = ed25519_pk_to_curve_point(&pub_key_a).unwrap();
    let point_b = ed25519_pk_to_curve_point(&pub_key_b).unwrap();

    // Different keys -> different points (injectivity)
    assert_ne!(
        point_a, point_b,
        "Different public keys must map to different Edwards curve points"
    );

    // Deterministic: same key -> always same point
    let point_a_again = ed25519_pk_to_curve_point(&pub_key_a).unwrap();
    assert_eq!(
        point_a, point_a_again,
        "Same public key must always produce the same curve point"
    );
}

