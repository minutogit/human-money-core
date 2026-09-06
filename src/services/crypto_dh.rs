//! # src/services/crypto_dh.rs
//!
//! Contains Diffie-Hellman key exchange logic using X25519.

use rand_core::OsRng;
use sha2::{Digest, Sha256, Sha512};
use ed25519_dalek::{SigningKey, VerifyingKey as EdPublicKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use hkdf::Hkdf;
use std::convert::TryInto;

use crate::error::VoucherCoreError;
use crate::services::crypto_constants::HKDF_X25519_EXCHANGE_LABEL;
use crate::services::crypto_symmetric::{encrypt_data, decrypt_data};
use crate::services::crypto_utils::{encode_base64, decode_base64};

/// Converts an Ed25519 public key to an X25519 public key for Diffie-Hellman key exchange.
///
/// This function converts an Ed25519 public key to its X25519 equivalent,
/// which is required for performing Diffie-Hellman key exchange.
///
/// # Arguments
///
/// * `ed_pub` - The Ed25519 public key.
///
/// # Returns
///
/// The X25519 public key.
pub fn ed25519_pub_to_x25519(ed_pub: &EdPublicKey) -> X25519PublicKey {
    let montgomery_point = ed_pub.to_montgomery();
    let x25519_bytes: [u8; 32] = montgomery_point.to_bytes();
    X25519PublicKey::from(x25519_bytes)
}

/// Helper: Builds the deterministic info string for HKDF.
/// The `recipient_id` is mandatory to enforce cryptographic separation
/// between different SAIs (Separated Account Identities) of the same user.
pub fn build_hkdf_info(pk1: &X25519PublicKey, pk2: &X25519PublicKey, recipient_id: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(HKDF_X25519_EXCHANGE_LABEL.len() + 64 + recipient_id.len() + 2);
    info.extend_from_slice(HKDF_X25519_EXCHANGE_LABEL);
    info.extend_from_slice(b"|");
    info.extend_from_slice(recipient_id.as_bytes());
    info.extend_from_slice(b"|");

    let (key_a, key_b) = if pk1.as_bytes() < pk2.as_bytes() {
        (pk1.as_bytes(), pk2.as_bytes())
    } else {
        (pk2.as_bytes(), pk1.as_bytes())
    };

    info.extend_from_slice(key_a);
    info.extend_from_slice(key_b);
    info
}

/// Generates a temporary X25519 key pair for Diffie-Hellman (Forward Secrecy).
///
/// This function generates a fresh X25519 key pair for each Diffie-Hellman exchange,
/// ensuring forward secrecy.
///
/// # Returns
///
/// A tuple containing the X25519 public key and the ephemeral secret.
pub fn generate_ephemeral_x25519_keypair() -> (X25519PublicKey, EphemeralSecret) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public, secret)
}

/// Performs Diffie-Hellman key exchange.
///
/// This function performs Diffie-Hellman key exchange using our ephemeral secret
/// and the other party's public key.
///
/// # Security Note
///
/// This function provides **Confidentiality** and **Sender Forward Secrecy**, but:
/// * **No Authentication:** Without an additional authentication layer (like signing the resulting container), this exchange is vulnerable to Man-in-the-Middle (MITM) attacks.
/// * **Recipient Compromise:** Since the recipient uses a static key (asynchronous protocol), a compromise of the recipient's private key allows decryption of PAST messages.
/// * **Replay/Key-Substitution:** The protocol layer must ensure protection against replay attacks and key substitution (e.g., by binding the container signature to the keys).
///
/// # Returns
///
/// The derived 32-byte shared symmetric key, or an error if the exchange was non-contributory.
pub fn perform_diffie_hellman(
    our_secret: EphemeralSecret,
    their_public: &X25519PublicKey,
    recipient_id: &str,
) -> Result<[u8; 32], VoucherCoreError> {
    // 1. Derive own public key (for context binding)
    let our_public = X25519PublicKey::from(&our_secret);

    // 2. Calculate raw shared secret
    let shared_secret = our_secret.diffie_hellman(their_public);

    // SECURITY: Check for non-contributory behavior (e.g. point at infinity/null).
    // This prevents attacks using weak keys or manipulated public keys.
    if !shared_secret.was_contributory() {
        return Err(VoucherCoreError::Crypto(
            "Diffie-Hellman exchange was non-contributory (weak key).".to_string(),
        ));
    }

    // 3. HKDF-Expansion
    // Salt is None because we are an asynchronous offline protocol without an interactive session handshake.
    //
    // DESIGN DECISION ON KEY SPLITTING:
    // We derive only a single 32-byte key here because it serves exclusively as a KEK for
    // ChaCha20Poly1305 (AEAD) in a unidirectional context.
    // - AEAD does not require separate Enc/MAC keys.
    // - Unidirectionality does not require separation into Send/Receive keys.
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    // CANONICALIZATION & info string construction with SAI-Binding
    let info = build_hkdf_info(&our_public, their_public, recipient_id);

    // Derivation of the key
    let mut symmetric_key = [0u8; 32];
    // expand should never fail here since the output length is fixed.
    hkdf.expand(&info, &mut symmetric_key)
        .map_err(|_| VoucherCoreError::Crypto("HKDF expansion failed".to_string()))?;

    Ok(symmetric_key)
}

/// Converts an Ed25519 signature key to an X25519 secret key for Diffie-Hellman.
///
/// This is the counterpart to the public key `ed25519_pub_to_x25519`. It enables the
/// derivation of a key agreement key (X25519) from a long-term
/// identity key (Ed25519).
///
/// # Arguments
///
/// * `ed_sk` - The secret Ed25519 signing key (`SigningKey`).
///
/// # Returns
///
/// The corresponding static secret X25519 key (`StaticSecret`).
///
/// # Security
///
/// The conversion follows the standard method, where the seed of the private Ed25519 key
/// is hashed with SHA-512. The lower 32 bytes of the hash are used. The function
/// `StaticSecret::from` then performs the clamping required for X25519.
pub fn ed25519_sk_to_x25519_sk(ed_sk: &SigningKey) -> StaticSecret {
    let mut hasher = Sha512::new();
    hasher.update(&ed_sk.to_bytes());
    let hash = hasher.finalize();
    // We must explicitly specify the target type for `try_into` to the compiler.
    let key_bytes: [u8; 32] = hash[..32]
        .try_into()
        .expect("SHA512 hash is guaranteed to be 64 bytes");
    StaticSecret::from(key_bytes)
}

/// Encrypts the Privacy Guard payload for the recipient.
///
/// # Arguments
/// * `payload_bytes` - The serialized data of the RecipientPayload.
/// * `recipient_public_key_ed` - The permanent public key (Ed25519) of the recipient.
pub fn encrypt_recipient_payload(
    payload_bytes: &[u8],
    recipient_public_key_ed: &EdPublicKey,
    recipient_id: &str,
) -> Result<String, VoucherCoreError> {
    let (ephemeral_pk, ephemeral_sk) = generate_ephemeral_x25519_keypair();
    let recipient_x_pk = ed25519_pub_to_x25519(recipient_public_key_ed);
    let shared_secret = perform_diffie_hellman(ephemeral_sk, &recipient_x_pk, recipient_id)?;
    let encrypted_bytes = encrypt_data(&shared_secret, payload_bytes)?;

    let mut privacy_guard_bytes = Vec::new();
    privacy_guard_bytes.extend_from_slice(ephemeral_pk.as_bytes());
    privacy_guard_bytes.extend_from_slice(&encrypted_bytes);
    Ok(encode_base64(&privacy_guard_bytes))
}

/// Decrypts the Privacy Guard payload for the recipient.
///
/// # Arguments
/// * `privacy_guard_base64` - The Base64-encoded guard string.
/// * `recipient_secret_key` - The permanent signing key of the recipient (will be converted to StaticSecret).
///
/// # Returns
/// The decrypted byte vector (JSON payload).
pub fn decrypt_recipient_payload(
    privacy_guard_base64: &str,
    recipient_secret_key: &SigningKey,
    recipient_id: &str,
) -> Result<Vec<u8>, VoucherCoreError> {
    // 1. Decode Base64
    let guard_bytes = decode_base64(privacy_guard_base64)?;

    // Guard Format: [EphemeralPK (32)] + [Nonce+Ciphertext]
    if guard_bytes.len() < 32 + 12 {
        return Err(VoucherCoreError::Crypto(
            "Invalid privacy guard length".to_string(),
        ));
    }

    let (ephemeral_pk_bytes, encrypted_content) = guard_bytes.split_at(32);

    // 2. Parse Ephemeral Public Key
    let ephemeral_pk_arr: [u8; 32] = ephemeral_pk_bytes.try_into().map_err(|_| {
        VoucherCoreError::Crypto(
            "Invalid ephemeral public key length (expected 32 bytes)".to_string(),
        )
    })?;
    let ephemeral_pk_x = X25519PublicKey::from(ephemeral_pk_arr);

    // 3. Recipient Secret Key conversion (Ed25519 -> X25519)
    let recipient_secret_x = ed25519_sk_to_x25519_sk(recipient_secret_key);

    // 4. DH Exchange
    let shared_point = recipient_secret_x.diffie_hellman(&ephemeral_pk_x);

    // SECURITY: Check for non-contributory behavior (e.g. point at infinity/null).
    // Mirrors `perform_diffie_hellman`: an attacker-controlled low-order
    // ephemeral key must never yield an attacker-known shared secret.
    if !shared_point.was_contributory() {
        return Err(VoucherCoreError::Crypto(
            "Diffie-Hellman exchange was non-contributory (weak key).".to_string(),
        ));
    }

    let shared_secret_bytes = shared_point.as_bytes();

    // 5. HKDF Derivation with SAI-Binding
    let recipient_public_x = X25519PublicKey::from(&recipient_secret_x);
    let info = build_hkdf_info(&ephemeral_pk_x, &recipient_public_x, recipient_id);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret_bytes);
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(&info, &mut symmetric_key)
        .map_err(|_| VoucherCoreError::Crypto("HKDF expansion failed".to_string()))?;

    // 6. Decrypt
    decrypt_data(&symmetric_key, encrypted_content).map_err(VoucherCoreError::SymmetricEncryption)
}
