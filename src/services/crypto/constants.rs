//! # Cryptographic Domain Separators
//!
//! This module centralizes all salt, label, and info strings used for
//! domain separation in cryptographic operations.
//!
//! ## Important
//! These constants are cryptographically bound. Changing any of these
//! values breaks compatibility with existing keys and data.
//! Changes require a new protocol version.

/// SLIP-0010 master key derivation: Standard HMAC key for Ed25519.
/// Corresponds to SLIP-0010 standard: `HMAC-SHA512(key="ed25519 seed", data=seed)`.
pub const SLIP10_ED25519_SEED_LABEL: &[u8] = b"ed25519 seed";

/// HKDF label for X25519 Diffie-Hellman key exchange.
/// Binds the derived SharedSecret to the `human-money-core` context.
pub const HKDF_X25519_EXCHANGE_LABEL: &[u8] = b"human-money-core/x25519-exchange";

/// Argon2id salt suffix for profile folder ID derivation.
/// Used in `AppService` to derive a deterministic folder ID
/// from the profile password.
pub const ARGON2_PROFILE_FOLDER_SALT: &[u8] = b"human-money-profile-folder-v1";
