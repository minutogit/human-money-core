//! # Kryptographische Domain-Separatoren
//!
//! Dieses Modul zentralisiert alle Salt-, Label- und Info-Strings, die zur
//! Domain-Separation in kryptographischen Operationen verwendet werden.
//!
//! ## Wichtig
//! Diese Konstanten sind kryptographisch gebunden. Eine Änderung eines dieser
//! Werte bricht die Kompatibilität mit bestehenden Schlüsseln und Daten.
//! Änderungen erfordern eine neue Protokollversion.

/// SLIP-0010 Master-Key-Ableitung: Standard HMAC-Key für Ed25519.
/// Entspricht dem SLIP-0010-Standard: `HMAC-SHA512(key="ed25519 seed", data=seed)`.
pub const SLIP10_ED25519_SEED_LABEL: &[u8] = b"ed25519 seed";

/// HKDF-Label für den X25519 Diffie-Hellman Schlüsselaustausch.
/// Bindet den abgeleiteten SharedSecret an den `human-money-core`-Kontext.
pub const HKDF_X25519_EXCHANGE_LABEL: &[u8] = b"human-money-core/x25519-exchange";

/// Argon2id Salt-Suffix für die Profil-Ordner-ID-Ableitung.
/// Wird in `AppService` verwendet, um eine deterministische Ordner-ID
/// aus dem Profil-Passwort abzuleiten.
pub const ARGON2_PROFILE_FOLDER_SALT: &[u8] = b"human-money-profile-folder-v1";
