//! # src/services/trap_manager.rs
//!
//! Implementiert die kryptographischen Primitive für die "Mathematische Falle" (Trap)
//! und Zero-Knowledge-Proofs (ZKP) gemäß Spezifikation v4.4.
//!
//! # Konzepte
//! - **Hash-to-Curve:** Deterministische Abbildung von Daten auf einen validen Kurvenpunkt U.
//! - **Trap:** Die Gleichung $V = m \cdot U + ID$, wobei $m$ geheim ist, aber $V$ und $U$ öffentlich.
//! - **ZKP:** Ein Schnorr-Beweis, dass der Ersteller $m$ kennt, ohne es zu verraten.

use crate::error::VoucherCoreError;
use crate::models::voucher::TrapData;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use std::convert::TryInto;

/// Generiert einen deterministischen EdwardsPoint aus beliebigen Eingabedaten.
/// Verwendet SHA-512 und die Elligator2-Variante von curve25519-dalek (`hash_from_bytes`).
///
/// # Arguments
/// * `input` - Die Eingabedaten (z.B. Transaktions-Details).
///
/// # Returns
/// Returns Ein valider `EdwardsPoint` auf der Kurve.
/// Generiert einen deterministischen Scalar aus beliebigen Eingabedaten.
/// Verwendet SHA-512.
pub fn hash_to_scalar(input: &[u8]) -> Scalar {
    let mut hasher = Sha512::default();
    hasher.update(input);
    Scalar::from_hash(hasher)
}

/// Generiert einen deterministischen EdwardsPoint aus beliebigen Eingabedaten.
/// Verwendet SHA-512 und die Elligator2-Variante von curve25519-dalek (`hash_from_bytes`).
///
/// # Arguments
/// * `input` - Die Eingabedaten (z.B. Transaktions-Details).
///
/// # Returns
/// Returns Ein valider `EdwardsPoint` auf der Kurve.
#[allow(deprecated)]
pub fn hash_to_curve(input: &[u8]) -> EdwardsPoint {
    // curve25519-dalek's hash_from_bytes uses SHA-512 internally and maps to a point.
    // This is secure and deterministic.
    EdwardsPoint::nonspec_map_to_curve::<Sha512>(input)
}

/// Leitet den Slope `m` deterministisch via HKDF ab.
///
/// # Arguments
/// * `prev_hash` - Der Hash der vorherigen Transaktion (Salt).
/// * `secret_key_bytes` - Der private Schlüssel des Senders (IKM).
/// * `prefix` - Das Präfix der User-ID (Info).
///
/// # Returns
/// Ein `Scalar`, der als `m` in der Trap-Gleichung verwendet wird.
pub fn derive_m(
    prev_hash: &str,
    secret_key_bytes: &[u8],
    prefix: &str,
) -> Result<Scalar, VoucherCoreError> {
    // Implementierung analog zu crypto_utils, aber spezifisch für Scalar-Ableitung.
    // Wir nutzen HKDF-SHA256.
    
    let salt = prev_hash.as_bytes();
    let ikm = secret_key_bytes;
    
    // HKDF-Extract
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    
    // HKDF-Expand
    // Wir benötigen 64 Bytes Output, um einen uniformen Scalar zu erzeugen (wide reduction).
    let mut okm = [0u8; 64]; 
    hkdf.expand(prefix.as_bytes(), &mut okm)
        .map_err(|_| VoucherCoreError::Crypto("HKDF expansion for m failed".to_string()))?;

    Ok(Scalar::from_bytes_mod_order_wide(&okm))
}

/// Generiert die Trap-Daten und den ZKP.
///
/// # Arguments
/// * `u` - Der Challenge-Punkt (berechnet via hash_to_curve).
/// * `m` - Der geheime Slope (Scalar).
/// * `my_id_point` - Der öffentliche Identitätspunkt des Senders (ID).
/// * `prefix` - Das Präfix (wird in die ZKP-Challenge eingebunden).
///
/// # Returns
/// Ein `TrapData`-Struct mit Base58-kodierten Werten.
/// Generiert die Trap-Daten und den ZKP.
///
/// # Arguments
/// * `ds_tag` - Der konstante Index-String.
/// * `u_scalar` - Der variierende Challenge-Scalar (berechnet via hash_to_scalar).
/// * `m` - Der geheime Slope (Scalar).
/// * `my_id_point` - Der öffentliche Identitätspunkt des Senders (ID).
/// * `prefix` - Das Präfix (wird in die ZKP-Challenge eingebunden).
///
/// # Returns
/// Ein `TrapData`-Struct mit Base58-kodierten Werten.
pub fn generate_trap(
    ds_tag: String,
    u_scalar: &Scalar,
    m: &Scalar,
    my_id_point: &EdwardsPoint,
    prefix: &str,
) -> Result<TrapData, VoucherCoreError> {
    // 1. Berechne V = u * (m * G) + ID
    //    V = (u * m) * G + ID
    //    Wir definieren M = m * G (Slope Point)
    let slope_term = (u_scalar * m) * ED25519_BASEPOINT_POINT;
    let v = slope_term + my_id_point;

    // 2. ZKP (Schnorr Proof)
    // Wir beweisen Wissen von 'm' bezüglich der Basis X = u * G.
    // Y = V - ID = m * X.
    // X = u * G
    // Y = m * X
    let x_base = u_scalar * ED25519_BASEPOINT_POINT;
    let y_public = v - my_id_point; // Dies ist (u*m)*G

    // Prover wählt zufälliges Nonce r
    let mut rng = rand::thread_rng();
    let r = Scalar::random(&mut rng);

    // Commitment R = r * X
    let commitment_r = r * x_base;

    // Challenge c = Hash(X, Y, R, prefix)
    let c = calculate_challenge(&x_base, &y_public, &commitment_r, prefix);

    // Response s = r + c * m
    let s = r + (c * m);

    // Serialisierung für Transport (Base58)
    // ds_tag ist bereits ein String (der konstante Index)
    
    // u ist der variierende Scalar
    let u_str = bs58::encode(u_scalar.as_bytes()).into_string();
    let blinded_id_str = bs58::encode(v.compress().as_bytes()).into_string();
    
    // Proof als Tupel (R, s) serialisiert
    // Format: [32 bytes R compressed] || [32 bytes s]
    let mut proof_bytes = Vec::with_capacity(64);
    proof_bytes.extend_from_slice(commitment_r.compress().as_bytes());
    proof_bytes.extend_from_slice(s.as_bytes());
    let proof_str = bs58::encode(proof_bytes).into_string();

    Ok(TrapData {
        ds_tag,
        u: u_str,
        blinded_id: blinded_id_str,
        proof: proof_str,
    })
}

/// Verifiziert die Trap-Daten und den ZKP.
///
/// # Arguments
/// * `trap_data` - Die empfangenen Trap-Daten.
/// * `expected_ds_tag` - Der erwartete konstante Index.
/// * `expected_u_input` - Die rohen Daten, die zu U führen sollten (zur Prüfung von U).
/// * `signer_id_point` - Der öffentliche Identitätspunkt (ID) des Senders.
/// * `prefix` - Das Nutzer-Präfix.
///
/// # Returns
/// Ok(()), wenn der Proof gültig ist.
pub fn verify_trap(
    trap_data: &TrapData,
    expected_ds_tag: &str,
    expected_u_input: &[u8],
    signer_id_point: &EdwardsPoint,
    prefix: &str,
) -> Result<(), VoucherCoreError> {
    // 1. Verify DS-Tag (Constant Index)
    if trap_data.ds_tag != expected_ds_tag {
        return Err(VoucherCoreError::Crypto("Trap DS-Tag does not match expected input (Constant Index Mismatch)".to_string()));
    }

    // 2. Parse U (Varying Challenge SCALAR), V (Blinded ID Point)
    let u_bytes = bs58::decode(&trap_data.u).into_vec().map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    let blinded_id_bytes = bs58::decode(&trap_data.blinded_id).into_vec().map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    
    let u_scalar = Scalar::from_bytes_mod_order(u_bytes.try_into().map_err(|_| VoucherCoreError::Crypto("Invalid Scalar U length".to_string()))?);
    let v_point = CompressedEdwardsY::from_slice(&blinded_id_bytes).map_err(|_| VoucherCoreError::Crypto("Invalid Blinded-ID (V)".to_string()))?.decompress().ok_or(VoucherCoreError::Crypto("Decompression Blinded-ID failed".to_string()))?;

    // 3. Verify U matches expected varying input (t_id included)
    let calculated_u_scalar = hash_to_scalar(expected_u_input);
    if u_scalar != calculated_u_scalar {
        return Err(VoucherCoreError::Crypto("Trap Scalar U does not match transaction data (Varying Input Mismatch)".to_string()));
    }

    // 4. Parse Proof (R, s)
    let proof_bytes = bs58::decode(&trap_data.proof).into_vec().map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    if proof_bytes.len() != 64 {
        return Err(VoucherCoreError::Crypto("Invalid proof length".to_string()));
    }
    let (r_bytes, s_bytes) = proof_bytes.split_at(32);
    
    let commitment_r = CompressedEdwardsY::from_slice(r_bytes).map_err(|_| VoucherCoreError::Crypto("Invalid point R".to_string()))?.decompress().ok_or(VoucherCoreError::Crypto("Decompression R failed".to_string()))?;
    let s = Scalar::from_bytes_mod_order(s_bytes.try_into().unwrap());

    // 5. Verify ZKP: s * X == R + c * Y
    // X = u * G
    // Y = V - ID
    let x_base = u_scalar * ED25519_BASEPOINT_POINT;
    let y_public = v_point - signer_id_point;

    let c = calculate_challenge(&x_base, &y_public, &commitment_r, prefix);
    
    let rhs = commitment_r + (c * y_public); // R + c*Y
    let lhs = s * x_base; // s * X

    if lhs != rhs {
        return Err(VoucherCoreError::Crypto("Trap ZKP verification failed".to_string()));
    }

    Ok(())
}

// Helper: Calculate Challenge c = Hash(U, V, R, prefix)
fn calculate_challenge(
    u: &EdwardsPoint,
    v: &EdwardsPoint,
    r: &EdwardsPoint,
    prefix: &str,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(u.compress().as_bytes());
    hasher.update(v.compress().as_bytes());
    hasher.update(r.compress().as_bytes());
    hasher.update(prefix.as_bytes());
    
    Scalar::from_hash(hasher)
}
