//! # src/services/trap_manager.rs
//!
//! Implements cryptographic primitives for the "Mathematical Trap"
//! and Zero-Knowledge-Proofs (ZKP) according to specification v4.4.
//!
//! # Concepts
//! - **Hash-to-Curve:** Deterministic mapping of data to a valid curve point U.
//! - **Trap:** The equation $V = m \cdot U + ID$, where $m$ is secret, but $V$ and $U$ are public.
//! - **ZKP:** A Schnorr proof that the creator knows $m$ without revealing it.

use crate::error::VoucherCoreError;
use crate::models::voucher::TrapData;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use crate::services::crypto_utils::{get_secret_scalar, generate_dleq_proof};
use std::convert::TryInto;

/// Generates a deterministic Scalar from arbitrary input data.
/// Uses SHA-512.
///
/// # Arguments
/// * `input` - The input data (e.g. transaction details).
///
/// # Returns
/// A valid `Scalar`.
pub fn hash_to_scalar(input: &[u8]) -> Scalar {
    let mut hasher = Sha512::default();
    hasher.update(input);
    Scalar::from_hash(hasher)
}

/// Generates a deterministic EdwardsPoint from arbitrary input data.
/// Uses SHA-512 and curve25519-dalek mapping to curve.
///
/// # Arguments
/// * `input` - The input data (e.g. transaction details).
///
/// # Returns
/// A valid `EdwardsPoint` on the curve.
#[allow(deprecated)]
pub fn hash_to_curve(input: &[u8]) -> EdwardsPoint {
    // curve25519-dalek's hash_from_bytes uses SHA-512 internally and maps to a point.
    // This is secure and deterministic.
    EdwardsPoint::nonspec_map_to_curve::<Sha512>(input)
}

/// Derives the slope `m` deterministically.
///
/// # Arguments
/// * `prev_hash` - The hash of the previous transaction.
/// * `secret_key_bytes` - The private key of the sender.
/// * `_prefix` - Ignored, kept for backward compatibility.
///
/// # Returns
/// A `Scalar` used as `m` in the trap equation.
pub fn derive_m(
    prev_hash: &str,
    secret_key_bytes: &[u8],
    _prefix: Option<&str>,
) -> Result<Scalar, VoucherCoreError> {
    let key_bytes: [u8; 32] = secret_key_bytes.try_into().map_err(|_| {
        VoucherCoreError::Crypto("secret_key_bytes must be exactly 32 bytes".to_string())
    })?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    let sk_sender = get_secret_scalar(&signing_key);
    
    let prev_hash_bytes = bs58::decode(prev_hash)
        .into_vec()
        .unwrap_or_else(|_| prev_hash.as_bytes().to_vec());
    let p_point = hash_to_curve(&prev_hash_bytes);
    let k_point = sk_sender * p_point;
    let m = hash_to_scalar(&k_point.compress().to_bytes());
    Ok(m)
}

#[derive(Debug, Clone)]
pub struct DleqProof {
    pub trap_k_point: [u8; 32],
    pub dleq_c: [u8; 32],
    pub dleq_s: [u8; 32],
}

/// Generates trap data and the ZKP.
///
/// # Arguments
/// * `ds_tag` - The constant index string.
/// * `u_scalar` - The varying challenge scalar (computed via hash_to_scalar).
/// * `m` - The secret slope (Scalar).
/// * `my_id_point` - The public identity point of the sender (ID).
/// * `prefix` - The optional prefix. None for root accounts.
/// * `sk_sender` - Optional sender secret scalar (for DLEQ proof).
/// * `p_point` - Optional generator point P (for DLEQ proof).
///
/// # Returns
/// A `TrapData` struct and optional `DleqProof`.
pub fn generate_trap(
    ds_tag: String,
    u_scalar: &Scalar,
    m: &Scalar,
    my_id_point: &EdwardsPoint,
    prefix: Option<&str>,
    sk_sender: Option<&Scalar>,
    p_point: Option<&EdwardsPoint>,
) -> Result<(TrapData, Option<DleqProof>), VoucherCoreError> {
    // 1. Calculate V = u * (m * G) + ID
    //    V = (u * m) * G + ID
    //    We define M = m * G (Slope Point)
    let slope_term = (u_scalar * m) * ED25519_BASEPOINT_POINT;
    let v = slope_term + my_id_point;

    // 2. ZKP (Schnorr Proof)
    // We prove knowledge of 'm' with respect to base X = u * G.
    // Y = V - ID = m * X.
    // X = u * G
    // Y = m * X
    let x_base = u_scalar * ED25519_BASEPOINT_POINT;
    let y_public = v - my_id_point; // This is (u*m)*G

    // Prover chooses random nonce r
    let mut rng = rand::thread_rng();
    let r = Scalar::random(&mut rng);

    // Commitment R = r * X
    let commitment_r = r * x_base;

    // Challenge c = Hash(X, Y, R, prefix)
    let c = calculate_challenge(&x_base, &y_public, &commitment_r, prefix);

    // Response s = r + c * m
    let s = r + (c * m);

    // Serialization for transport (Base58)
    // ds_tag is already a string (the constant index)

    // u is the varying scalar
    let u_str = bs58::encode(u_scalar.as_bytes()).into_string();
    let blinded_id_str = bs58::encode(v.compress().as_bytes()).into_string();

    // Proof serialized as tuple (R, s)
    // Format: [32 bytes R compressed] || [32 bytes s]
    let mut proof_bytes = Vec::with_capacity(64);
    proof_bytes.extend_from_slice(commitment_r.compress().as_bytes());
    proof_bytes.extend_from_slice(s.as_bytes());
    let proof_str = bs58::encode(proof_bytes).into_string();

    let trap_data = TrapData {
        ds_tag,
        u: u_str,
        blinded_id: blinded_id_str,
        proof: proof_str,
    };

    let dleq_proof = if let (Some(sk), Some(p)) = (sk_sender, p_point) {
        let k_point = sk * p;
        let (c_dleq, s_dleq) = generate_dleq_proof(sk, p, &k_point);
        Some(DleqProof {
            trap_k_point: k_point.compress().to_bytes(),
            dleq_c: c_dleq.to_bytes(),
            dleq_s: s_dleq.to_bytes(),
        })
    } else {
        None
    };

    Ok((trap_data, dleq_proof))
}

/// Verifies trap data and the ZKP.
///
/// # Arguments
/// * `trap_data` - The received trap data.
/// * `expected_ds_tag` - The expected constant index.
/// * `expected_u_input` - The raw data expected to produce U (for checking U).
/// * `signer_id_point` - The public identity point (ID) of the sender.
/// * `prefix` - The optional user prefix. None for root accounts.
///
/// # Returns
/// Ok(()) if the proof is valid.
pub fn verify_trap(
    trap_data: &TrapData,
    expected_ds_tag: &str,
    expected_u_input: &[u8],
    signer_id_point: &EdwardsPoint,
    prefix: Option<&str>,
) -> Result<(), VoucherCoreError> {
    // 1. Verify DS-Tag (Constant Index)
    if trap_data.ds_tag != expected_ds_tag {
        return Err(VoucherCoreError::Crypto(
            "Trap DS-Tag does not match expected input (Constant Index Mismatch)".to_string(),
        ));
    }

    // 2. Parse U (Varying Challenge SCALAR), V (Blinded ID Point)
    let u_bytes = bs58::decode(&trap_data.u)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    let blinded_id_bytes = bs58::decode(&trap_data.blinded_id)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let u_scalar = Scalar::from_bytes_mod_order(
        u_bytes
            .try_into()
            .map_err(|_| VoucherCoreError::Crypto("Invalid Scalar U length".to_string()))?,
    );
    let v_point = CompressedEdwardsY::from_slice(&blinded_id_bytes)
        .map_err(|_| VoucherCoreError::Crypto("Invalid Blinded-ID (V)".to_string()))?
        .decompress()
        .ok_or(VoucherCoreError::Crypto(
            "Decompression Blinded-ID failed".to_string(),
        ))?;

    // 3. Verify U matches expected varying input (t_id included)
    let calculated_u_scalar = hash_to_scalar(expected_u_input);
    if u_scalar != calculated_u_scalar {
        return Err(VoucherCoreError::Crypto(
            "Trap Scalar U does not match transaction data (Varying Input Mismatch)".to_string(),
        ));
    }

    // 4. Parse Proof (R, s)
    let proof_bytes = bs58::decode(&trap_data.proof)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    if proof_bytes.len() != 64 {
        return Err(VoucherCoreError::Crypto("Invalid proof length".to_string()));
    }
    let (r_bytes, s_bytes) = proof_bytes.split_at(32);

    let commitment_r = CompressedEdwardsY::from_slice(r_bytes)
        .map_err(|_| VoucherCoreError::Crypto("Invalid point R".to_string()))?
        .decompress()
        .ok_or(VoucherCoreError::Crypto(
            "Decompression R failed".to_string(),
        ))?;
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
        return Err(VoucherCoreError::Crypto(
            "Trap ZKP verification failed".to_string(),
        ));
    }

    Ok(())
}

// Helper: Calculate Challenge c = Hash(U, V, R, prefix)
fn calculate_challenge(
    u: &EdwardsPoint,
    v: &EdwardsPoint,
    r: &EdwardsPoint,
    prefix: Option<&str>,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(u.compress().as_bytes());
    hasher.update(v.compress().as_bytes());
    hasher.update(r.compress().as_bytes());
    hasher.update(prefix.unwrap_or("").as_bytes());

    Scalar::from_hash(hasher)
}

/// Extracts the identity (ID point) mathematically from two colliding trap data entries.
/// This is the core unmasking logic for double-spends.
///
/// Identity is recovered via equation ID = V1 - u1 * (V1 - V2) * (u1 - u2)^-1,
/// where V is the blinded_id point and u is the challenge scalar.
pub fn extract_id_point_from_raw_data(
    ds_tag1: &str,
    u1_str: &str,
    v1_str: &str,
    ds_tag2: &str,
    u2_str: &str,
    v2_str: &str,
) -> Result<EdwardsPoint, VoucherCoreError> {
    if ds_tag1 != ds_tag2 {
        return Err(VoucherCoreError::Crypto(
            "Traps have different DS-Tags - not a collision".to_string(),
        ));
    }
    if u1_str == u2_str {
        return Err(VoucherCoreError::Crypto(
            "Traps have identical U (no fork detected)".to_string(),
        ));
    }

    // 1. Decode Base58 data
    let u1_bytes = bs58::decode(u1_str)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid U1: {}", e)))?;
    let u2_bytes = bs58::decode(u2_str)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid U2: {}", e)))?;
    let v1_bytes = bs58::decode(v1_str)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid V1: {}", e)))?;
    let v2_bytes = bs58::decode(v2_str)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid V2: {}", e)))?;

    // 2. Convert to cryptographic types
    let u1 = Scalar::from_bytes_mod_order(
        u1_bytes
            .try_into()
            .map_err(|_| VoucherCoreError::Crypto("Invalid Scalar U1 length".to_string()))?,
    );
    let u2 = Scalar::from_bytes_mod_order(
        u2_bytes
            .try_into()
            .map_err(|_| VoucherCoreError::Crypto("Invalid Scalar U2 length".to_string()))?,
    );

    let v1 = CompressedEdwardsY::from_slice(&v1_bytes)
        .map_err(|_| VoucherCoreError::Crypto("Invalid Blinded-ID V1".to_string()))?
        .decompress()
        .ok_or_else(|| VoucherCoreError::Crypto("Decompress V1 failed".to_string()))?;
    let v2 = CompressedEdwardsY::from_slice(&v2_bytes)
        .map_err(|_| VoucherCoreError::Crypto("Invalid Blinded-ID V2".to_string()))?
        .decompress()
        .ok_or_else(|| VoucherCoreError::Crypto("Decompress V2 failed".to_string()))?;

    // 3. Calculate deltas
    let delta_v = v1 - v2;
    let delta_u = u1 - u2;

    // 4. Calculate slope point M = Delta V * (Delta U)^-1
    let delta_u_inv = delta_u.invert();
    let m_point = delta_v * delta_u_inv;

    // 5. Calculate identity ID = V1 - u1 * M
    let recovered_id_point = v1 - (m_point * u1);

    Ok(recovered_id_point)
}
