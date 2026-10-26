//! Compact V4 shared-signature traps and victim witness disclosure.
//!
//! Honest spends share one Schnorr signature over mu = H(domain, ds_tag, E).
//! The private nonce is H(domain, x, mu), never a hash of the disclosed VRF
//! point K_trap. Both masks derive from (R_sig, s_sig, mu), so reconstructed
//! lines can be checked without a private witness. Single-shard anonymity is
//! computational; deterministic hash-derived masks are not perfect hiding.
//!
//! All outputs bind E = X + H(domain, seed, X)G to their owner. The opening
//! seed stays inside the encrypted recipient guard during normal transfers.
//! Public shards remain one point and one scalar (64 bytes).
//!
//! A malformed historical shard or a malicious signer's fresh nonce can make
//! autonomous signature reconstruction fail. A direct victim can still prove
//! the owner with its checked handover witness plus two conflicting E-signed
//! fingerprints. Only that authenticated conflict permits witness disclosure
//! and definitive DID attribution. Bare gossip yields an ephemeral offender
//! and, if reconstruction succeeds, an advisory identity candidate.

use crate::error::VoucherCoreError;
use crate::models::conflict::TransactionFingerprint;
use crate::models::voucher::{Transaction, TrapData};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use std::convert::TryInto;

use crate::services::crypto::{
    ed25519_pk_to_curve_point, get_pubkey_from_user_id, get_secret_scalar, hash_to_curve,
};

//==============================================================================
// DOMAIN SEPARATION TAGS (V4 / SST)
//==============================================================================

/// Domain tag binding the trap message $\mu$ to the spend input.
pub const SST_DOMAIN_SIG_MSG: &[u8] = b"HMC_TRAP_SIG_V4";
/// Domain tag for the deterministic Schnorr nonce derivation.
pub const SST_DOMAIN_NONCE: &[u8] = b"HMC_TRAP_NONCE_V4";
/// Domain tag for the Schnorr challenge hash.
pub const SST_DOMAIN_CHALLENGE: &[u8] = b"HMC_TRAP_CHAL_V4";
/// Domain tag for the masking point $M_R$ derivation.
pub const SST_DOMAIN_MASK_R: &[u8] = b"HMC_MASK_R_V4";
/// Domain tag for the masking scalar $m_s$ derivation.
pub const SST_DOMAIN_MASK_S: &[u8] = b"HMC_MASK_S_V4";
/// Domain tag for the spend-specific shard evaluation point $\tau_i$.
pub const SST_DOMAIN_TAU: &[u8] = b"HMC_TAU_V4";
/// Domain tag for VRF generator point H_mu derivation.
pub const SST_DOMAIN_VRF_BASE: &[u8] = b"HMC_SST_VRF_BASE_V4";
/// Domain tag for deterministic DLEQ nonce derivation.
pub const SST_DOMAIN_DLEQ_NONCE: &[u8] = b"HMC_SST_DLEQ_NONCE_V4";
/// Domain tag for Chaum-Pedersen DLEQ challenge hash.
pub const SST_DOMAIN_DLEQ_CHAL: &[u8] = b"HMC_SST_DLEQ_CHAL_V4";
/// Domain tag for stealth key blinding scalar derivation.
pub const SST_DOMAIN_STEALTH_BLIND: &[u8] = b"HMC_STEALTH_BLIND_V4";
/// Domain tag for stealth key Ed25519 signing nonce derivation.
pub const SST_DOMAIN_STEALTH_NONCE: &[u8] = b"HMC_STEALTH_NONCE_V4";

/// Canonical marker for absent trap components (genesis transactions).
pub const SST_NONE_PLACEHOLDER: &str = "none";

//==============================================================================
// CORE HASH HELPERS
//==============================================================================

/// Generates a deterministic Scalar from arbitrary input data (SHA-512).
pub fn hash_to_scalar(input: &[u8]) -> Scalar {
    let mut hasher = Sha512::default();
    hasher.update(input);
    Scalar::from_hash(hasher)
}

/// Encodes a domain tag plus raw parts with 4-byte little-endian length
/// prefixes (anti-malleability: segment boundaries cannot be shifted).
pub fn sst_encoded_parts(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(tag.len() as u32).to_le_bytes());
    out.extend_from_slice(tag);
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Derives a deterministic scalar from a domain tag and raw parts
/// (SHA-512 followed by modular reduction).
pub fn sst_scalar(tag: &[u8], parts: &[&[u8]]) -> Scalar {
    hash_to_scalar(&sst_encoded_parts(tag, parts))
}

/// Computes the SST trap message $\mu$ that binds the shared signature to the
/// spend input:
/// $\mu = H(\text{"HMC\_TRAP\_SIG\_V4"} \parallel ds\_tag \parallel E)$.
///
/// All segments are length-prefixed. See the module docs for why the raw
/// `prev_hash` is intentionally not part of $\mu$ (it is committed by
/// `ds_tag`, and gossip fingerprints must be self-sufficient for autonomous
/// identity extraction).
///
/// # Arguments
/// * `ds_tag` - The Base58-encoded double-spend tag of the spent input.
/// * `eph_pub` - The revealed ephemeral public key of the spender (32 bytes).
pub fn compute_trap_message_mu(ds_tag: &str, eph_pub: &[u8; 32]) -> [u8; 32] {
    crate::services::crypto::get_raw_hash_from_slices(&[
        SST_DOMAIN_SIG_MSG,
        ds_tag.as_bytes(),
        eph_pub.as_slice(),
    ])
}

/// Derives tau from the input, transaction ID, and authenticated guard hash.
/// Different guards yield different evaluations even when the ID is reused.
pub fn compute_tau(ds_tag: &str, t_id: &str, guard_hash: &str) -> Scalar {
    sst_scalar(
        SST_DOMAIN_TAU,
        &[ds_tag.as_bytes(), t_id.as_bytes(), guard_hash.as_bytes()],
    )
}

/// Computes the Schnorr challenge
/// $c = H(\text{"HMC\_TRAP\_CHAL\_V4"} \parallel \mu \parallel R) \bmod q$.
fn sst_challenge(mu: &[u8; 32], commitment_r: &EdwardsPoint) -> Scalar {
    sst_scalar(
        SST_DOMAIN_CHALLENGE,
        &[mu.as_slice(), commitment_r.compress().as_bytes()],
    )
}

/// Public counterpart of [`sst_challenge`] (same length-prefixed derivation).
///
/// Exposed so external tooling/tests can derive the challenge identically to
/// the engine when reconstructing alternative witnesses of the same shard.
pub fn compute_sst_challenge(mu: &[u8; 32], commitment_r: &EdwardsPoint) -> Scalar {
    sst_challenge(mu, commitment_r)
}

/// Parses a 32-byte scalar strictly in canonical (fully reduced) form.
///
/// # Security
/// `from_bytes_mod_order` silently reduces non-canonical encodings
/// (`x` and `x + l` map to the same scalar), which allowed malleability
/// attacks where two different byte strings represent the same scalar.
/// This helper rejects any encoding that is not the canonical
/// little-endian representation of a scalar below the group order.
fn parse_canonical_scalar(bytes: &[u8], label: &str) -> Result<Scalar, VoucherCoreError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VoucherCoreError::Crypto(format!("Invalid Scalar {} length", label)))?;
    Scalar::from_canonical_bytes(arr)
        .into_option()
        .ok_or_else(|| {
            VoucherCoreError::Crypto(format!(
                "Non-canonical scalar encoding for {} rejected",
                label
            ))
        })
}

/// Decompresses a Base58-encoded Edwards point, rejecting malformed input.
fn parse_point_bs58(encoded: &str, label: &str) -> Result<EdwardsPoint, VoucherCoreError> {
    if encoded.len() > 44 {
        return Err(VoucherCoreError::Crypto(format!(
            "Point {} exceeds maximum Base58 length",
            label
        )));
    }
    let bytes = crate::services::crypto::decode_bs58_fixed::<32>(encoded, label)?;
    ensure_canonical_y(&bytes)?;
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| VoucherCoreError::Crypto(format!("Decompression of {} failed", label)))?;
    if point.compress().to_bytes() != bytes || !point.is_torsion_free() {
        return Err(VoucherCoreError::Crypto(format!(
            "Non-canonical or non-prime-order point {} rejected",
            label
        )));
    }
    Ok(point)
}

fn parse_scalar_bs58(encoded: &str, label: &str) -> Result<Scalar, VoucherCoreError> {
    if encoded.len() > 44 {
        return Err(VoucherCoreError::Crypto(
            "Scalar exceeds maximum Base58 length".into(),
        ));
    }
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Base58 for {}: {}", label, e)))?;
    parse_canonical_scalar(&bytes, label)
}

/// SECURITY (HMSEC-SA04-09): Structural validation of the PUBLIC SST shard
/// pair embedded in a transaction against the generation contract of
/// [`generate_sst_trap`]: both shards must be Base58-decodable, exactly
/// 32 bytes long, and cryptographically well-formed - `trap_r` must
/// decompress to a curve25519 Edwards point, `trap_s` must be a canonical
/// (fully reduced) scalar encoding.
///
/// The chain validator enforces this on every non-init transaction. This checks
/// encodings and subgroups; historical shard correctness still requires a
/// private witness or collision analysis. The genesis placeholder pair
/// ("none"/"none") fails the length/decoding gates
/// by design - placeholder shards are reserved for init fingerprints and
/// must never appear inside a spend transaction.
pub(crate) fn validate_shard_structure(trap_r: &str, trap_s: &str) -> Result<(), VoucherCoreError> {
    // DoS guard: 32-byte payloads are ~44 Base58 chars; anything > 64 is
    // attacker-bloated and is rejected before allocation-heavy decoding.
    if trap_r.len() > 64 || trap_s.len() > 64 {
        return Err(VoucherCoreError::Crypto(
            "Shard string exceeds maximum Base58 length (64)".to_string(),
        ));
    }
    parse_point_bs58(trap_r, "trap_r")?;
    parse_scalar_bs58(trap_s, "trap_s")?;
    Ok(())
}

/// Little-endian encoding of the base field prime p = 2^255 - 19.
const FIELD_MODULUS_LE: [u8; 32] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// SECURITY: Rejects non-canonical compressed Edwards encodings whose masked
/// y coordinate is >= p. `CompressedEdwardsY::decompress()` implicitly
/// reduces such encodings modulo p and may therefore accept them, which
/// would leave shard malleability open (two encodings for one point).
/// Mirrors the strict canonical scalar policy of [`parse_canonical_scalar`].
fn ensure_canonical_y(encoded: &[u8; 32]) -> Result<(), VoucherCoreError> {
    let mut y = *encoded;
    y[31] &= 0x7f; // clear the x-coordinate sign bit
    for i in (0..32).rev() {
        match y[i].cmp(&FIELD_MODULUS_LE[i]) {
            std::cmp::Ordering::Less => return Ok(()),
            std::cmp::Ordering::Greater => break,
            std::cmp::Ordering::Equal => continue,
        }
    }
    Err(VoucherCoreError::Crypto(
        "Non-canonical Edwards point encoding for trap_r rejected".to_string(),
    ))
}

//==============================================================================
// TRAP GENERATION & L1 WITNESS VERIFICATION
//==============================================================================

pub use crate::models::voucher::TrapWitness;

/// Creates a compact public shard and the private handover witness.
///
/// The Schnorr nonce r = H(domain, x, mu) stays secret even from the recipient.
/// Mask parameters derive from the base signature (R_sig, s_sig) and mu.
/// The DLEQ proof binds the auxiliary VRF point to the same permanent identity;
/// it does not prove deterministic Schnorr nonce selection by a malicious signer.
/// Such equivocation is attributable through victim witness disclosure.
///
/// input_seed must open E to the signing identity. guard_hash is the exact
/// commitment authenticated by the transaction/fingerprint signature. Creation
/// first builds the private witness, then uses shard_from_witness once the
/// encrypted guard is available, avoiding a guard/shard hash cycle.
pub fn generate_sst_trap(
    sk: &ed25519_dalek::SigningKey,
    ds_tag: &str,
    eph_pub: &[u8; 32],
    t_id: &str,
    guard_hash: &str,
    input_seed: &[u8; 32],
) -> Result<(TrapData, TrapWitness), VoucherCoreError> {
    let did = crate::services::crypto::create_user_id(&sk.verifying_key(), None)?;
    verify_input_owner(&did, &bs58::encode(input_seed).into_string(), eph_pub)?;
    let x = get_secret_scalar(sk);
    let payer_point = ed25519_pk_to_curve_point(&sk.verifying_key())?;

    // 1. Message binding
    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    // 2. VRF base point and K_trap
    let h_mu = hash_to_curve(&sst_encoded_parts(SST_DOMAIN_VRF_BASE, &[mu.as_slice()]));
    let k_trap = x * h_mu;

    // 3. Chaum-Pedersen DLEQ proof (log_G(payer_point) == log_{H_mu}(K_trap))
    let k = sst_scalar(SST_DOMAIN_DLEQ_NONCE, &[x.as_bytes(), mu.as_slice()]);
    let a_point = k * ED25519_BASEPOINT_POINT;
    let b_point = k * h_mu;
    let dleq_c = sst_scalar(
        SST_DOMAIN_DLEQ_CHAL,
        &[
            mu.as_slice(),
            payer_point.compress().as_bytes(),
            h_mu.compress().as_bytes(),
            k_trap.compress().as_bytes(),
            a_point.compress().as_bytes(),
            b_point.compress().as_bytes(),
        ],
    );
    let dleq_s = k + dleq_c * x;

    // 4. Secret Schnorr nonce and self-verifying signature-derived masks
    let r = sst_scalar(SST_DOMAIN_NONCE, &[x.as_bytes(), mu.as_slice()]);
    let r_sig_point = r * ED25519_BASEPOINT_POINT;
    let c = sst_challenge(&mu, &r_sig_point);
    let s_sig = r + c * x;

    let (m_r_point, m_s) = mask_parameters(&r_sig_point, &s_sig, &mu);

    // 5. Spend-specific evaluation point & shards
    let tau = compute_tau(ds_tag, t_id, guard_hash);
    let r_i = r_sig_point + tau * m_r_point;
    let s_i = s_sig + tau * m_s;

    let trap_data = TrapData {
        ds_tag: ds_tag.to_string(),
        trap_r: bs58::encode(r_i.compress().as_bytes()).into_string(),
        trap_s: bs58::encode(s_i.as_bytes()).into_string(),
    };

    let witness = TrapWitness {
        input_seed: bs58::encode(input_seed).into_string(),
        r_sig: bs58::encode(r_sig_point.compress().as_bytes()).into_string(),
        s_sig: bs58::encode(s_sig.as_bytes()).into_string(),
        m_r: bs58::encode(m_r_point.compress().as_bytes()).into_string(),
        m_s: bs58::encode(m_s.as_bytes()).into_string(),
        k_trap: bs58::encode(k_trap.compress().as_bytes()).into_string(),
        dleq_c: bs58::encode(dleq_c.as_bytes()).into_string(),
        dleq_s: bs58::encode(dleq_s.as_bytes()).into_string(),
    };

    Ok((trap_data, witness))
}

/// Checks the input ownership opening, identity signature, DLEQ proof,
/// signature-derived masks, and both shares for the authenticated evaluation.
/// Invalid handover witnesses fail closed without exposing historical senders.
pub fn verify_sst_witness(
    witness: &TrapWitness,
    trap_shard: &TrapData,
    payer_did: &str,
    ds_tag: &str,
    eph_pub: &[u8; 32],
    t_id: &str,
    guard_hash: &str,
) -> Result<(), VoucherCoreError> {
    if trap_shard.ds_tag != ds_tag {
        return Err(VoucherCoreError::Crypto(
            "SST witness check failed: ds_tag mismatch".to_string(),
        ));
    }

    verify_input_owner(payer_did, &witness.input_seed, eph_pub)?;

    // Parse witness components (strictly canonical response scalars).
    let r_sig_point = parse_point_bs58(&witness.r_sig, "R_sig")?;
    let s_sig = parse_scalar_bs58(&witness.s_sig, "s_sig")?;
    let m_r_point = parse_point_bs58(&witness.m_r, "M_R")?;
    let m_s = parse_scalar_bs58(&witness.m_s, "m_s")?;

    let k_trap_point = parse_point_bs58(&witness.k_trap, "k_trap")?;
    let dleq_c = parse_scalar_bs58(&witness.dleq_c, "dleq_c")?;
    let dleq_s = parse_scalar_bs58(&witness.dleq_s, "dleq_s")?;

    if !k_trap_point.is_torsion_free() || k_trap_point.is_identity() {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: k_trap is not torsion-free or is identity".to_string(),
        ));
    }
    if !m_r_point.is_torsion_free() {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: point is not torsion-free".to_string(),
        ));
    }
    if !r_sig_point.is_torsion_free() {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: point is not torsion-free".to_string(),
        ));
    }

    // Resolve the payer's public identity point.
    let payer_pk = get_pubkey_from_user_id(payer_did)?;
    let payer_point = ed25519_pk_to_curve_point(&payer_pk)?;

    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    // 1. One-stage Schnorr signature verification against the payer identity.
    let c = sst_challenge(&mu, &r_sig_point);
    if c == Scalar::ZERO || s_sig * ED25519_BASEPOINT_POINT != r_sig_point + c * payer_point {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: signature does not verify against payer DID".to_string(),
        ));
    }

    // 2. Chaum-Pedersen DLEQ proof verification:
    // log_G(payer_point) == log_{H_mu}(k_trap_point)
    let h_mu = hash_to_curve(&sst_encoded_parts(SST_DOMAIN_VRF_BASE, &[mu.as_slice()]));
    let a_prime = dleq_s * ED25519_BASEPOINT_POINT - dleq_c * payer_point;
    let b_prime = dleq_s * h_mu - dleq_c * k_trap_point;
    let c_expected = sst_scalar(
        SST_DOMAIN_DLEQ_CHAL,
        &[
            mu.as_slice(),
            payer_point.compress().as_bytes(),
            h_mu.compress().as_bytes(),
            k_trap_point.compress().as_bytes(),
            a_prime.compress().as_bytes(),
            b_prime.compress().as_bytes(),
        ],
    );
    if dleq_c != c_expected {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: invalid DLEQ proof for K_trap".to_string(),
        ));
    }

    // The masks are self-verifying from the base signature. Its nonce stays
    // secret: deriving it from disclosed K_trap would expose the permanent key.
    let (expected_m_r, expected_m_s) = mask_parameters(&r_sig_point, &s_sig, &mu);
    if m_r_point != expected_m_r || m_s != expected_m_s {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: non-deterministic signature masks".into(),
        ));
    }

    // 4. Shard consistency for THIS spend.
    let tau = compute_tau(ds_tag, t_id, guard_hash);
    let expected_r = r_sig_point + tau * m_r_point;
    let expected_s = s_sig + tau * m_s;

    if trap_shard.trap_r != bs58::encode(expected_r.compress().as_bytes()).into_string()
        || trap_shard.trap_s != bs58::encode(expected_s.as_bytes()).into_string()
    {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: trap shard does not match witness".to_string(),
        ));
    }

    Ok(())
}

//==============================================================================
// COLLISION ANALYSIS (AUTONOMOUS GOSSIP DEANONYMIZATION)
//==============================================================================

/// A parsed, validated trap shard ready for linear reconstruction.
#[derive(Debug, Clone, Copy)]
struct ParsedShard {
    tau: Scalar,
    r: EdwardsPoint,
    s: Scalar,
}

/// Parses a Base58 shard pair into validated cryptographic components.
fn parse_shard(trap_r: &str, trap_s: &str, tau: Scalar) -> Result<ParsedShard, VoucherCoreError> {
    let r = parse_point_bs58(trap_r, "trap_r")?;
    let s = parse_scalar_bs58(trap_s, "trap_s")?;
    Ok(ParsedShard { tau, r, s })
}

/// Linear polynomial reconstruction from two colliding shards.
///
/// Returns the reconstructed masking values $(\hat{M}_R, \hat{m}_s)$, the
/// underlying signature $(\hat{R}, \hat{s})$ and the extracted identity
/// point $\hat{X}$.
///
/// # Guards (degenerate-case firewall)
/// - $\tau_1 \neq \tau_2$ (division-by-zero protection),
/// - $(R_1, s_1) \neq (R_2, s_2)$ (no fork information),
/// - canonical scalar encodings (malleability),
/// - decompressable points,
/// - $c \neq 0$ and $\hat{X} \neq \mathcal{O}$,
/// - $\hat{M}_R$ and $\hat{X}$ torsion-free (prime-order subgroup; rejects
///   off-line fabricated junk lines, HMC-SEC-02-08).
fn reconstruct_identity(
    mu: &[u8; 32],
    sh1: &ParsedShard,
    sh2: &ParsedShard,
) -> Result<(EdwardsPoint, Scalar, EdwardsPoint, Scalar, EdwardsPoint), VoucherCoreError> {
    // Guard: identical evaluation points carry no fork information.
    if sh1.tau == sh2.tau {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: identical tau values (no fork detected)".to_string(),
        ));
    }

    // Guard: fully identical shards are degenerate (replay, not a fork).
    if sh1.r == sh2.r && sh1.s == sh2.s {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: identical trap shards".to_string(),
        ));
    }

    let delta_tau_inv = (sh1.tau - sh2.tau).invert();

    // Polynomial reconstruction of the masking values:
    // M_R = (R1 - R2) * (tau1 - tau2)^-1 ; m_s = (s1 - s2) * (tau1 - tau2)^-1
    let m_hat_r = (sh1.r - sh2.r) * delta_tau_inv;
    let m_hat_s = (sh1.s - sh2.s) * delta_tau_inv;

    // Guard (HMC-SEC-02-08): honest masking points ALWAYS live in the
    // prime-order subgroup (`hash_to_curve` output is torsion-free), so a
    // reconstructed point carrying a cofactor component proves an off-line
    // fabricated junk line. Reject before it can be promoted to a did:key
    // attribution by the conflict handler.
    if !m_hat_r.is_torsion_free() {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: reconstructed masking point is not torsion-free \
             (off-line fabricated shard line)"
                .to_string(),
        ));
    }

    // Reconstruction of the underlying Schnorr signature.
    let r_hat = sh1.r - sh1.tau * m_hat_r;
    let s_hat = sh1.s - sh1.tau * m_hat_s;

    let (expected_m_r, expected_m_s) = mask_parameters(&r_hat, &s_hat, mu);
    if m_hat_r != expected_m_r || m_hat_s != expected_m_s {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: reconstructed signature masks do not match".into(),
        ));
    }

    // Identity extraction: X = (s*G - R) * c^-1.
    let c = sst_challenge(mu, &r_hat);
    if c == Scalar::ZERO {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: zero challenge (degenerate signature)".to_string(),
        ));
    }
    let x_hat = (s_hat * ED25519_BASEPOINT_POINT - r_hat) * c.invert();

    // Guard: the identity of a real actor is never the neutral element.
    if x_hat.is_identity() {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: extracted identity point is the neutral element".to_string(),
        ));
    }

    // Guard (HMC-SEC-02-08): genuine Ed25519 identity keys are clamped
    // scalars times the basepoint and therefore torsion-free. Accepting a
    // torsion-carrying extracted point would let junk shard pairs circulate
    // as parseable (definitive) offender identities.
    if !x_hat.is_torsion_free() {
        return Err(VoucherCoreError::Crypto(
            "SST collision rejected: extracted identity point is not torsion-free \
             (no valid Ed25519 actor key)"
                .to_string(),
        ));
    }

    Ok((m_hat_r, m_hat_s, r_hat, s_hat, x_hat))
}

/// Reconstructs a candidate signature identity from two self-verifying shards.
/// Equal IDs are supported when their authenticated guard hashes differ.
///
/// This algebraic check alone does not prove that the identity owns E. Callers
/// publishing a definitive offender DID must verify a victim ownership receipt
/// and the signatures of the two conflicting spends. Junk pairs fail closed.
pub fn extract_sst_identity(
    ds_tag: &str,
    eph_pub: &[u8; 32],
    fp1: &TransactionFingerprint,
    fp2: &TransactionFingerprint,
) -> Result<EdwardsPoint, VoucherCoreError> {
    if fp1.ds_tag != ds_tag || fp2.ds_tag != ds_tag {
        return Err(VoucherCoreError::Crypto(
            "SST extraction failed: fingerprints do not share the collision ds_tag".to_string(),
        ));
    }

    let expected_eph = bs58::encode(eph_pub).into_string();
    if (!fp1.sender_ephemeral_pub.is_empty() || !fp2.sender_ephemeral_pub.is_empty())
        && (fp1.sender_ephemeral_pub != expected_eph || fp2.sender_ephemeral_pub != expected_eph)
    {
        return Err(VoucherCoreError::Crypto(
            "SST extraction failed: fingerprint sender_ephemeral_pub mismatch".to_string(),
        ));
    }

    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    let sh1 = parse_shard(
        &fp1.trap_r,
        &fp1.trap_s,
        compute_tau(ds_tag, &fp1.t_id, &fp1.privacy_guard_hash),
    )?;
    let sh2 = parse_shard(
        &fp2.trap_r,
        &fp2.trap_s,
        compute_tau(ds_tag, &fp2.t_id, &fp2.privacy_guard_hash),
    )?;

    let (_, _, _, _, x_hat) = reconstruct_identity(&mu, &sh1, &sh2)?;
    Ok(x_hat)
}

/// Verifies that a set of colliding shards is internally consistent AND
/// extracts to exactly `expected_id`.
///
/// Reconstruction is performed from the first two shards; every additional
/// shard ($n \ge 3$) must lie on the reconstructed line:
/// $R_j \stackrel{?}{=} \hat{R} + \tau_j \cdot \hat{M}_R$,\;
/// $s_j \stackrel{?}{=} \hat{s} + \tau_j \cdot \hat{m}_s$.
///
/// This checks a signature candidate. Definitive attribution additionally
/// requires authenticated spend signatures and an input ownership opening.
pub fn verify_sst_shards_consistency(
    shards: &[&TransactionFingerprint],
    expected_id: &EdwardsPoint,
    ds_tag: &str,
    eph_pub: &[u8; 32],
) -> Result<(), VoucherCoreError> {
    if shards.len() < 2 {
        return Err(VoucherCoreError::Crypto(
            "SST consistency check requires at least two colliding shards".to_string(),
        ));
    }

    let expected_eph = bs58::encode(eph_pub).into_string();
    let has_any_eph = shards.iter().any(|fp| !fp.sender_ephemeral_pub.is_empty());
    if has_any_eph {
        for fp in shards {
            if fp.sender_ephemeral_pub != expected_eph {
                return Err(VoucherCoreError::Crypto(
                    "SST consistency check: shard sender_ephemeral_pub mismatch".to_string(),
                ));
            }
        }
    }

    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    let parsed: Vec<ParsedShard> = shards
        .iter()
        .map(|fp| {
            if fp.ds_tag != ds_tag {
                return Err(VoucherCoreError::Crypto(
                    "SST consistency check: shard carries foreign ds_tag".to_string(),
                ));
            }
            parse_shard(
                &fp.trap_r,
                &fp.trap_s,
                compute_tau(ds_tag, &fp.t_id, &fp.privacy_guard_hash),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (m_hat_r, m_hat_s, r_hat, s_hat, x_hat) =
        reconstruct_identity(&mu, &parsed[0], &parsed[1])?;

    if x_hat != *expected_id {
        return Err(VoucherCoreError::Crypto(
            "SST consistency check: extracted identity does not match the claimed offender"
                .to_string(),
        ));
    }

    // Sanity: the reconstructed signature verifies against the claimed id
    // (holds by construction after the equality above; cheap belt-and-braces).
    let c = sst_challenge(&mu, &r_hat);
    if s_hat * ED25519_BASEPOINT_POINT != r_hat + c * x_hat {
        return Err(VoucherCoreError::Crypto(
            "SST consistency check: reconstructed signature does not verify".to_string(),
        ));
    }

    // Firewall for n >= 3: every further shard must lie on the same line.
    for sh in &parsed[2..] {
        let expected_r = r_hat + sh.tau * m_hat_r;
        let expected_s = s_hat + sh.tau * m_hat_s;
        if sh.r != expected_r || sh.s != expected_s {
            return Err(VoucherCoreError::Crypto(
                "SST consistency check: inconsistent extra shard detected".to_string(),
            ));
        }
    }

    Ok(())
}

/// Checks whether any stored pair has a self-verifying base signature for the
/// claimed candidate identity. Extra junk does not veto a valid pair. This
/// primitive does not authenticate spend signatures or an E-to-DID binding;
/// definitive proof import uses verify_victim_witness_disclosure instead.
pub fn verify_stored_trap_shards_against_identity(
    transactions: &[Transaction],
    claimed_id_point: &EdwardsPoint,
) -> Result<(), VoucherCoreError> {
    let mut shards: Vec<TransactionFingerprint> = Vec::new();
    let mut context: Option<(String, [u8; 32])> = None;

    for tx in transactions {
        let Some(trap) = &tx.trap_data else {
            continue; // structural skip (synthetic placeholders etc.)
        };
        let eph_str = tx.sender_ephemeral_pub.as_deref().ok_or_else(|| {
            VoucherCoreError::Crypto(
                "SST attribution: conflicting transaction lacks sender_ephemeral_pub".to_string(),
            )
        })?;
        let eph_bytes: [u8; 32] =
            crate::services::crypto::decode_bs58_fixed::<32>(eph_str, "eph_pub")
                .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

        // All shards of one collision share the same context.
        match context {
            None => context = Some((trap.ds_tag.clone(), eph_bytes)),
            Some((ref ds_tag, ref ctx_eph)) => {
                if *ds_tag != trap.ds_tag || *ctx_eph != eph_bytes {
                    return Err(VoucherCoreError::Crypto(
                        "SST attribution: conflicting transactions disagree on collision context"
                            .to_string(),
                    ));
                }
            }
        }

        shards.push(TransactionFingerprint {
            ds_tag: trap.ds_tag.clone(),
            t_id: tx.t_id.clone(),
            trap_r: trap.trap_r.clone(),
            trap_s: trap.trap_s.clone(),
            privacy_guard_hash: crate::services::l2_gateway::privacy_guard_commitment(
                tx.privacy_guard.as_deref(),
            ),
            ..Default::default()
        });
    }

    let Some((ds_tag, eph_bytes)) = context else {
        return Err(VoucherCoreError::Crypto(
            "SST attribution: no trap shards present".to_string(),
        ));
    };

    if shards.len() < 2 {
        return Err(VoucherCoreError::Crypto(
            "SST attribution: requires at least two colliding shards".to_string(),
        ));
    }

    // AUDIT-01-F13: evaluate every colliding PAIR; one consistent pair under
    // the claimed identity is sufficient attribution evidence.
    let refs: Vec<&TransactionFingerprint> = shards.iter().collect();
    let mut last_err: Option<VoucherCoreError> = None;
    for i in 0..refs.len() {
        for j in (i + 1)..refs.len() {
            match verify_sst_shards_consistency(
                &[refs[i], refs[j]],
                claimed_id_point,
                &ds_tag,
                &eph_bytes,
            ) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        VoucherCoreError::Crypto("SST attribution: no shard pair evaluated".to_string())
    }))
}

/// Recomputable after interpolation; prevents steered junk-shard attribution.
fn mask_parameters(r: &EdwardsPoint, s: &Scalar, mu: &[u8; 32]) -> (EdwardsPoint, Scalar) {
    let compressed = r.compress();
    let parts: &[&[u8]] = &[compressed.as_bytes(), s.as_bytes(), mu];
    (
        hash_to_curve(&sst_encoded_parts(SST_DOMAIN_MASK_R, parts)),
        sst_scalar(SST_DOMAIN_MASK_S, parts),
    )
}

/// Publicly proves that a declared DID owns the spent output without revealing
/// its secret key. The opening is published only together with signed conflicts.
pub fn verify_input_owner(
    payer_did: &str,
    input_seed: &str,
    eph_pub: &[u8; 32],
) -> Result<(), VoucherCoreError> {
    let pk = get_pubkey_from_user_id(payer_did)?;
    let seed = crate::services::crypto::decode_bs58_fixed::<32>(input_seed, "input_seed")?;
    if crate::services::crypto::derive_stealth_ephemeral_point(&pk, &seed)?
        .compress()
        .to_bytes()
        != *eph_pub
    {
        return Err(VoucherCoreError::Crypto(
            "Spent output is not derived from the declared owner identity".into(),
        ));
    }
    Ok(())
}

/// Re-evaluates an already generated witness after the guard hash is known.
pub fn shard_from_witness(
    witness: &TrapWitness,
    identity: &EdwardsPoint,
    ds_tag: &str,
    eph_pub: &[u8; 32],
    t_id: &str,
    guard_hash: &str,
) -> Result<TrapData, VoucherCoreError> {
    let r = parse_point_bs58(&witness.r_sig, "R_sig")?;
    let s = parse_scalar_bs58(&witness.s_sig, "s_sig")?;
    let (m_r, m_s) = mask_parameters(&r, &s, &compute_trap_message_mu(ds_tag, eph_pub));
    let tau = compute_tau(ds_tag, t_id, guard_hash);
    let trap = TrapData {
        ds_tag: ds_tag.into(),
        trap_r: bs58::encode((r + tau * m_r).compress().as_bytes()).into_string(),
        trap_s: bs58::encode((s + tau * m_s).as_bytes()).into_string(),
    };
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&identity.compress().to_bytes())
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    let did = crate::services::crypto::create_user_id(&pk, None)?;
    verify_sst_witness(witness, &trap, &did, ds_tag, eph_pub, t_id, guard_hash)?;
    Ok(trap)
}

/// Verifies a candidate signature identity from signed gossip. Definitive
/// attribution additionally needs an authenticated input ownership opening.
pub fn verify_fingerprint_shards_against_identity(
    fingerprints: &[TransactionFingerprint],
    claimed: &EdwardsPoint,
) -> Result<(), VoucherCoreError> {
    for i in 0..fingerprints.len() {
        for j in i + 1..fingerprints.len() {
            let a = &fingerprints[i];
            let b = &fingerprints[j];
            if !crate::services::conflict_manager::verify_fingerprint_signature(a)
                || !crate::services::conflict_manager::verify_fingerprint_signature(b)
            {
                continue;
            }
            let Ok(eph) = crate::services::crypto::decode_bs58_fixed::<32>(
                &a.sender_ephemeral_pub,
                "sender_ephemeral_pub",
            ) else {
                continue;
            };
            if extract_sst_identity(&a.ds_tag, &eph, a, b).is_ok_and(|x| x == *claimed) {
                return Ok(());
            }
        }
    }
    Err(VoucherCoreError::Crypto(
        "No authenticated fingerprint pair proves the candidate identity".into(),
    ))
}

/// True only for distinct authenticated spend contents for the same input.
/// Signature re-randomization and retention changes alone are replays.
pub fn fingerprints_conflict(a: &TransactionFingerprint, b: &TransactionFingerprint) -> bool {
    !a.sender_ephemeral_pub.is_empty()
        && a.ds_tag == b.ds_tag
        && a.sender_ephemeral_pub == b.sender_ephemeral_pub
        && (a.t_id != b.t_id
            || a.privacy_guard_hash != b.privacy_guard_hash
            || a.trap_r != b.trap_r
            || a.trap_s != b.trap_s
            || a.encrypted_timestamp != b.encrypted_timestamp
            || a.created_at_ms != b.created_at_ms
            || a.layer2_voucher_id != b.layer2_voucher_id)
}

/// Verifies a victim's private receipt against one honest handover AND a
/// second E-signed spend. The second shard may be arbitrary junk. Verification
/// is ordered so no ownership claim is accepted without authenticated fraud.
pub fn verify_victim_witness_disclosure(
    disclosure: &crate::models::conflict::VictimWitnessDisclosure,
    fingerprints: &[TransactionFingerprint],
) -> Result<EdwardsPoint, VoucherCoreError> {
    let honest = fingerprints
        .get(disclosure.fingerprint_index)
        .ok_or_else(|| {
            VoucherCoreError::ProofImport("Victim witness points outside the evidence set".into())
        })?;
    if !crate::services::conflict_manager::verify_fingerprint_signature(honest)
        || !fingerprints.iter().any(|other| {
            fingerprints_conflict(honest, other)
                && crate::services::conflict_manager::verify_fingerprint_signature(other)
        })
    {
        return Err(VoucherCoreError::ProofImport(
            "Victim disclosure requires two authenticated conflicting spends".into(),
        ));
    }
    let eph = crate::services::crypto::decode_bs58_fixed::<32>(
        &honest.sender_ephemeral_pub,
        "sender_ephemeral_pub",
    )?;
    let trap = TrapData {
        ds_tag: honest.ds_tag.clone(),
        trap_r: honest.trap_r.clone(),
        trap_s: honest.trap_s.clone(),
    };
    verify_sst_witness(
        &disclosure.witness,
        &trap,
        &disclosure.sender_permanent_did,
        &honest.ds_tag,
        &eph,
        &honest.t_id,
        &honest.privacy_guard_hash,
    )?;
    ed25519_pk_to_curve_point(&get_pubkey_from_user_id(&disclosure.sender_permanent_did)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn signed_fingerprint(
        trap: &TrapData,
        key: &crate::services::crypto::EphemeralKey,
        id: &str,
        guard: &str,
    ) -> TransactionFingerprint {
        let eph = key.verifying_key().to_bytes();
        let id_bytes = crate::services::crypto::decode_bs58_fixed::<32>(id, "t_id").unwrap();
        let digest = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
            "none",
            &trap.ds_tag,
            &id_bytes,
            &eph,
            &trap.trap_r,
            &trap.trap_s,
            0,
            0,
            None,
            guard,
        );
        TransactionFingerprint {
            ds_tag: trap.ds_tag.clone(),
            t_id: id.into(),
            trap_r: trap.trap_r.clone(),
            trap_s: trap.trap_s.clone(),
            privacy_guard_hash: guard.into(),
            sender_ephemeral_pub: bs58::encode(eph).into_string(),
            layer2_voucher_id: "none".into(),
            layer2_signature: bs58::encode(key.sign(&digest).to_bytes()).into_string(),
            ..Default::default()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn collision_and_victim_disclosure_invariants(secret in any::<[u8; 32]>(), seed in any::<[u8; 32]>(), same_id in any::<bool>()) {
            let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
            let input = crate::services::crypto::derive_owned_ephemeral_key(&sk, &seed).unwrap();
            let eph = input.verifying_key().to_bytes();
            let did = crate::services::crypto::create_user_id(&sk.verifying_key(), None).unwrap();
            let tag = crate::services::crypto::get_hash(b"input");
            let a_id = crate::services::crypto::get_hash(b"a");
            let b_id = if same_id { a_id.clone() } else { crate::services::crypto::get_hash(b"b") };
            let (a, witness) = generate_sst_trap(&sk, &tag, &eph, &a_id, "guard A", &seed).unwrap();
            let (b, _) = generate_sst_trap(&sk, &tag, &eph, &b_id, "guard B", &seed).unwrap();
            verify_sst_witness(&witness, &a, &did, &tag, &eph, &a_id, "guard A").unwrap();
            prop_assert!(verify_sst_witness(&witness, &a, &did, &tag, &eph, &a_id, "wrong").is_err());
            let fa = signed_fingerprint(&a, &input, &a_id, "guard A");
            let fb = signed_fingerprint(&b, &input, &b_id, "guard B");
            let expected = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
            prop_assert_eq!(extract_sst_identity(&tag, &eph, &fa, &fb).unwrap(), expected);
            let disclosure = crate::models::conflict::VictimWitnessDisclosure { fingerprint_index: 0,
                sender_permanent_did: did, witness };
            prop_assert_eq!(verify_victim_witness_disclosure(&disclosure, &[fa.clone(), fb.clone()]).unwrap(), expected);
            prop_assert!(verify_victim_witness_disclosure(&disclosure, &[fa.clone(), fa.clone()]).is_err());
            let mut junk = b.clone();
            junk.trap_r = bs58::encode(ED25519_BASEPOINT_POINT.compress().as_bytes()).into_string();
            let signed_junk = signed_fingerprint(&junk, &input, &b_id, "guard B");
            prop_assert!(extract_sst_identity(&tag, &eph, &fa, &signed_junk).is_err());
            prop_assert_eq!(verify_victim_witness_disclosure(&disclosure, &[fa.clone(), signed_junk.clone()]).unwrap(), expected);
            let mut forged = signed_junk;
            forged.layer2_signature = fa.layer2_signature.clone();
            prop_assert!(verify_victim_witness_disclosure(&disclosure, &[fa.clone(), forged]).is_err());
            let mut bad_opening = disclosure;
            bad_opening.witness.input_seed = bs58::encode([0xff; 32]).into_string();
            prop_assert!(verify_victim_witness_disclosure(&bad_opening, &[fa, fb]).is_err());
            prop_assert_eq!(bs58::decode(&a.trap_r).into_vec().unwrap().len() + bs58::decode(&a.trap_s).into_vec().unwrap().len(), 64);
        }
    }

    #[test]
    fn private_witness_cannot_reveal_the_permanent_key_via_its_nonce() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let seed = [12; 32];
        let eph = crate::services::crypto::derive_owned_ephemeral_key(&sk, &seed)
            .unwrap()
            .verifying_key()
            .to_bytes();
        let (_, witness) = generate_sst_trap(&sk, "input", &eph, "a", "", &seed).unwrap();
        let k = parse_point_bs58(&witness.k_trap, "K_trap").unwrap();
        let mu = compute_trap_message_mu("input", &eph);
        let public_nonce = sst_scalar(SST_DOMAIN_NONCE, &[k.compress().as_bytes(), &mu]);
        let r = parse_point_bs58(&witness.r_sig, "R_sig").unwrap();
        let s = parse_scalar_bs58(&witness.s_sig, "s_sig").unwrap();
        let recovered = (s - public_nonce) * compute_sst_challenge(&mu, &r).invert();
        assert_ne!(recovered, get_secret_scalar(&sk));
    }

    #[test]
    fn non_deterministic_signer_nonce_cannot_evade_victim_disclosure() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let input = crate::services::crypto::derive_owned_ephemeral_key(&sk, &[22; 32]).unwrap();
        let eph = input.verifying_key().to_bytes();
        let did = crate::services::crypto::create_user_id(&sk.verifying_key(), None).unwrap();
        let tag = crate::services::crypto::get_hash(b"input");
        let a_id = crate::services::crypto::get_hash(b"a");
        let b_id = crate::services::crypto::get_hash(b"b");
        let (a, witness) = generate_sst_trap(&sk, &tag, &eph, &a_id, "", &[22; 32]).unwrap();
        let mut altered = witness.clone();
        let nonce = Scalar::from(12345u64);
        let r = nonce * ED25519_BASEPOINT_POINT;
        let s = nonce
            + sst_challenge(&compute_trap_message_mu(&tag, &eph), &r) * get_secret_scalar(&sk);
        let (m_r, m_s) = mask_parameters(&r, &s, &compute_trap_message_mu(&tag, &eph));
        altered.r_sig = bs58::encode(r.compress().as_bytes()).into_string();
        altered.s_sig = bs58::encode(s.as_bytes()).into_string();
        altered.m_r = bs58::encode(m_r.compress().as_bytes()).into_string();
        altered.m_s = bs58::encode(m_s.as_bytes()).into_string();
        let x = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
        let b = shard_from_witness(&altered, &x, &tag, &eph, &b_id, "").unwrap();
        let fps = [
            signed_fingerprint(&a, &input, &a_id, ""),
            signed_fingerprint(&b, &input, &b_id, ""),
        ];
        assert!(extract_sst_identity(&tag, &eph, &fps[0], &fps[1]).is_err());
        let disclosure = crate::models::conflict::VictimWitnessDisclosure {
            fingerprint_index: 0,
            sender_permanent_did: did,
            witness,
        };
        assert_eq!(
            verify_victim_witness_disclosure(&disclosure, &fps).unwrap(),
            x
        );
    }

    #[test]
    fn point_and_scalar_parsers_share_strict_canonical_subgroup_policy() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        for torsion in EIGHT_TORSION.iter().skip(1) {
            let point = bs58::encode(torsion.compress().as_bytes()).into_string();
            assert!(parse_point_bs58(&point, "test").is_err());
            assert!(
                validate_shard_structure(
                    &point,
                    &bs58::encode(Scalar::ONE.as_bytes()).into_string()
                )
                .is_err()
            );
        }
        let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(
            parse_point_bs58(
                &bs58::encode(mixed.compress().as_bytes()).into_string(),
                "mixed"
            )
            .is_err()
        );
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        assert!(
            parse_point_bs58(&bs58::encode(noncanonical).into_string(), "noncanonical").is_err()
        );
        let mut negative_zero = EdwardsPoint::default().compress().to_bytes();
        negative_zero[31] |= 0x80;
        assert!(
            parse_point_bs58(&bs58::encode(negative_zero).into_string(), "negative zero").is_err()
        );
        assert!(parse_canonical_scalar(&[0xff; 32], "test").is_err());
    }
}
