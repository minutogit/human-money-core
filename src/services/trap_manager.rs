//! # src/services/trap_manager.rs
//!
//! Implements the cryptographic engine of the **Shared-Signature Trap (SST)**
//! — the V3 identity-trap protocol (`HMC_TX_AUTH_V3`) of human_money_core.
//!
//! # Concepts (V3 / SST)
//! - **Shared Schnorr signature:** every spend publishes a *shard*
//!   $(R_i, s_i)$ of one deterministic Schnorr signature
//!   $\sigma = (R_{sig}, s_{sig})$ over the spend input message $\mu$:
//!   $$R_i = R_{sig} + \tau_i \cdot M_R \qquad s_i = s_{sig} + \tau_i \cdot m_s$$
//! - **Information-theoretic anonymity:** a single shard hides the signer
//!   behind four unknowns ($R_{sig}, s_{sig}, M_R, m_s$); no registry mining
//!   ("P-pre") can link it to an identity.
//! - **Autonomous deanonymization:** two colliding shards (same `ds_tag`)
//!   linearly reconstruct $(\hat{R}, \hat{s})$; the challenge $c$ binds them to
//!   exactly one public key $\hat{X}$. Extracting any identity other than the
//!   true signer's key would constitute an EUF-CMA forgery against
//!   Schnorr/Ed25519 — framing innocent third parties is computationally
//!   infeasible (remediation AUDIT-01-F07).
//! - **L1 fraud prevention (R5):** the private witness
//!   $W = (R_{sig}, s_{sig}, M_R, m_s)$ travels in the encrypted
//!   `RecipientPayload`, letting the recipient verify the trap at handover and
//!   reject garbage/forged traps immediately.
//!
//! # Message binding ($\mu$)
//! $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \parallel ds\_tag \parallel E)$ where
//! `E` is the revealed ephemeral key of the spender.
//!
//! The raw fork point `prev_hash` is deliberately NOT mixed into $\mu$: it is
//! already cryptographically committed via
//! `ds_tag = H(prev_hash \parallel E)` (second-preimage resistance), and —
//! crucially — `prev_hash` is NOT part of a gossip fingerprint. Deriving
//! $\mu$ from fingerprint data alone (`ds_tag`, `E`) is what enables ANY
//! gossip recipient to perform the autonomous, single-round identity
//! extraction without requesting heavy transaction chains.

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
// DOMAIN SEPARATION TAGS (V3 / SST)
//==============================================================================

/// Domain tag binding the trap message $\mu$ to the spend input.
pub const SST_DOMAIN_SIG_MSG: &[u8] = b"HMC_TRAP_SIG_V1";
/// Domain tag for the deterministic Schnorr nonce derivation.
pub const SST_DOMAIN_NONCE: &[u8] = b"HMC_TRAP_NONCE_V1";
/// Domain tag for the Schnorr challenge hash.
pub const SST_DOMAIN_CHALLENGE: &[u8] = b"HMC_TRAP_CHAL_V1";
/// Domain tag for the masking point $M_R$ derivation.
pub const SST_DOMAIN_MASK_R: &[u8] = b"HMC_MASK_R_V1";
/// Domain tag for the masking scalar $m_s$ derivation.
pub const SST_DOMAIN_MASK_S: &[u8] = b"HMC_MASK_S_V1";
/// Domain tag for the spend-specific shard evaluation point $\tau_i$.
pub const SST_DOMAIN_TAU: &[u8] = b"HMC_TAU_V1";

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
fn sst_encoded_parts(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
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
fn sst_scalar(tag: &[u8], parts: &[&[u8]]) -> Scalar {
    hash_to_scalar(&sst_encoded_parts(tag, parts))
}

/// Computes the SST trap message $\mu$ that binds the shared signature to the
/// spend input:
/// $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \parallel ds\_tag \parallel E)$.
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

/// Computes the spend-specific shard evaluation point
/// $\tau_i = H(\text{"HMC\_TAU\_V1"} \parallel ds\_tag \parallel t\_id_i) \bmod q$.
///
/// Distinct transactions spending the same input (distinct `t_id`)
/// necessarily get distinct evaluation points, which is what makes collision
/// reconstruction work.
pub fn compute_tau(ds_tag: &str, t_id: &str) -> Scalar {
    sst_scalar(SST_DOMAIN_TAU, &[ds_tag.as_bytes(), t_id.as_bytes()])
}

/// Computes the Schnorr challenge
/// $c = H(\text{"HMC\_TRAP\_CHAL\_V1"} \parallel \mu \parallel R) \bmod q$.
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
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        VoucherCoreError::Crypto(format!("Invalid Scalar {} length", label))
    })?;
    Scalar::from_canonical_bytes(arr).into_option().ok_or_else(|| {
        VoucherCoreError::Crypto(format!(
            "Non-canonical scalar encoding for {} rejected",
            label
        ))
    })
}

/// Decompresses a Base58-encoded Edwards point, rejecting malformed input.
fn parse_point_bs58(encoded: &str, label: &str) -> Result<EdwardsPoint, VoucherCoreError> {
    let bytes = bs58::decode(encoded).into_vec().map_err(|e| {
        VoucherCoreError::Crypto(format!("Invalid Base58 for {}: {}", label, e))
    })?;
    CompressedEdwardsY::from_slice(&bytes)
        .map_err(|_| VoucherCoreError::Crypto(format!("Invalid point {} length", label)))?
        .decompress()
        .ok_or_else(|| {
            VoucherCoreError::Crypto(format!("Decompression of {} failed", label))
        })
}

/// SECURITY (HMSEC-SA04-09): Structural validation of the PUBLIC SST shard
/// pair embedded in a transaction against the generation contract of
/// [`generate_sst_trap`]: both shards must be Base58-decodable, exactly
/// 32 bytes long, and cryptographically well-formed - `trap_r` must
/// decompress to a curve25519 Edwards point, `trap_s` must be a canonical
/// (fully reduced) scalar encoding.
///
/// The chain validator enforces this on every non-init transaction so a
/// malicious payer cannot blind the SST with arbitrary signed garbage
/// strings and thereby permanently evade double-spend attribution. The
/// genesis placeholder pair ("none"/"none") fails the length/decoding gates
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
    let r_bytes = bs58::decode(trap_r).into_vec().map_err(|e| {
        VoucherCoreError::Crypto(format!("Invalid Base58 for trap_r: {}", e))
    })?;
    let r_len = r_bytes.len();
    let r_arr: [u8; 32] = r_bytes.try_into().map_err(|_| {
        VoucherCoreError::Crypto(format!("Invalid point trap_r length ({})", r_len))
    })?;
    ensure_canonical_y(&r_arr)?;
    // Decompressability gate: rejects byte strings that are not affine
    // images of an Edwards point (no sqrt solution on the curve equation).
    CompressedEdwardsY(r_arr)
        .decompress()
        .ok_or_else(|| VoucherCoreError::Crypto("Decompression of trap_r failed".to_string()))?;
    let s_bytes = bs58::decode(trap_s).into_vec().map_err(|e| {
        VoucherCoreError::Crypto(format!("Invalid Base58 for trap_s: {}", e))
    })?;
    parse_canonical_scalar(&s_bytes, "trap_s")?;
    Ok(())
}

/// Little-endian encoding of the base field prime p = 2^255 - 19.
const FIELD_MODULUS_LE: [u8; 32] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x7F,
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

/// The private trap witness handed to the payment recipient at L1.
///
/// Contains everything needed to verify the trap shard locally:
/// the underlying Schnorr signature $(R_{sig}, s_{sig})$ and the masking
/// values $(M_R, m_s)$. All fields are Base58-encoded 32-byte values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrapWitness {
    /// The Schnorr commitment $R_{sig}$ over the spend input.
    pub r_sig: String,
    /// The Schnorr response $s_{sig}$ over the spend input.
    pub s_sig: String,
    /// The masking point $M_R$ (compressed, Base58).
    pub m_r: String,
    /// The masking scalar $m_s$ (canonical scalar, Base58).
    pub m_s: String,
}

/// Generates the SST trap data (public shard) and the private witness for a
/// single spend transaction.
///
/// Math specification (V3):
/// 1. $\mu = H(\text{"SIG"} \parallel ds\_tag \parallel E)$
/// 2. $r = H(\text{"NONCE"} \parallel x \parallel \mu) \bmod q$ (deterministic nonce);\quad
///    $R_{sig} = r \cdot G$;\quad
///    $c = H(\text{"CHAL"} \parallel \mu \parallel R_{sig})$;\quad
///    $s_{sig} = r + c \cdot x$
/// 3. $M_R = \text{hash\_to\_curve}(\text{"MASK\_R"} \parallel x \parallel E \parallel ds\_tag)$;\quad
///    $m_s = H(\text{"MASK\_S"} \parallel x \parallel E \parallel ds\_tag) \bmod q$
/// 4. $\tau_i = H(\text{"TAU"} \parallel ds\_tag \parallel t\_id)$;\quad
///    $R_i = R_{sig} + \tau_i \cdot M_R$;\quad
///    $s_i = s_{sig} + \tau_i \cdot m_s$
///
/// # Arguments
/// * `sk` - The sender's long-term Ed25519 signing key ($x$, anchored to the `did:key`).
/// * `ds_tag` - The double-spend tag of the input being spent.
/// * `eph_pub` - The revealed ephemeral public key (32 raw bytes).
/// * `t_id` - The unique ID of the NEW spending transaction.
///
/// # Returns
/// A tuple of the public [`TrapData`] shard (embedded into the transaction)
/// and the private [`TrapWitness`] (embedded ONLY into the encrypted
/// `RecipientPayload` for the recipient).
pub fn generate_sst_trap(
    sk: &ed25519_dalek::SigningKey,
    ds_tag: &str,
    eph_pub: &[u8; 32],
    t_id: &str,
) -> Result<(TrapData, TrapWitness), VoucherCoreError> {
    let x = get_secret_scalar(sk);

    // 1. Message binding
    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    // 2. Deterministic nonce & Schnorr signature
    let r = sst_scalar(SST_DOMAIN_NONCE, &[x.as_bytes(), &mu]);
    let r_sig_point = r * ED25519_BASEPOINT_POINT;
    let c = sst_challenge(&mu, &r_sig_point);
    let s_sig = r + c * x;

    // 3. Masking slopes (derived exclusively from the long-term key + input)
    let m_r_point = hash_to_curve(&sst_encoded_parts(
        SST_DOMAIN_MASK_R,
        &[x.as_bytes(), eph_pub.as_slice(), ds_tag.as_bytes()],
    ));
    let m_s = sst_scalar(
        SST_DOMAIN_MASK_S,
        &[x.as_bytes(), eph_pub.as_slice(), ds_tag.as_bytes()],
    );

    // 4. Spend-specific evaluation point & shards
    let tau = compute_tau(ds_tag, t_id);
    let r_i = r_sig_point + tau * m_r_point;
    let s_i = s_sig + tau * m_s;

    let trap_data = TrapData {
        ds_tag: ds_tag.to_string(),
        trap_r: bs58::encode(r_i.compress().as_bytes()).into_string(),
        trap_s: bs58::encode(s_i.as_bytes()).into_string(),
    };

    let witness = TrapWitness {
        r_sig: bs58::encode(r_sig_point.compress().as_bytes()).into_string(),
        s_sig: bs58::encode(s_sig.as_bytes()).into_string(),
        m_r: bs58::encode(m_r_point.compress().as_bytes()).into_string(),
        m_s: bs58::encode(m_s.as_bytes()).into_string(),
    };

    Ok((trap_data, witness))
}

/// Verifies the private L1 handover of a trap (fraud *prevention*, R5).
///
/// The recipient of a payment re-derives the challenge from the payer's
/// public identity and checks:
/// 1. **Signature validity:** $s_{sig} \cdot G \stackrel{?}{=} R_{sig} + c \cdot X_{payer}$
///    with $c = H(\text{"CHAL"} \parallel \mu \parallel R_{sig})$
/// 2. **Commitment shard:** $R_i \stackrel{?}{=} R_{sig} + \tau_i \cdot M_R$
/// 3. **Response shard:** $s_i \stackrel{?}{=} s_{sig} + \tau_i \cdot m_s$
///
/// Any failing check proves a garbage/manipulated trap — the caller MUST
/// reject the payment.
///
/// # Arguments
/// * `witness` - The private witness $W$ from the `RecipientPayload`.
/// * `trap_shard` - The public [`TrapData`] embedded in the transaction.
/// * `payer_did` - The declared permanent DID of the payer.
/// * `ds_tag` - The double-spend tag of the input being spent.
/// * `eph_pub` - The revealed ephemeral public key (32 raw bytes).
/// * `t_id` - The ID of the new spending transaction.
pub fn verify_sst_witness(
    witness: &TrapWitness,
    trap_shard: &TrapData,
    payer_did: &str,
    ds_tag: &str,
    eph_pub: &[u8; 32],
    t_id: &str,
) -> Result<(), VoucherCoreError> {
    if trap_shard.ds_tag != ds_tag {
        return Err(VoucherCoreError::Crypto(
            "SST witness check failed: ds_tag mismatch".to_string(),
        ));
    }

    // Parse witness components (strictly canonical response scalars).
    let r_sig_point = parse_point_bs58(&witness.r_sig, "R_sig")?;
    let s_sig = parse_canonical_scalar(
        &bs58::decode(&witness.s_sig)
            .into_vec()
            .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Base58 for s_sig: {}", e)))?,
        "s_sig",
    )?;
    let m_r_point = parse_point_bs58(&witness.m_r, "M_R")?;
    let m_s = parse_canonical_scalar(
        &bs58::decode(&witness.m_s)
            .into_vec()
            .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Base58 for m_s: {}", e)))?,
        "m_s",
    )?;

    // Resolve the payer's public identity point.
    let payer_pk = get_pubkey_from_user_id(payer_did)?;
    let payer_point = ed25519_pk_to_curve_point(&payer_pk)?;

    // 1. One-stage Schnorr signature verification against the payer identity.
    let mu = compute_trap_message_mu(ds_tag, eph_pub);
    let c = sst_challenge(&mu, &r_sig_point);
    if s_sig * ED25519_BASEPOINT_POINT != r_sig_point + c * payer_point {
        return Err(VoucherCoreError::Crypto(
            "SST witness rejected: signature does not verify against payer DID".to_string(),
        ));
    }

    // 2./3. Shard consistency for THIS spend.
    let tau = compute_tau(ds_tag, t_id);
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
    let s = parse_canonical_scalar(
        &bs58::decode(trap_s)
            .into_vec()
            .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Base58 for trap_s: {}", e)))?,
        "trap_s",
    )?;
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
            "SST collision rejected: extracted identity point is the neutral element"
                .to_string(),
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

/// Extracts the offender's identity point directly from two colliding V3
/// gossip fingerprints sharing the same input (`ds_tag`).
///
/// This is the autonomous, single-round-trip deanonymization step of the SST
/// protocol: no transaction chains need to be requested. The result is
/// mathematically bound to the true signer — attributing a different
/// identity would require forging a Schnorr signature (EUF-CMA hardness),
/// which is why the result may be published as a definitive `did:key`
/// attribution (remediation AUDIT-01-F07).
///
/// # Arguments
/// * `ds_tag` - The collision tag both fingerprints must share.
/// * `eph_pub` - The revealed ephemeral public key of the spender (32 bytes).
/// * `fp1`, `fp2` - The two colliding fingerprints (distinct `t_id`s).
///
/// # Returns
/// The extracted identity point $\hat{X}$ (compressed bytes yield the
/// offender's Ed25519 public key).
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
    if fp1.t_id == fp2.t_id {
        return Err(VoucherCoreError::Crypto(
            "SST extraction failed: identical t_ids (replay, not a fork)".to_string(),
        ));
    }

    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    let sh1 = parse_shard(&fp1.trap_r, &fp1.trap_s, compute_tau(ds_tag, &fp1.t_id))?;
    let sh2 = parse_shard(&fp2.trap_r, &fp2.trap_s, compute_tau(ds_tag, &fp2.t_id))?;

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
/// Used as the anti-framing attribution gate: publishing `expected_id` as a
/// `did:key` offender claim is only allowed when this check passes.
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

    let mu = compute_trap_message_mu(ds_tag, eph_pub);

    let parsed: Vec<ParsedShard> = shards
        .iter()
        .map(|fp| {
            if fp.ds_tag != ds_tag {
                return Err(VoucherCoreError::Crypto(
                    "SST consistency check: shard carries foreign ds_tag".to_string(),
                ));
            }
            parse_shard(&fp.trap_r, &fp.trap_s, compute_tau(ds_tag, &fp.t_id))
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

/// Verifies the stored SST trap shards of conflicting transactions against a
/// claimed identity point.
///
/// This is the import-gate counterpart of [`verify_sst_shards_consistency`]
/// operating on full [`Transaction`]s (e.g. inside a `ProofOfDoubleSpend`).
/// Transactions without trap shards are skipped structurally.
///
/// # Security (AUDIT-01-F13): attribution stands on ANY consistent pair
/// The generation side attributes a did:key when ONE colliding pair
/// reconstructs a valid Schnorr signature under the extracted key, while a
/// strict full-set line firewall here let a single attacker-broadcast
/// off-line shard veto every honestly attributed report afterwards
/// (attribution evasion / propagation DoS). This gate therefore succeeds as
/// soon as ANY pair of colliding shards reconstructs a valid signature for
/// exactly the claimed identity point. Extra shards neither contribute to
/// nor weaken the claim: fabricating a verifying pair for an innocent key
/// remains an EUF-CMA forgery, so anti-framing is unaffected. All shards of
/// one collision must still agree on `ds_tag` and `sender_ephemeral_pub`;
/// divergence is treated as tampered evidence.
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
        let eph_bytes: [u8; 32] = bs58::decode(eph_str)
            .into_vec()
            .map_err(|_| {
                VoucherCoreError::Crypto(
                    "SST attribution: invalid sender_ephemeral_pub encoding".to_string(),
                )
            })?
            .try_into()
            .map_err(|_| {
                VoucherCoreError::Crypto(
                    "SST attribution: sender_ephemeral_pub must be 32 bytes".to_string(),
                )
            })?;

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

//==============================================================================
// UNIT TESTS (round-trip & guards)
//==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn fresh_signing_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    fn random_b58_32() -> String {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        bs58::encode(b).into_string()
    }

    fn make_fp(t_id: &str, trap: &TrapData) -> TransactionFingerprint {
        TransactionFingerprint {
            ds_tag: trap.ds_tag.clone(),
            t_id: t_id.to_string(),
            trap_r: trap.trap_r.clone(),
            trap_s: trap.trap_s.clone(),
            ..Default::default()
        }
    }

    fn payer_did_of(sk: &ed25519_dalek::SigningKey) -> String {
        let vk = sk.verifying_key();
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(vk.as_bytes());
        format!("did:key:z{}", bs58::encode(mc).into_string())
    }

    #[test]
    fn test_sst_roundtrip_generation_witness_and_extraction() {
        let sk = fresh_signing_key();
        let ds_tag = random_b58_32();
        let mut eph = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph);

        // Two forks of the same input (same ds_tag/eph).
        let t_id_a = random_b58_32();
        let t_id_b = random_b58_32();
        let (trap_a, wit_a) = generate_sst_trap(&sk, &ds_tag, &eph, &t_id_a).unwrap();
        let (trap_b, wit_b) = generate_sst_trap(&sk, &ds_tag, &eph, &t_id_b).unwrap();

        // Witness verifies for both honest shards.
        let payer_did = payer_did_of(&sk);
        verify_sst_witness(&wit_a, &trap_a, &payer_did, &ds_tag, &eph, &t_id_a)
            .expect("honest witness must verify");
        verify_sst_witness(&wit_b, &trap_b, &payer_did, &ds_tag, &eph, &t_id_b)
            .expect("honest witness must verify");

        // One shared witness covers BOTH forks of the same input (that is the
        // core SST property). A witness from a DIFFERENT signer must fail.
        let stranger = fresh_signing_key();
        assert!(verify_sst_witness(
            &TrapWitness {
                r_sig: wit_a.r_sig.clone(),
                s_sig: wit_a.s_sig.clone(),
                m_r: wit_a.m_r.clone(),
                m_s: bs58::encode(
                    (Scalar::from_canonical_bytes(
                        bs58::decode(&wit_a.m_s)
                            .into_vec()
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    )
                    .into_option()
                    .unwrap()
                        + Scalar::ONE)
                        .as_bytes(),
                )
                .into_string(),
            },
            &trap_a,
            &payer_did,
            &ds_tag,
            &eph,
            &t_id_a
        )
        .is_err());
        assert!(verify_sst_witness(
            &wit_a,
            &trap_a,
            &payer_did_of(&stranger),
            &ds_tag,
            &eph,
            &t_id_a
        )
        .is_err());

        // Collision extraction recovers the true identity point.
        let expected_x = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
        let fp_a = make_fp(&t_id_a, &trap_a);
        let fp_b = make_fp(&t_id_b, &trap_b);
        let x_hat = extract_sst_identity(&ds_tag, &eph, &fp_a, &fp_b).unwrap();
        assert_eq!(
            x_hat, expected_x,
            "extraction must recover the signer identity"
        );

        // Consistency check passes for the true identity...
        verify_sst_shards_consistency(&[&fp_a, &fp_b], &expected_x, &ds_tag, &eph)
            .expect("genuine shards must be consistent");

        // ...and fails for any other identity (anti-framing).
        let stranger_pt = ed25519_pk_to_curve_point(&stranger.verifying_key()).unwrap();
        assert!(verify_sst_shards_consistency(&[&fp_a, &fp_b], &stranger_pt, &ds_tag, &eph).is_err());
    }

    #[test]
    fn test_sst_degenerate_guards_fire() {
        let sk = fresh_signing_key();
        let ds_tag = random_b58_32();
        let mut eph = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph);

        // Identical t_id => identical tau => replay guard fires.
        let t_id = random_b58_32();
        let (trap_a, _) = generate_sst_trap(&sk, &ds_tag, &eph, &t_id).unwrap();
        let (trap_b, _) = generate_sst_trap(&sk, &ds_tag, &eph, &t_id).unwrap();
        assert_eq!(trap_a, trap_b, "generation is deterministic");
        let fp_a = make_fp(&t_id, &trap_a);
        assert!(
            extract_sst_identity(&ds_tag, &eph, &fp_a, &fp_a).is_err(),
            "identical fingerprints (replay) must be rejected"
        );
        let _ = trap_b;
    }

    #[test]
    fn test_sst_non_canonical_scalars_rejected() {
        let sk = fresh_signing_key();
        let ds_tag = random_b58_32();
        let mut eph = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph);

        let t_id_b = random_b58_32();
        let (trap_b, _) = generate_sst_trap(&sk, &ds_tag, &eph, &t_id_b).unwrap();

        // The original shard is canonical.
        let s_bytes = bs58::decode(&trap_b.trap_s).into_vec().unwrap();
        assert!(parse_canonical_scalar(&s_bytes, "trap_s").is_ok());

        // A malleated BYTE encoding (s_bytes + L, same group element) must be
        // rejected by strict canonical parsing.
        const L_BYTES: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde,
            0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut malleated_bytes = s_bytes;
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = malleated_bytes[i] as u16 + L_BYTES[i] as u16 + carry;
            malleated_bytes[i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }
        assert!(
            parse_canonical_scalar(&malleated_bytes, "trap_s").is_err(),
            "non-canonical scalar encodings must be rejected"
        );
    }

    #[test]
    fn test_sst_inconsistent_third_shard_rejected() {
        let sk = fresh_signing_key();
        let ds_tag = random_b58_32();
        let mut eph = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph);

        let t_a = random_b58_32();
        let t_b = random_b58_32();
        let (trap_a, _) = generate_sst_trap(&sk, &ds_tag, &eph, &t_a).unwrap();
        let (trap_b, _) = generate_sst_trap(&sk, &ds_tag, &eph, &t_b).unwrap();

        // A third shard from a DIFFERENT signer (inconsistent line).
        let impostor = fresh_signing_key();
        let t_c = random_b58_32();
        let (trap_c, _) = generate_sst_trap(&impostor, &ds_tag, &eph, &t_c).unwrap();

        let fp_a = make_fp(&t_a, &trap_a);
        let fp_b = make_fp(&t_b, &trap_b);
        let fp_c = make_fp(&t_c, &trap_c);

        let expected_x = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
        assert!(
            verify_sst_shards_consistency(&[&fp_a, &fp_b, &fp_c], &expected_x, &ds_tag, &eph)
                .is_err(),
            "an inconsistent n>=3 shard set must be rejected"
        );
    }

    #[test]
    fn test_canonical_y_boundary_values() {
        // Little-endian encodings around the base field prime
        // p = 2^255 - 19 = [0xED, 0xFF x30, 0x7F] (sign bit cleared).
        let mut y_p_minus_one = [0xFFu8; 32];
        y_p_minus_one[0] = 0xEC;
        y_p_minus_one[31] = 0x7F;

        let mut y_p = [0xFFu8; 32];
        y_p[0] = 0xED;
        y_p[31] = 0x7F;

        let mut y_p_plus_one = [0xFFu8; 32];
        y_p_plus_one[0] = 0xEE;
        y_p_plus_one[31] = 0x7F;

        assert!(
            ensure_canonical_y(&y_p_minus_one).is_ok(),
            "the largest canonical coordinate y = p - 1 must be accepted"
        );
        assert!(
            ensure_canonical_y(&y_p).is_err(),
            "the modulus encoding itself (y = p) must be rejected"
        );
        assert!(
            ensure_canonical_y(&y_p_plus_one).is_err(),
            "y > p must be rejected"
        );
    }

    #[test]
    fn test_validate_shard_structure_accepts_max_canonical_point() {
        // y = p - 1 ([0xEC, 0xFF x30, 0x7F], sign bit cleared) decompresses to
        // the valid curve point (0, -1), so the maximal canonical coordinate
        // must pass the full structural validation.
        let mut max_canonical = [0xFFu8; 32];
        max_canonical[0] = 0xEC;
        max_canonical[31] = 0x7F;
        assert!(
            CompressedEdwardsY(max_canonical)
                .decompress()
                .is_some(),
            "y = p - 1 must decompress to the curve point (0, -1)"
        );
        let trap_r_max = bs58::encode(max_canonical).into_string();
        // Canonical scalar encoding as a well-formed trap_s companion.
        let trap_s_valid = bs58::encode([0x01u8; 32]).into_string();

        validate_shard_structure(&trap_r_max, &trap_s_valid)
            .expect("maximal canonical trap_r encoding must be accepted");

        // Encodings with y >= p fail the canonical-y gate BEFORE decompression
        // is attempted (they would otherwise reduce modulo p implicitly).
        for first_byte in [0xEDu8, 0xEE] {
            let mut non_canonical = [0xFFu8; 32];
            non_canonical[0] = first_byte;
            non_canonical[31] = 0x7F;
            let bad_trap_r = bs58::encode(non_canonical).into_string();
            assert!(
                validate_shard_structure(&bad_trap_r, &trap_s_valid).is_err(),
                "non-canonical trap_r (y >= p) must be rejected"
            );
        }
    }
}
