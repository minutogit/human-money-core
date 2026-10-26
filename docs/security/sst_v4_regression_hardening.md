# SST V4 regression hardening

Date: 2026-10-26. V4 intentionally rejects prior authorization signatures and key derivations. No compatibility fallback or migration is provided.

## Receipt ownership

Genesis holders, received outputs, and split change all use `E = X + hG`, where `h = H(HMC_STEALTH_BLIND_V4, seed, X)`. The owner scalar is `x + h`. Genesis/change use private HKDF-derived blinding seeds; received outputs use random seeds. A payer knowing the received seed cannot derive the payee's spend scalar.

The encrypted `RecipientPayload` carries `input_key_seed`, the opening of the **spent input**, alongside the checked trap witness. `verify_sst_witness` requires that opening to derive exactly the revealed `sender_ephemeral_pub` from the declared sender DID. Public chains also check the permanent owner attached to a matched public anchor. Raw `SigningKey::from_bytes(recipient_seed)` fallbacks are removed from creation, ingress, balance calculation, recovery, and test helpers.

Clients constructing keys directly must use `derive_owned_ephemeral_key`, rather than treating a blinding seed as an Ed25519 private key. The wallet recovery API still returns `EphemeralKey`.

## Compact, self-verifying signature lines

The honest base signature remains `R_sig = rG`, `s_sig = r + cx`, with `c = H(domain, mu, R_sig)` and `mu = H(domain, ds_tag, E)`. V4 derives **r from secret x and mu**. Deriving r from the disclosed `K_trap` would let a recipient recover the permanent scalar as `(s_sig - r) / c`.

Both masks derive from `(R_sig, s_sig, mu)` with separate point/scalar domains. After interpolating a pair, reconstruction recomputes both masks before returning a signature identity candidate. Steered junk therefore cannot create a valid alternative attribution. Every parser applies the same canonical encoding and prime-order subgroup checks, including rejection of negative-zero point encodings and non-canonical scalars.

Single-shard anonymity is computational; the former claim of information-theoretic hiding no longer applies to deterministic self-verifying masks. A DLEQ proof does not prove that an adversarial signer chose a deterministic secret Schnorr nonce. Different valid signature lines can be accepted individually; victim disclosure closes attribution for that case too.

The public shard representation stays **32-byte point + 32-byte scalar**. No historical validity certificates or general ZK proofs are added to L1. The existing encrypted receipt gains the input opening; conflict-only disclosures live in `ProofOfDoubleSpend`.

## Victim witness disclosure

A historical junk shard cannot be publicly validated in isolation without revealing private witness data. Rejecting it during interpolation prevents false attribution, but cannot reconstruct a DID from the remaining single honest shard.

A direct victim has the original encrypted handover receipt. Upon observing a collision, the wallet:

1. Verifies two distinct spend contents signed by the same E under the same `ds_tag`. An exact replay, retention changes, or signature re-randomization alone do not qualify.
2. Decrypts its own matching stored receipt and verifies the complete witness, ownership opening, guard commitment, and honest shard.
3. Publishes `VictimWitnessDisclosure` with its index in the complete authenticated fingerprint evidence.
4. Attributes the decoded permanent owner only after that disclosure verifies.

An independent wallet rechecks the signed collision **before** accepting the disclosed owner. The second shard may be garbage. Ordinary history remains private, including prior senders in Stealth/Flexible transfers. Without an ownership disclosure, a gossip-only proof keeps `ephemeral:E` as its offender; successful interpolation can supply an advisory signature candidate, but cannot establish ownership of E by itself.

Proofs retain original fingerprints so signed voucher bindings, timestamps, guard hashes, and same-ID variants survive synthetic transaction conversion and export/import. Duplicate detection uses these original authenticated fields, including metadata equivocations, while excluding retention-only changes and signature re-randomization. Definitive DID imports require the ownership disclosure. A copied private trap witness alone cannot authenticate a fabricated second spend. Proof evidence is bounded by the existing fingerprint bucket limit, and at most one receipt disclosure is admitted. Proof generation prefers an actual locally stored input and excludes unrelated keys poisoning the same tag bucket. Import requires one common input key. Fingerprint-only proofs can establish attribution, but synthetic IDs/timestamps do not authorize transaction-state changes; canonical full transaction proofs retain their existing quarantine behavior.

This fallback requires an honest direct recipient to retain its receipt and observe the conflicting signed spend. Pure gossip can authenticate an ephemeral offender immediately; permanent attribution is propagated once a victim supplies the ownership opening. Core performs no network calls.

## Same-ID equivocation

`tau = H(HMC_TAU_V4, ds_tag, t_id, privacy_guard_hash)` uses the already authenticated guard commitment. Creation builds the witness, encrypts the guard, then evaluates the public shard to avoid a hash cycle. Same-ID handovers with different guards now have distinct evaluations and survive proof creation, relay, and import. Same-ID changes confined to trap data can still be proved by victim disclosure even when interpolation has equal tau.

All authorization digests use `HMC_TX_AUTH_V4`. L2 remains a blind adapter over the existing `trap_r`/`trap_s` fields; external consumers must adopt the new domain. L2 conflict retries with the same local transaction ID retain their existing idempotent success semantics.

## Regression evidence

The first six secure assertions in `tests/poc_sst_trap_evasion_v2.rs` all failed against the original code. A subsequent end-to-end historical junk-hop test also failed after self-verifying masks alone, and now passes through automatic victim disclosure and independent serialized proof import.

Coverage includes identity swaps, all three output kinds, legacy seed rejection, steered shards, contradictory attribution, same-ID guard and metadata conflicts, corrupt private witnesses, secret-nonce disclosure, malicious per-fork nonce selection, exact replays, forged second signatures, tampered ownership disclosures, unchanged 64-byte shards, and private multi-hop history. Property tests exercise random identity/input seeds and both ordinary forks and guard equivocations.

Validation results are recorded in `STATUS.md`.
