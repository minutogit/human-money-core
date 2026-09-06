# WAVE 4 — Module 01 Results: Double-Spend Trap, DS-Tags & Conflict Detection

**Date:** 2026-08-26 · **Branch:** live · **Phase:** B (Fail-First-TDD proof build)
**Test file:** `tests/security_audit_wave4_traps.rs` · **Command:** `CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_traps`
**Final canonical run:** `3 tests run: 0 passed, 3 failed` — every hypothesis PROVEN red on the unpatched baseline.

> **Environment note:** During the session a parallel agent refactored the V3
> auth digest (`calculate_l2_payload_hash_raw`) live and transiently broke the
> pre-existing `src/bin/l2_client_simulator` bin, which blocked ALL integration
> test builds repo-wide (~12:35–12:41). The test file was hardened against this
> churn by using library-side helpers (`sign_fingerprint_in_place`,
> `verify_fingerprint_signature`, `resign_transaction_ext`) plus an explicit
> fixture-validity precondition that converts any future digest drift into a
> loud failure instead of a vacuous pass.

---

## AUDIT-W4-TRAP-201 (WH4-01-201) — Fabricated `ephemeral:` soft-proof claims gain persistent offender linkage at import

| Field | Value |
| :--- | :--- |
| Status | **PROVEN** |
| Severity / CWE | HIGH · CWE-347 / CWE-345 |
| Test | `wh4_01_201_import_rejects_unverified_ephemeral_offender_claims` |

**Failure excerpt (red on unpatched code):**

```
AUDIT-W4-TRAP-201: fabricated `ephemeral:` soft-proof claim without ANY
cryptographic evidence gained persistent offender linkage (import_result=true,
reputation="KnownOffender(26gmfBUamkjBs24QEFj6NBLs936TTKFpYRJu8cLWSkqQ)",
persisted_conflicts=1). Non-did:key attribution claims must be evidence-verified
(or stripped) at the import boundary.
```

**Proof semantics:** Fresh witness wallet, attacker-signed report with
`offender_id = ephemeral:<victim_pub>`, two structurally consistent
`gossip_soft_placeholder` transactions with garbage shards under an
attacker-chosen ds_tag. All gates pass (Gate 3b skips non-did:key claims, Gate 4
has no local context → `NoLocalContext`), the defamatory record persists and
`check_reputation` flips to `KnownOffender`.

**Fix-Notiz:** Re-establish evidence authenticity at the import boundary — reject
`ephemeral:`/anonymous-attributing proofs unless each embedded transaction's V3
material verifies under the claimed key (or persist stripped of all offender
linkage so reputation stays untouched); the SOLL assertion accepts either
remediation (`import is_err() || reputation != KnownOffender`).

---

## AUDIT-W4-TRAP-202 (WH4-01-202) — Trap-bearing INIT transactions mint spend-typed fingerprints under attacker-chosen DS-Tags

| Field | Value |
| :--- | :--- |
| Status | **PROVEN** |
| Severity / CWE | MEDIUM · CWE-20 / CWE-349 |
| Test | `wh4_01_202_trap_bearing_init_must_not_classify_as_spend_claim` |

**Failure excerpt (red on unpatched code):**

```
AUDIT-W4-TRAP-202: trap-bearing INIT transaction passed L1 validation (true)
and produced a SPEND-TYPED fingerprint (is_init=false,
attacker_chosen_ds_tag='2NTUcLEEUxr3xNyehCPxrZ9PAWX5kRE3sjvsR34Nifn1',
ingress_authentic_probe=false) — an authenticated spend-claim masquerade minted
by any voucher author.
```

**Proof semantics:** Genuine voucher whose init tx carries a real
`generate_sst_trap()` shard pair under an attacker-chosen ds_tag, fully
re-signed via the genesis-lock derivation (t_id stable — its preimage excludes
`trap_data`). Chain validation stays green because the shard-structure firewall
(HMSEC-SA04-09) and ds_tag input-binding live inside chain.rs's `.skip(1)` loop;
`create_fingerprint_for_transaction` blindly trusts `trap.ds_tag` → spend-typed
classification. Note: the diagnostic probe shows the ingress signature gate
currently rejects such entries (challenge-tag mismatch), so the concrete
pollution channel is the LOCAL detection pipeline (own/local-history buckets,
`check_for_double_spend` merges without ingress gate) — refine the threat model
accordingly during triage.

**Fix-Notiz:** Either reject trap-bearing init transactions in chain validation
(move the trap block out of the `.skip(1)` scope for init) or classify init-tx
fingerprints as init/no-trap regardless of embedded shards; the combined SOLL
assertion (`validation is_err() || is_init_fingerprint(fp)`) turns green on
either route.

---

## AUDIT-W4-TRAP-203 (WH4-01-203) — Unbounded foreign fingerprint ingress (quadratic SST extraction + junk storage)

| Field | Value |
| :--- | :--- |
| Status | **PROVEN** |
| Severity / CWE | MEDIUM · CWE-770 / CWE-407 |
| Test | `wh4_01_203_foreign_ingress_admission_must_be_capacity_bounded` |

**Failure excerpt (red on unpatched code):**

```
AUDIT-W4-TRAP-203: unbounded foreign fingerprint ingress admitted 2000 entries
into bucket 'Ds7AM8B9ogVQGhe1ugmBBekfy8uuFnX93HzFpJ6PQX6k' (bucket_len=2000) —
no admission cap exists (proposed bound 150, symmetric to outbound
MAX_FINGERPRINTS_TO_SEND). This enables quadratic SST extraction work and
unbounded authenticated junk storage.
```

**Proof semantics (STATE-based, no wall-clock assertions per instructions):**
2000 fingerprints sharing one attacker-chosen ds_tag, distinct counter-seeded
t_ids, valid-format-but-unrelated shards — each individually GENUINELY passing
the V3 ingress signature gate (fixture precondition asserts
`verify_fingerprint_signature == true` for first AND last entry, eliminating
vacuous passes). Result: `accepted == bucket_len == 2000`; the uncapped bucket
itself is the finding (every later conflict scan runs O(n²) pairwise
`extract_sst_identity` parse attempts over it).

**Fix-Notiz:** Enforce a bounded admission cap at ingress in
`import_foreign_fingerprints` (per-bucket and/or global foreign-store bound;
proposed reference value 150 mirroring the outbound `MAX_FINGERPRINTS_TO_SEND`,
final value = design decision).

---

## Summary Table

| Finding-ID | Status | Test | Red-Failure-Art |
| :--- | :--- | :--- | :--- |
| AUDIT-W4-TRAP-201 | PROVEN | `wh4_01_201_import_rejects_unverified_ephemeral_offender_claims` | import Ok + `KnownOffender` persisted |
| AUDIT-W4-TRAP-202 | PROVEN | `wh4_01_202_trap_bearing_init_must_not_classify_as_spend_claim` | validation Ok + spend-typed fp |
| AUDIT-W4-TRAP-203 | PROVEN | `wh4_01_203_foreign_ingress_admission_must_be_capacity_bounded` | accepted/bucket_len == 2000 |

WH4-01-204 was explicitly out of scope for Phase B per assignment (KNOWN-OPEN-DEEPDIVE).
No finding required REFUTED rewriting; no test is BLOCKED.
