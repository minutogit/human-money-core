# Wave 4 — Results Module 04: Transaction Logic & State Integrity

> Agent: B-04 (Phase B, Fail-First TDD). Branch `live`. Date: 2026-08-26.
> Test file: `tests/security_audit_wave4_integrity.rs` (only file created besides this report).
> Command: `CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_integrity`
> Result: **3 tests run: 0 passed, 3 failed** — every test asserts the secure
> Soll-Verhalten and is RED on unpatched code (= proof). No src/ changes, no git ops.
> Note: during the run a concurrent agent's WIP temporarily broke
> `bin/l2_client_simulator` (pre-existing compile error against their in-flight L2-API
> changes, not caused by this test file); after their fix the command above ran cleanly.
> Deviation from hypothesis WH4-04-502: the sketch's example pair
> (`init "…T00:00:00Z"` / transfer `"2026-01-01T23:59:59-14:00"`) is accidentally
> FAIL-CLOSED — its string sorts BELOW the tip, so the raw string guard already rejects
> it. The exploitable direction (proven here) is a large POSITIVE offset whose local
> clock reading sorts ABOVE the tip while the parsed instant lies BEFORE it.

| Finding-ID | Wave-ID | Severity | Status | Test |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-W4-INT-501 | WH4-04-501 | HIGH | **PROVEN** | `wh4_04_501_init_without_attributed_creator_must_fail_validation` |
| AUDIT-W4-INT-502 | WH4-04-502 | LOW | **PROVEN** | `wh4_04_502_chain_time_ordering_must_reject_offset_confusion` |
| AUDIT-W4-INT-503 | WH4-04-K4 | MEDIUM | **PROVEN** | `wh4_04_k4_committed_multi_send_must_not_silently_lose_forensics` |

---

## AUDIT-W4-INT-501 / WH4-04-501 — PROVEN (HIGH)

- **Test:** `wh4_04_501_init_without_attributed_creator_must_fail_validation`
- **Setup:** hand-crafted voucher with header byte-faithful to the loaded,
  runtime-signed MINUTO-V1 standard (uuid `MINUTO-V1-2025-09`, verified
  `standard_definition_hash`, unit "Minuto", amount 100, P5Y validity within
  `[P1Y,P10Y]`, firewall P3Y satisfied) but `creator_profile.id = None`.
  Init tx: sender = recipient = attacker `did:key`, attacker-controlled genesis key,
  V3-consistent `layer2_signature` + identity signature via the shared production-shape
  helper `resign_transaction_ext`. Minuto's strict guarantor policy ([2,2], role
  "guarantor", ISO-5218 gender-parity CEL rules) is satisfied entirely with
  ATTACKER-owned keys (male "1" + female "2", valid signature_id/Ed25519 pairs) —
  demonstrating that non-creator minima bind nothing to an issuer.
- **Assertion (Soll):** `validate_voucher_against_standard(&v, &std)` must be `Err`.
- **Ausschnitt (red run):**
  ```text
  AUDIT-W4-INT-501 VIOLATION: accepted a voucher under trusted standard UUID
  'MINUTO-V1-2025-09' whose creator_profile.id is None and whose init transaction
  is sent/received solely by the attacker's did:key. … Got: Ok(())
  ```
- **Fix-Notiz:** Make issuance attribution mandatory instead of conditional:
  (a) reject `creator_profile.id == None` outright in
  `verify_transaction_basics` (chain.rs:511-520) — or require init sender ==
  recipient == a PRESENT creator id; (b) require a creator-role signature
  unconditionally in `verify_signatures` (signatures.rs:26-42/69-89); (c)
  fail closed in the issuance firewall when the creator id is absent
  (balance.rs:33-39). Confirm no intentional anonymous-issuance use case
  exists first (none documented; queries render blank creators today).

## AUDIT-W4-INT-502 / WH4-04-502 — PROVEN (LOW)

- **Test:** `wh4_04_502_chain_time_ordering_must_reject_offset_confusion`
- **Setup:** cryptographically fully self-consistent 2-tx public chain
  (init 100.00 → full transfer, all hashes/t_ids recomputed, structurally valid SST
  shards via `generate_sst_trap`, L2 signatures per HMC_TX_AUTH_V3):
  `init.t_time = "2026-01-02T00:00:00Z"` (instant 00:00Z),
  `transfer.t_time = "2026-01-02T13:00:00+14:00"` → instant **2026-01-01T23:00:00Z**,
  i.e. BEFORE its predecessor, while the string sorts AFTER the tip ('1' > '0'
  at index 10), so chain.rs:177's raw comparison accepts it.
- **Assertion (Soll):** `verify_transactions(&v, &std)` must be
  `Err(InvalidTimeOrder{..})`.
- **Ausschnitt (red run):**
  ```text
  AUDIT-W4-INT-502 VIOLATION: verify_transactions accepted a chain whose interior
  t_time '2026-01-02T13:00:00+14:00' (instant 2026-01-01T23:00:00Z) is instant-wise
  BEFORE its predecessor '2026-01-02T00:00:00Z' … Got: Ok("Ok(())")
  ```
- **Fix-Notiz:** Replace lexicographic comparisons with instant-based ones at all
  three sites: chain.rs:177 (`tx.t_time <= last_tx_time`), chain.rs:530
  (`tx.t_time < voucher.creation_date`), signatures.rs:98
  (`signature_time < voucher.creation_date`). Parse both operands as
  RFC3339 instants and reject unparsable forms outright (fail closed).

## AUDIT-W4-INT-503 / WH4-04-K4 — PROVEN (MEDIUM)

- **Test:** `wh4_04_k4_committed_multi_send_must_not_silently_lose_forensics`
- **Setup:** wallet with two healthy Active FreeTaler sources (100 each);
  both fully sent in one atomic `execute_multi_transfer_and_bundle` with a spy
  archive that returns a persistent error for exactly source #2's
  `archive_voucher` call. Financial commit succeeds (best-effort phase must
  not abort a committed send — precondition asserted green).
- **Assertion (Soll):** after the Ok commit, the forensic archive contains ALL
  transferred pre-states (or the caller is informed about the incompleteness).
- **Ausschnitt (red run):**
  ```text
  AUDIT-W4-INT-503 VIOLATION: atomically committed 2-source send returned Ok(())
  while the forensic archive holds only ["92DVyEKdWd151sEji6xySyF6aqRSvEobAgq1jCxuSewb",
  "8gi9eknvaftJFagPC4gH1mhG6VP8aPdy1vxytpbPTgGM"] -- the pre-state of voucher
  '21wbrb2e3f72X89TmshusZGe9p9CxNgyg9zjvN9DCmFK' was lost to a per-voucher 'continue'
  in the best-effort archiving loop with no completeness signal to the caller
  (transaction_handler.rs:1073-1097).
  ```
- **Fix-Notiz:** Surface archive-completeness to the caller: add a result flag /
  metadata channel on `CreateBundleResult` (e.g. `archive_incomplete: Vec<String>`
  or a warn event), or journal-and-retry failed states until the forensic set is
  complete. Keep the phase best-effort w.r.t. aborting the send, but never silent.

---

### Summary

All three targeted hypotheses (501, 502, K4) are **PROVEN** by red tests through the
mandated command; N4 was out of scope for this pass (assignment listed K4 as optional
follow-up only). Tests turn into permanent regression shields once the fixes above land.
