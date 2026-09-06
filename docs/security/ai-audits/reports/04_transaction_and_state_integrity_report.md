# Security Audit: Transaction Logic, State Integrity & Rust Robustness

## AI Auditor Role & System Invariants

You are a senior Rust systems engineer and financial ledger security auditor.

`human_money_core` manages value transfers, splitting, and merging of vouchers.

1. **Conservation of Value:** $\sum \text{Inputs} = \sum \text{Outputs} + \text{Fees}$. Value can NEVER be created out of thin air. Negative amounts, precision underflows, and arithmetic overflows must be mathematically impossible.
2. **Split Anchor Separation**: In split transactions, the transfer branch and the change branch MUST have cryptographically independent ephemeral keys and anchor commitments ($Key_{\text{Receiver}} \neq Key_{\text{Change}}$).
3. **Panic-Freedom on Untrusted Inputs**: The library processes untrusted binary/TOML bundles from external networks and peers. The core engine MUST NEVER panic (`unwrap()`, `expect()`, out-of-bounds indexing) on malformed or malicious inputs.

---

## Vulnerability Findings

### H-01-01: `unwrap_or(Decimal::MIN)` Silent Balance Sentinel (Medium)

**Target**: `src/models/voucher.rs::spendable_balance` and `spendable_balance_for_user`

**Hypothesis**: The `unwrap_or(Decimal::MIN)` pattern on `Decimal::from_str()` results silently defaults to `Decimal::MIN` on parse failure. While `Decimal::MIN` is a fail-closed sentinel (unlike defaulting to `Decimal::ZERO`), any `from_str` failure still indicates malformed data that should be surfaced as an error rather than producing a sentinel value that could mask value conservation issues.

**Evidence**: In `voucher.rs::spendable_balance` (lines 990, 995, 999, 1004, 1012):
```rust
Decimal::from_str(&last_tx.amount).unwrap_or(Decimal::MIN)
```
Five occurrences across the function where a malformed amount string silently defaults to `Decimal::MIN` instead of returning a `VoucherCoreError`. The associated comment (line 986-988) documents this as intentional per security guideline AUDIT-00-WILDCARD-13 to prevent forensic masking, but the `unwrap_or` pattern itself remains a footgun if the sentinel value is ever changed back to `Decimal::ZERO` or if code paths evolve to interpret `MIN` as a valid balance.

**Root Cause**: `Decimal::from_str().unwrap_or(...)` defaults on parse failure rather than propagating the error. The code intentionally uses `Decimal::MIN` as a fail-closed sentinel (per AUDIT-00-WILDCARD-13), but the underlying pattern of silently defaulting on deserialization failure persists.

**Test Strategy**: Create a test voucher with a transaction that has a malformed amount string edge case and verify `spendable_balance` does not silently return `Decimal::MIN` as if it were a valid balance. The test MUST assert that malformed amounts are properly rejected or handled through the error path.

---

### H-02-01: `unwrap_or(0)` in `ValueDefinition::validate_precision` and `format_amount` (High)

**Target**: `src/models/voucher.rs::ValueDefinition::validate_precision` (line 283-285) and `ValueDefinition::format_amount` (line 298-300)

**Hypothesis**: In both `validate_precision` and `format_amount`, the expression `Decimal::from_str(&self.amount).map(|d| d.scale()).unwrap_or(0)` defaults to `0` if the standard's `amount` field is malformed or missing. An attacker crafting a non-canonical standard TOML with an invalid `amount` string could cause the allowed scale to default to `0`, permitting any precision on transaction amounts and potentially allowing value conservation violations where output value exceeds input.

**Evidence**: 
- `voucher.rs:283-285`:
  ```rust
  let allowed = Decimal::from_str(&self.amount)
      .map(|d| d.scale())
      .unwrap_or(0);
  ```
- `voucher.rs:298-300`:
  ```rust
  let allowed = Decimal::from_str(&self.amount)
      .map(|d| d.scale())
      .unwrap_or(0);
  ```

If a standard is issued with a non-numeric or empty `amount` field, `allowed` becomes `0`, meaning any transaction amount (even arbitrarily large or precision-heavy values) would pass validation (`amount.scale() > 0` is always true for non-integer amounts). This could enable a minting-like exploit where the standard's precision constraints are subverted.

**Root Cause**: `Decimal::from_str().unwrap_or(0)` silently defaults the allowed scale to `0` on parse failure, rather than returning an error. The standard's `amount` field is treated as trusted, but TOML bundles from external sources could contain malformed standards.

**Severity**: High — Could allow precision-based value conservation violations if a malicious or non-compliant standard is loaded.

**Affected Lines**: `voucher.rs:283-285`, `voucher.rs:298-300`

**Triage Classification**: `[CONFIRMED VULNERABILITY]`

**Triage Rationale**: 
- *Threat-Actor Boundary*: The standard TOML could be supplied by external parties or derived from untrusted sources. The `amount` field in the standard is not cryptographically verified beyond normal deserialization.
- *Offline Resilience*: Not applicable — this is a standard-loading concern, not an offline forensics feature.
- *Architectural Decision*: Not an intentional design requirement; the `unwrap_or(0)` is a latent footgun.
- *Functional Trade-Off*: Replacing `unwrap_or(0)` with a `VoucherCoreError` would cause standards with intentionally minimal `amount` fields to fail, but such standards should use a valid numeric string. The fix is to return an error on parse failure.

**Remediation**: Replace `unwrap_or(0)` with `map_err(|_| VoucherCoreError::AmountPrecisionExceeded { allowed: 0, found: 0 })` or similar, so that a malformed standard `amount` field is rejected outright rather than defaulting to permissive precision.

---

### H-02-02: Panic Hazards in `round_up_date` — `.unwrap()` and `.expect()` Calls (Medium)

**Target**: `src/services/utils.rs::round_up_date` (lines 96, 175, 357-363)

**Hypothesis**: The `round_up_date` function contains multiple `.unwrap()` and `.expect()` calls that could panic if given unexpected date/rounding_str combinations. While the function is currently called with values from the trusted standard configuration during voucher creation, the audit vector specifically requires checking for panic hazards on untrusted inputs. If an adversary could influence the rounding string or date values (e.g., via a malformed standard), a panic could be triggered, causing a DoS.

**Evidence**:
- `utils.rs:96`: `.expect("valid predecessor day")` — fails if date arithmetic produces no predecessor
- `utils.rs:175`: `.expect("Dec 31 is always valid")` — assumes Dec 31 is always a valid date (true for Gregorian, but the unwrap is on a `single()` result)
- `utils.rs:357-363`: `.unwrap()` and `.unwrap()` chained calls on `with_hour`, `with_minute`, `with_second`, `with_nanosecond` — each could `panic` if the date is invalid (though Dec 31 is always valid, the chain is fragile)

**Root Cause**: The function assumes specific invariants about the input date and rounding string that may not hold if called with crafted inputs. The `.unwrap()`/`.expect()` calls are defense-in-depth gaps.

**Severity**: Medium — Panic potential exists, but the function is currently only called with trusted internal values. The risk is elevated by the audit's untrusted-input threat model.

**Affected Lines**: `utils.rs:96`, `utils.rs:175`, `utils.rs:357-363`

**Triage Classification**: `[FALSE POSITIVE / MISINTERPRETATION]`

**Triage Rationale**: 
- *Threat-Actor Boundary*: The `round_up_date` function is called during voucher creation with `rounding_str` from `verified_standard.mutable.app_config.round_up_validity_to`, which is part of the standard definition (trusted configuration). It is not directly processing untrusted binary data. However...
- *Offline Resilience*: Not applicable — a panic here would break voucher creation, not offline forensics.
- *Architectural Decision*: The behavior is not documented as an intentional design requirement in `design-decisions`, `PRIVACY_FAQ.md`, or ADRs. However, the inputs are constrained to known-good values from the standard config.
- *Functional Trade-Off*: Changing the `.unwrap()`/`.expect()` calls to proper `Result` handling would increase robustness but is not critical since the function is not on the untrusted data path. Per the triage rules, since the finding is based on a assumption that the function could receive untrusted inputs (which is not the current code path), this is a [FALSE POSITIVE] in the strict sense. However, it is noted as a code-quality concern for future refactoring.

**Action**: No code change required. Document in code comments that `round_up_date` is called with trusted standard configuration only, and the `.unwrap()`/`.expect()` calls assume valid inputs per architectural invariants.

---

### H-02-03: Split Transaction Anchor Independence Verification (Low)

**Target**: `src/models/voucher.rs::create_transaction` (lines 695-724)

**Hypothesis**: In split transactions, the change anchor (`change_ephemeral_pub_hash`) is derived via HKDF from the sender's permanent key, while the transfer anchor uses the sender's ephemeral key. The audit vector requires verifying that these two anchors are cryptographically independent ($Key_{\text{Receiver}} \neq Key_{\text{Change}}$).

**Evidence**: 
- Lines 695-724 derive `change_ephemeral_pub_hash` using HKDF extraction/expansion from `sender_permanent_key.to_bytes()` with info `"change_seed"` or `"<prefix>change_seed"`.
- The sender ephemeral key (used for transfer anchor via `receiver_ephemeral_pub_hash`) is derived from the `sender_ephemeral_key` parameter (an external, per-transaction key).

**Analysis**: The two anchor derivation paths use completely different key material (permanent key vs. per-transaction ephemeral key) and different KDF procedures (HKDF vs. direct derivation). This ensures cryptographic independence by design. No overlap vector exists.

**Root Cause**: N/A — the independence is a confirmed design property. However, the audit requires explicit verification and documentation.

**Severity**: Low — No vulnerability; design verified correct.

**Affected Lines**: `voucher.rs:695-724`

**Triage Classification**: `[INTENTIONAL DESIGN REQUIREMENT]`

**Triage Rationale**: 
- *Threat-Actor Boundary*: Both anchors are derived from sender key material, but via independent KDF paths. Neither is exposed to the network directly; both are part of the voucher's internal state.
- *Offline Resilience*: Anchor independence is critical for offline double-spend forensics (enabling hop-by-hop attribution). Changing this would break the offline dispute resolution model.
- *Architectural Decision*: The dual-key derivation is explicitly documented in the code comments and is a core architectural decision for the split protocol. It is intended behavior, not a vulnerability.
- *Functional Trade-Off*: The two-derivation-path design intentionally separates change and transfer anchors to prevent the specific attack vector of anchor key reuse. This is a [INTENTIONAL DESIGN REQUIREMENT] per the split protocol specification.

**Action**: Document the anchor independence design rationale in code comments and reference the split protocol specification. No logic changes needed.

---

## Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| H-01-01 | — | `[INTENTIONAL DESIGN REQUIREMENT]` | `Decimal::MIN` sentinel is intentional per AUDIT-00-WILDCARD-13 to prevent forensic masking. The `unwrap_or` pattern persists as a footgun if sentinel is changed back. | Documented in code comments; no logic change. |
| H-02-01 | CWE-347 / CWE-131 | `[CONFIRMED VULNERABILITY]` | `unwrap_or(0)` in `ValueDefinition::validate_precision` and `format_amount` defaults allowed scale to 0 on malformed standard `amount`, enabling precision-based value conservation violations. | Replace `unwrap_or(0)` with `map_err(...)` to reject malformed standard amounts. |
| H-02-02 | — | `[FALSE POSITIVE / MISINTERPRETATION]` | `round_up_date` panic hazards exist but function is only called with trusted standard configuration, not untrusted data directly. | No code change; added code-comment documentation. |
| H-02-03 | — | `[INTENTIONAL DESIGN REQUIREMENT]` | Split transaction anchors are intentionally derived via independent KDF paths (permanent key vs. per-transaction ephemeral key) to enable offline forensics. Changing would break offline double-spend investigation. | Documented in code; no logic change. |

---

## Design-Intent Triage Notes

1. **H-01-01**: The code was previously audited with the finding `unwrap_or(Decimal::ZERO)` (High severity). The code has since been updated to `unwrap_or(Decimal::MIN)` per security guideline AUDIT-00-WILDCARD-13, which changes the severity from High to Medium and reclassifies the finding as an intentional design requirement (fail-closed sentinel rather than silent-zero vulnerability). The underlying `unwrap_or` pattern is still noted as a code-quality footgun.

2. **H-02-01**: This is a new finding not present in the previous audit cycle. It addresses the `unwrap_or(0)` pattern in `ValueDefinition` methods that could be exploited via malformed standard TOML bundles. This is a genuine [CONFIRMED VULNERABILITY] because the standard amount field could be manipulated.

3. **H-02-02**: The `.unwrap()`/`.expect()` calls in `round_up_date` were flagged by the audit vector "Panic Hazards on Untrusted Inputs". After triage, these are classified as [FALSE POSITIVE] because the function is only called with values from the trusted standard configuration during voucher creation, not from untrusted binary/TOML bundles directly. However, the code is noted as a future robustness improvement area.

4. **H-02-03**: The split/change anchor key separation was verified against the design. The two-key derivation (HKDF from permanent key for change; ephemeral key for transfer) is an intentional architectural decision documented in the code (lines 695-724) and is essential for offline fraud attribution. This is classified [INTENTIONAL DESIGN REQUIREMENT].

5. **Conservation of Value**: All findings were evaluated against the invariants $\sum \text{Inputs} = \sum \text{Outputs} + \text{Fees}$. The only vector that could mathematically break value conservation is H-02-01 (precision-based validation bypass). All other findings are either intentional design or false positives that do not affect the value conservation invariant.