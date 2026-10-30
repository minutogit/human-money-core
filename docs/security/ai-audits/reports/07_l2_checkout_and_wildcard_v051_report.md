# Adversarial Security Audit Report — Module 07 (L2 Checkout Z01/Z08/Z10, 14/20-BFT Quorum, Send-Intents) & Module 00 Wildcard (Cross-Subsystem Backup / Crash-Atomic Desyncs)

**Target Version:** `human-money-core` v0.5.1 (with sibling `humoco-proto`)  
**Scope:** `src/app_service/checkout.rs`, `src/app_service/l2_intents.rs`, `src/wallet/l2_intents.rs`, `src/models/l2_intent.rs`, `src/services/l2_gateway.rs`, `src/services/l2_causality.rs`, `src/models/layer2_api.rs`, `src/wallet/reconciliation.rs`, `src/wallet/transactions.rs`, `src/app_service/backup_ops.rs`, `src/app_service/storage_ops.rs`, `src/app_service/orchestrator.rs`, `src/storage/wallet_transaction.rs`, and `../humoco-proto/src/{live.rs, mesh.rs, verify.rs, causal.rs}`.

---

## Executive Summary of Verified Findings

| ID | Severity | Focus Area | Title | Primary Location |
|---|---|---|---|---|
| **AUDIT-07-01** | **CRITICAL** | Area 4 (Wildcard Backup <-> L2) | `Wallet::build_voucher_status_query` Queries Incoming/Root Tag Instead of Outgoing Spend `ds_tag` + Unverified `reconcile_voucher_state` -> Disappearing Unspent Vouchers AND Silent Honest-User Double-Spend / DID Deanonymization on Backup Restore | `src/wallet/reconciliation.rs:35-76, 91-119`, `src/app_service/backup_ops.rs:486-491` |
| **AUDIT-07-02** | **CRITICAL** | Area 1 (Z01 Checkout Release) | `AppService::complete_checkout_purchase` Mints `DurablePurchaseBinding` (`can_release_goods_automatically = true`) Even When L1 Double-Spend Ingress Immediately Quarantines the Imported Voucher | `src/app_service/checkout.rs:335-363`, `src/wallet/transactions.rs:510-555` |
| **AUDIT-07-03** | **HIGH** | Area 2 (Z10 Send-Intents) | Unoccupied L2 Slot (`child_lock == [0u8; 32]`) Falsely Terminates `L2SendIntent` as `Conflicted`, Split-Change Outputs Stay `Active` After Real `Conflicted` Resolution, and `Confirmed` Prepared Intents Permanently Lock Funds | `src/app_service/l2_intents.rs:328-355`, `src/wallet/transactions.rs:883-896, 988-998`, `src/wallet/l2_intents.rs:9-12` |
| **AUDIT-07-04** | **HIGH** | Area 2 (Z08/Z10 Intents & Skew) | Premature Pruning of Unresolved `L2SendIntent`s Under Clock Skew / Grace Window, Missing Challenge TTL + Concurrent Renewal Overwrite Race, and Idle Write Amplification | `src/app_service/l2_intents.rs:189-258, 284-288, 377-437`, `src/wallet/l2_intents.rs:13-28` |
| **AUDIT-07-05** | **HIGH** | Area 4 & Area 1 (Backup <-> Checkout) | Differential Backup Clones In-Flight `CheckoutPurchase` Across Devices -> Double Automatic Goods Release (`newly_committed == true` Twice); Rollback Reconciliation Overwrites `Quarantined` Status to `Archived` | `src/app_service/backup_ops.rs:463-495`, `src/app_service/checkout.rs:247-257, 307-357`, `src/app_service/storage_ops.rs:359-372` |
| **AUDIT-07-06** | **HIGH** | Area 1 & Area 2 (Z01/Z08 Capability) | `CheckoutReleaseVerdict` Exposes `pub` Fields + `#[derive(Deserialize)]` Bypassing `DurablePurchaseBinding`, and Completed-Replay Fast Paths Skip Fork-Lock & Post-Import Quarantine Checks | `src/models/layer2_api.rs:621-629`, `src/app_service/checkout.rs:66-96, 287-301` |
| **AUDIT-07-07** | **HIGH** | Area 3 (Quorum Adapter) | `evaluate_multi_node_anchor_verdicts` Falls Back to `verdicts.first()` (Quorum = 1) on Split Responses and Accepts Unverified Lock Entries / Divergent `remote_t_id`s | `src/services/l2_gateway.rs:1018-1136` |
| **AUDIT-07-08** | **MEDIUM** | Area 3 (14/20 Quorum Adapter) | `process_l2_verdict_with_authority` & `verify_checkout_response_with_authority` Bypass Committee Quorum When Unsigned `quorum_certificate` Is Omitted or `L2Verdict::Ok` Is Sent, While Canonical `L2Verdict::Confirmed { proof }` Always Fails | `src/services/l2_gateway.rs:598-606, 728-769, 832-835`, `src/models/layer2_api.rs:426-455`, `src/app_service/conflicts.rs:340-355` |
| **AUDIT-07-09** | **MEDIUM** | Area 4 (Crash-Atomic / Orchestrator) | `update_seal_after_state_change` Commits Without Undo Journal or Commit Marker (Bricking Wallet on Seal Error), Failed-Commit Recovery Drops `StateMergeHook` RAM State & Ignores Seal Gate, and `execute_seal_with_policy` / `compare_remote_seal` Leave Torn State | `src/app_service/storage_ops.rs:234-240, 659-679, 905-930`, `src/app_service/orchestrator.rs:338-365, 414-449, 520-560` |

---

## Detailed Vulnerability Reports

---

### [AUDIT-07-01] `Wallet::build_voucher_status_query` Queries Incoming/Root Tag Instead of Outgoing Spend `ds_tag` + Unverified `reconcile_voucher_state` -> Disappearing Unspent Vouchers AND Silent Honest-User Double-Spend / DID Deanonymization on Backup Restore

- **Severity:** `CRITICAL`
- **CWE:** CWE-840 (Business Logic Errors), CWE-345 (Insufficient Verification of Data Authenticity)
- **Exact File & Line Numbers:**
  - `src/wallet/reconciliation.rs:35-76` (`Wallet::build_voucher_status_query`, specifically line `59`: `let challenge_ds_tag = l2_gateway::derive_challenge_tag(last_tx)?;`)
  - `src/wallet/reconciliation.rs:91-119` (`Wallet::reconcile_voucher_state`)
  - `src/app_service/backup_ops.rs:486-491` (`restore_backup` emitting `status_queries`)
  - `src/app_service/conflicts.rs:236-246` (`AppService::build_voucher_status_query` / `reconcile_voucher_state`)
  - `src/app_service/storage_ops.rs:334-376` (`reconcile_rollback_with_diagnostics`)

#### Mechanics & Root Cause
Tier-2 voucher reconciliation (`POST /v1/status`) is explicitly designed to protect honest users restoring a differential backup from spending outputs that were already spent on Device A after the backup was created (`src/wallet/reconciliation.rs:11-18`).

However, `Wallet::build_voucher_status_query` (`src/wallet/reconciliation.rs:53-59`) computes `challenge_ds_tag` by calling `l2_gateway::derive_challenge_tag(last_tx)` on the **current tip transaction** $T_k$ held in the wallet:
1. **Case 1 — Any received or split-change voucher (`transactions = [T_0, ..., T_k]`, $k \ge 1$):**
   `derive_challenge_tag(T_k)` (`src/services/l2_gateway.rs:233-242`) returns `T_k.trap_data.ds_tag`. That tag is `get_ds_tag(hash(T_{k-1}), sender_ephemeral_pub(T_k))` — the **INCOMING collision slot** that $T_k$ *itself* occupied when the voucher was transferred to the user!
   - When the user later spends this voucher in $T_{k+1}$, `wallet/transactions.rs:815-828` registers $T_{k+1}$ under a **completely different collision slot**:
     $$\text{outgoing\_ds\_tag}(T_k) = \text{get\_ds\_tag}\big(\text{get\_hash}(\text{to\_canonical\_json}(T_k)),\ \text{bs58}(\text{holder\_ephemeral\_pub}(T_k))\big)$$
     where `holder_ephemeral_pub(T_k)` is derived via `self.rederive_secret_seed(&instance.voucher, identity)?.verifying_key()` (note `identity: &UserIdentity` is not even passed into `build_voucher_status_query`!).
2. **Case 2 — Freshly minted (`init`) genesis voucher (`transactions = [T_0]`):**
   `derive_challenge_tag(T_0)` returns `T_0.t_id` (the genesis root proof tag). As documented at `src/services/l2_gateway.rs:1149-1150`, *"Genesis is only a root proof and never occupies a collision slot"*. When Device A spends $T_0 \to T_1$, $T_1$ occupies `get_ds_tag(get_hash(to_canonical_json(T_0)), sender_ephemeral_pub(T_0))`, **not** `T_0.t_id`!
3. **Compounding Missing Verification in `reconcile_voucher_state` (`src/wallet/reconciliation.rs:112-117`):**
   `reconcile_voucher_state` never calls `l2_gateway::verify_lock_entry_proof(...)` and never checks `lock.t_id != local_last_tx_t_id`. Any `Some(lock)` immediately transitions the voucher to `VoucherStatus::Archived`!

*(Why existing tests missed this: `tests/l2_wallet_safety_tests.rs:213-241` fabricated a synthetic `child_lock` struct directly in memory without running `derive_challenge_tag` against a real L2 spend table.)*

#### Step-by-Step Reproduction Scenario
- **Scenario A (Disappearing Unspent Funds — 100% False Positive):**
  1. Alice receives a 100-unit voucher `[T_0, T_1]` from Bob; `T_1` was anchored on Layer 2 under `T_1.trap_data.ds_tag` (`lock.t_id == T_1.t_id`). Alice has **never spent** this voucher.
  2. Alice creates a differential backup, then restores it on Device B via `AppService::restore_backup` (`backup_ops.rs:486-491`).
  3. Device B executes the returned `status_queries[0]`, querying `challenge_ds_tag == T_1.trap_data.ds_tag`.
  4. Layer 2 returns HTTP 200 `Some(lock_for_T_1)` because `T_1` itself occupies that slot.
  5. Device B passes `Some(&lock_for_T_1)` to `reconcile_voucher_state` (or `reconcile_rollback_with_diagnostics`), which immediately marks Alice's **unspent** voucher `VoucherStatus::Archived` (`AlreadySpent { successor_t_id: T_1.t_id }`). Alice's funds vanish!
- **Scenario B (Silent Honest-User Self-Double-Spend & DID Deanonymization — False Negative):**
  1. Alice mints genesis voucher `[T_0]` (or holds unanchored `[T_0, T_1]`), creates a differential backup, and then spends `[T_0] -> T_1` online on Device A (`T_1` is anchored on L2 under `outgoing_ds_tag(T_0)`).
  2. Device A dies; Alice restores the backup on Device B. `restore_backup` queries `T_0.t_id` instead of `outgoing_ds_tag(T_0)`.
  3. L2 collision lock lookup for `ds_tag == T_0.t_id` returns `None` (404 — genesis root is not a spend collision lock; or if root is returned, `T_1` on `outgoing_ds_tag(T_0)` is never checked).
  4. `reconcile_voucher_state` returns `UnspentSafe`, leaving `[T_0]` `Active`. Honest Alice spends `[T_0] -> T_1'` on Device B, producing a genuine L1 double-spend (`T_1` vs `T_1'`) whose SST V4 trap algebraically recovers and blacklists Alice's `did:key`!

#### Exact Fix (Respecting L1 Sovereignty)
Keep L1 transaction schemas untouched. Fix `Wallet::build_voucher_status_query` and `Wallet::reconcile_voucher_state` in `src/wallet/reconciliation.rs` (and thread `&UserIdentity` from `AppService` in `backup_ops.rs:488` and `conflicts.rs:238`):
1. Compute the **next outgoing spend `ds_tag`** from `last_tx` and the holder's derived ephemeral signing key for `instance.voucher`:
   ```rust
   let prev_hash = crate::services::crypto_utils::get_hash(
       crate::services::crypto_utils::to_canonical_json(last_tx)?,
   );
   let holder_ephem_signing_key = self.rederive_secret_seed(&instance.voucher, identity)?;
   let holder_ephem_pub_bs58 = bs58::encode(
       holder_ephem_signing_key.verifying_key().to_bytes()
   ).into_string();
   let challenge_ds_tag = crate::services::double_spend_detection::get_ds_tag(
       &prev_hash,
       &holder_ephem_pub_bs58,
   );
   ```
2. In `Wallet::reconcile_voucher_state` (take `identity: &UserIdentity`), recompute `(expected_voucher_id, expected_ephem_pub_bs58, expected_outgoing_ds_tag)` and before archiving on `Some(lock)`:
   - Require `bs58::encode(lock.t_id).into_string() != last_tx.t_id`.
   - Call `l2_gateway::verify_lock_entry_proof(lock, &expected_voucher_id, Some(&expected_ephem_pub_bs58), &expected_outgoing_ds_tag)?` so an unauthenticated/forged HTTP 200 response cannot archive active funds (DoS).

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_01_backup_restore_queries_outgoing_ds_tag_not_incoming_or_genesis_tag() {
    // 1. Mint voucher V on Bob, transfer V (T0 -> T1) to Alice, generate L2LockRequest for T1
    //    and store L2LockEntry(T1) in a mock L2 map keyed by lock_request.ds_tag.
    // 2. On Alice's wallet (holding unspent [T0, T1]), call build_voucher_status_query:
    //    ASSERT query.challenge_ds_tag != T1.trap_data.unwrap().ds_tag;
    //    Lookup query.challenge_ds_tag in mock L2 map -> None -> reconcile_voucher_state -> UnspentSafe!
    // 3. Now Alice spends [T0, T1] -> T2 on Device A; insert L2LockEntry(T2) into mock L2 map
    //    keyed by lock_request_T2.ds_tag.
    // 4. Restore pre-T2 backup on Device B; run build_voucher_status_query:
    //    ASSERT query.challenge_ds_tag == lock_request_T2.ds_tag.unwrap();
    //    Lookup returns Some(L2LockEntry(T2)) -> reconcile_voucher_state -> AlreadySpent -> Archived!
    // 5. Repeat steps 3-4 for a 1-tx genesis voucher [T0] spent in T1.
}
```

---

### [AUDIT-07-02] `AppService::complete_checkout_purchase` Mints `DurablePurchaseBinding` (`can_release_goods_automatically = true`) Even When L1 Double-Spend Ingress Immediately Quarantines the Imported Voucher

- **Severity:** `CRITICAL`
- **CWE:** CWE-840 (Business Logic Errors), CWE-367 (TOC/TOU / Layer Mismatch Between L2 Final-Hop Attestation and L1 Multi-Hop ProofChain Ingress)
- **Exact File & Line Numbers:**
  - `src/app_service/checkout.rs:335-363` (`complete_checkout_purchase`)
  - `src/wallet/transactions.rs:357, 510-555` (`process_bundle_with_registry_inner` -> `check_for_double_spend` -> `handle_conflicts_and_quarantine`)
  - `src/wallet/conflicts/ingress.rs:822-865` (`handle_conflicts_and_quarantine` — sets losing instance to `VoucherStatus::Quarantined` and returns `Ok(())`)

#### Mechanics & Root Cause
`begin_checkout_purchase` / `complete_checkout_purchase` constructs `LiveStateContext` over **only the final transaction `last`** (`parent_lock = blake3(last.ds_tag)`, `child_lock = last.t_id`, `src/app_service/checkout.rs:199-245`). After `verify_live_state_proof` succeeds on line `335`, `complete_checkout_purchase` imports the L1 bundle (`checkout.rs:336-352`):
```rust
let outcome = wallet.process_bundle_with_registry_inner(
    identity, bundle_data, None, &registry, Some(epoch_start.as_str()), epoch, false,
)?;
if outcome.involved_vouchers.len() != 1 {
    return Err(invalid("purchase did not import exactly one voucher"));
}
if !wallet.profile.mark_checkout_purchase_completed(purchase_id) {
    return Err(invalid("purchase disappeared"));
}
Ok(true)
```
By explicit offline-first L1 design (`src/wallet/conflicts/ingress.rs:822-824`), **`process_bundle_with_registry_inner` does NOT return `Err` when a double-spend is detected**! Instead, it imports the conflicting voucher to capture cryptographic fraud evidence, runs `check_for_double_spend`, transitions the losing voucher to **`VoucherStatus::Quarantined`** ("Earliest Wins", since `conflict.layer2_verdict` is `None`), populates `outcome.check_result.verifiable_conflicts` / `unverifiable_warnings`, and returns `Ok(ProcessBundleResult)` with `outcome.involved_vouchers.len() == 1`!

Because `complete_checkout_purchase` never inspects `outcome.check_result` and never checks `wallet.voucher_store.vouchers[&outcome.involved_vouchers[0]].status == VoucherStatus::Active`, it commits `purchase.completed = true` and unconditionally returns:
```rust
CheckoutReleaseVerdict::new(L2ProcessingOutcome::Confirmed, false)
    .with_durable_purchase_binding(DurablePurchaseBinding::backend_verified())
```
yielding `can_release_goods_automatically == true` and `is_goods_release_authorized == true` for a **Quarantined, unspendable double-spend**!

#### Step-by-Step Reproduction Scenario
1. Attacker holds voucher $V$ (`[T_0]`, 100 units) and sends $T_0 \to T_1$ (timestamp $t_1$) **offline** to Merchant M (e.g., manual counter payment or background P2P sync via `receive_bundle`, never anchored on L2; or Merchant M received gossip fingerprints for an ancestor hop $T_0 \to T_1$ while attacker presents 2-hop $T_0 \to T_1' \to T_2$ where $T_2$'s parent $T_1'$ is fresh on L2).
2. Attacker walks up to Merchant M's automated PoS terminal with conflicting spend $T_0 \to T_1'$ (timestamp $t_2 > t_1$) and anchors $T_1'$ on Layer 2. Because offline $T_1$ never touched L2 (or in the 2-hop case $T_1' \to T_2$ has an uncontested final parent $T_1'$), 14/20 shard nodes sign a genuine `LiveStateProof` for the final hop.
3. Merchant M's PoS calls `begin_checkout_purchase("pos-1", bundle_T1_prime, ...)` and `complete_checkout_purchase("pos-1", bundle_T1_prime, &proof, ...)`.
4. Inside `complete_checkout_purchase`, `process_bundle_with_registry_inner` detects the `ds_tag` collision against `own_fingerprints`/`known_fingerprints`, marks the newly imported `T_1'` instance **`VoucherStatus::Quarantined`**, and returns `Ok(outcome)` with `involved_vouchers.len() == 1`.
5. `complete_checkout_purchase` marks `"pos-1"` completed and returns `Confirmed` with `DurablePurchaseBinding` (`can_release_goods_automatically == true`). The automated PoS releases goods a second time even though Merchant M's wallet immediately quarantined the payment!

#### Exact Fix
In `src/app_service/checkout.rs:345-351`, strictly enforce that zero double-spend conflicts/warnings occurred AND the imported voucher instance is `VoucherStatus::Active` before marking the purchase completed or minting `DurablePurchaseBinding` (rolling back or returning a fail-closed error / `Quarantined` verdict without `DurablePurchaseBinding` if violated):
```rust
if outcome.involved_vouchers.len() != 1 {
    return Err(invalid("purchase did not import exactly one voucher"));
}
if !outcome.check_result.verifiable_conflicts.is_empty()
    || !outcome.check_result.unverifiable_warnings.is_empty()
{
    return Err(invalid("purchase voucher triggered double-spend conflict"));
}
let imported_id = &outcome.involved_vouchers[0];
let imported_active = wallet
    .voucher_store
    .vouchers
    .get(imported_id)
    .is_some_and(|inst| matches!(inst.status, crate::wallet::instance::VoucherStatus::Active));
if !imported_active {
    return Err(invalid("imported purchase voucher is not active"));
}
```
*(Optional forensic enhancement: if the merchant wishes to retain the fraud proof on disk while still failing closed on goods release, commit the quarantined voucher + conflict proof without setting `purchase.completed = true` and return `CheckoutReleaseVerdict::new(L2ProcessingOutcome::Quarantined { .. }, false)` with `newly_committed: false` and NO `DurablePurchaseBinding`.)*

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_02_complete_checkout_fails_closed_when_l1_import_quarantines_double_spend() {
    // 1. Setup sender S (snapshot before spend) and merchant M with RegionalMeshPolicy + 20-node committee.
    // 2. Branch 1 (t1): S sends voucher V -> M offline; M imports via receive_bundle (V is Active in M).
    // 3. Restore S from snapshot; Branch 2 (t2 > t1): S creates conflicting bundle_2 -> M.
    // 4. M calls begin_checkout_purchase("sale-ds", &bundle_2, &views, now_ms, pw).
    // 5. Sign valid 14/20 LiveStateProof over the returned LiveStateContext (simulating unanchored Branch 1 on L2).
    // 6. Call complete_checkout_purchase("sale-ds", &bundle_2, &proof, &views, &standards, now_ms + 100, pw):
    //    MUST return Err(SecurityViolation) (or Quarantined verdict with can_release_goods_automatically == false),
    //    NEVER Ok(completion) with completion.verdict.can_release_goods_automatically == true!
}
```

---

### [AUDIT-07-03] Unoccupied L2 Slot (`child_lock == [0u8; 32]`) Falsely Terminates `L2SendIntent` as `Conflicted`, Split-Change Outputs Stay `Active` After Real `Conflicted` Resolution, and `Confirmed` Prepared Intents Permanently Lock Funds

- **Severity:** `HIGH`
- **CWE:** CWE-840 (Business Logic Errors), CWE-667 (Improper Locking), CWE-672 (Operation on a Resource after Expiration or Release)
- **Exact File & Line Numbers:**
  - `src/app_service/l2_intents.rs:24-44` (`prepare_l2_send_intent`)
  - `src/app_service/l2_intents.rs:328-355` (`complete_intent_reconciliation`)
  - `src/wallet/transactions.rs:883-896, 988-998, 1059-1063` (`_execute_single_transfer` & `execute_multi_transfer_and_bundle_inner`)
  - `src/wallet/l2_intents.rs:9-12` (`Wallet::stage_l2_send_intent`)

#### Mechanics & Root Cause
Three tightly coupled state-machine bugs break Z10 terminal retained-choice reconciliation in `l2_intents`:

1. **Bug 3A — Unspent/Unoccupied Slot (`child_lock == [0u8; 32]`) Treated as Terminal `Conflicted` (`src/app_service/l2_intents.rs:328-351`):**
   `humoco_proto::live::validate_live_context` (`../humoco-proto/src/live.rs:41-55`) explicitly allows `child_lock == [0u8; 32]` (paired with `state_digest == [0u8; 32]`) to represent an **unoccupied** `parent_lock` slot on Layer 2.
   In `complete_intent_reconciliation` (`l2_intents.rs:328-351`), the `else` branch assumes *any* `proof.context.child_lock != request.transaction_hash` is a competing child transaction:
   ```rust
   } else {
       let expected_conflict_context = humoco_proto::live::LiveStateContext {
           child_lock: proof.context.child_lock,
           state_digest: proof.context.state_digest,
           ..expected_context
       };
       verify_live_state_proof(proof, &expected_conflict_context)...
       intent.retained_original_observed = false;
       IntentTerminalResolution::Conflicted {
           resolved_at_ms: now_ms,
           observed_child: hex::encode(proof.context.child_lock),
       }
   }
   ```
   When the sender's original L2 write timed out in transit before reaching the shard, 14/20 honest nodes attest that `parent_lock` currently has **no child** (`child_lock = [0u8; 32]`, `state_digest = [0u8; 32]`). `complete_intent_reconciliation` verifies that valid 14/20 proof and **permanently terminates the intent as `Conflicted { observed_child: "0000...0000" }`**, preventing the wallet from re-submitting `intent.request_bytes`!

2. **Bug 3B — Split-Change Remainder Stays `Active` & Spendable Both While Parent Intent Is Unresolved AND After Parent Intent Terminates as `Conflicted` (`src/wallet/transactions.rs:883-896, 1059-1063`, `src/app_service/l2_intents.rs:336-354`):**
   During a partial split (`create_transfer_bundle_with_l2_intents`, e.g., sending `10` out of `100` as in `reconciliation_fixture` at `l2_intents.rs:838-854`), `_execute_single_transfer` removes source `L0`, appends split transaction `T1`, and inserts the `90` remainder into `wallet.voucher_store.vouchers` under a **new `local_instance_id` `L1`** with **`VoucherStatus::Active`**, while `stage_l2_send_intent` keys the intent under **`L0`**.
   - While `L0`'s intent (`T1`) is unresolved, `transactions.rs:988` only checks `l2_send_intents.contains_key(&source.local_instance_id)`, so `L1` is freely spendable (`T1 -> T2`) before `T1` is confirmed.
   - Worse: when `complete_intent_reconciliation` / `record_intent_conflict` proves via 14/20 quorum that `T1` **lost** on Layer 2 to a competing spend `T1'` (`IntentTerminalResolution::Conflicted`), `complete_intent_reconciliation` marks `l2_send_intents[L0]` as `Conflicted` **without quarantining `L1`**! The wallet continues showing `90` phantom spendable balance (`Active`) on a quorum-rejected branch.

3. **Bug 3C — `Confirmed` Output Prepared via `prepare_l2_send_intent` Is Permanently Blocked from Spending & Stale Intent Is Reused (`src/wallet/transactions.rs:988-998`, `src/wallet/l2_intents.rs:9-12`):**
   - `AppService::prepare_l2_send_intent(local_id, ...)` (`l2_intents.rs:24-44`) stages an intent on an **active** voucher output `local_id` (e.g., anchoring a genesis/received output). Once reconciled to `IntentTerminalResolution::Confirmed`, the resolved intent remains in `wallet.profile.l2_send_intents` for retention.
   - However, `execute_multi_transfer_and_bundle_inner` (`src/wallet/transactions.rs:988-998`) checks:
     ```rust
     if temp_wallet.profile.l2_send_intents.contains_key(&source.local_instance_id) {
         return Err(VoucherCoreError::Transaction(
             TransactionError::InvalidSourceVoucherStatus {
                 local_id: source.local_instance_id.clone(),
                 status: "Output has an unresolved durable L2 send intent".to_string(),
             },
         ));
     }
     ```
     It checks `contains_key` **without checking `intent.terminal_resolution.is_none()`**! Thus `unresolved_l2_send_intents()` returns `[]`, yet every attempt to spend `local_id` fails with `"Output has an unresolved durable L2 send intent"`!
   - And if `transactions.rs:988` were relaxed without also fixing `Wallet::stage_l2_send_intent` (`src/wallet/l2_intents.rs:9-12`: `if let Some(existing) = self.profile.l2_send_intents.get(local_id) { return Ok(existing.clone()); }`), spending `local_id` via `create_transfer_bundle_with_l2_intents` would return the **old `Confirmed` genesis intent** instead of staging the new outgoing spend's `L2LockRequest`!

#### Step-by-Step Reproduction Scenario
1. **3A:** Call `create_transfer_bundle_with_l2_intents` (10 of 100), advance 31s, call `begin_intent_reconciliation`, sign a 14/20 `LiveStateProof` with `child_lock = [0u8; 32], state_digest = [0u8; 32]`, and call `complete_intent_reconciliation` -> returns `Ok(Conflicted { observed_child: "0000...0000" })` on an unspent slot!
2. **3B:** Call `record_intent_conflict` with a real competing `child_lock = [0x99; 32]` -> returns `Ok(Conflicted { .. })`, then inspect `service.get_voucher_summaries(None, None)`: the `90` split-change voucher `L1` is still `VoucherStatus::Active` and can be spent!
3. **3C:** Mint voucher `L0`, call `prepare_l2_send_intent(&L0, Mainnet, pw)`, reconcile to `Confirmed`, then call `create_transfer_bundle` -> fails with `"Output has an unresolved durable L2 send intent"`.

#### Exact Fix
1. **In `complete_intent_reconciliation` (`src/app_service/l2_intents.rs:335`):** Explicitly reject or handle `proof.context.child_lock == [0u8; 32]`: do **not** mark `Conflicted`. Either return an error (`"parent slot is still unoccupied on Layer 2; retry original intent submission"`) while keeping `terminal_resolution = None` so the caller re-broadcasts `intent.request_bytes`, or return a dedicated non-terminal status. Also reject `proof.context.state_digest == [0u8; 32]` in the `Conflicted` branch (`humoco_proto::live::validate_live_context` already requires `child_lock != [0; 32] <=> state_digest != [0; 32]`, so rejecting `child_lock == [0; 32]` enforces both).
2. **In `L2SendIntent` (`src/models/l2_intent.rs`) + `transactions.rs` + `complete_intent_reconciliation`:** Record `created_change_local_id: Option<String>` (or match `v.voucher.transactions.last().t_id == tx.t_id` from `intent.transaction_bytes`). Block spending `created_change_local_id` while its parent intent has `terminal_resolution.is_none()`, and when the parent intent resolves to `IntentTerminalResolution::Conflicted`, immediately transition that split-change voucher to `VoucherStatus::Quarantined` inside the same `with_transactional_mut` commit!
3. **In `src/wallet/transactions.rs:988` & `src/wallet/l2_intents.rs:9-12`:**
   - In `transactions.rs:988`, block when `l2_send_intents.get(&source.local_instance_id)` has `terminal_resolution.is_none()` OR `matches!(terminal_resolution, Some(IntentTerminalResolution::Conflicted { .. }))`, allowing `Some(Confirmed { .. })` outputs (from `prepare_l2_send_intent`) to be spent.
   - In `stage_l2_send_intent` (`src/wallet/l2_intents.rs:9-12`), only reuse `existing` if `existing.terminal_resolution.is_none()` AND `existing_tx.t_id == tx.t_id`; if `existing` is a resolved `Confirmed` intent for an earlier `t_id`, archive/replace it with the new spend's `L2SendIntent`.

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_03_zero_child_lock_rejected_split_change_quarantined_and_confirmed_spendable() {
    // Part A: Proof with child_lock = [0u8; 32], state_digest = [0u8; 32] passed to
    // complete_intent_reconciliation MUST NOT produce IntentTerminalResolution::Conflicted.
    // Part B: Real competing child_lock = [0xAB; 32] passed to record_intent_conflict MUST
    // transition the 90-unit split-change voucher instance from Active to Quarantined.
    // Part C: prepare_l2_send_intent on genesis voucher -> reconcile to Confirmed ->
    // create_transfer_bundle_with_l2_intents MUST succeed and stage the new T1 spend intent.
}
```

---

### [AUDIT-07-04] Premature Pruning of Unresolved `L2SendIntent`s Under Clock Skew / Grace Window, Missing Challenge TTL + Concurrent Renewal Overwrite Race, and Idle Write Amplification

- **Severity:** `HIGH`
- **CWE:** CWE-672 (Operation on a Resource after Expiration or Release), CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **Exact File & Line Numbers:**
  - `src/app_service/l2_intents.rs:403-437` (`cleanup_terminal_intents`, lines `412, 424-427`)
  - `src/wallet/l2_intents.rs:13-28` (`Wallet::stage_l2_send_intent`, inline pruning at line `25`)
  - `src/app_service/l2_intents.rs:189-258` (`begin_intent_reconciliation`)
  - `src/app_service/l2_intents.rs:274-288` (`complete_intent_reconciliation`)
  - `src/app_service/l2_intents.rs:377-399` (`expire_intent_if_overdue`)

#### Mechanics & Root Cause
1. **Premature Pruning of Unresolved Intents (`l2_intents.rs:412, 424` & `wallet/l2_intents.rs:25`):**
   Despite its name and doc-comment (*"Cleans up terminally resolved intents"*), `cleanup_terminal_intents` deletes **unresolved** intents (`intent.terminal_resolution.is_none()`) whenever `now_ms >= intent.root_valid_until_ms.saturating_add(30_000)` (`l2_intents.rs:424-426`). Worse, `Wallet::stage_l2_send_intent` (`src/wallet/l2_intents.rs:25`) runs the exact same unconditional `retain` using **unauthenticated local wall-clock** `current_unix_timestamp_ms()`!
   - If the device clock jumps forward (NTP glitch / user timezone/date tweak) or the app was offline across `root_valid_until_ms + 30_000`, staging any unrelated transfer or calling `cleanup_terminal_intents` **silently deletes unresolved `L2SendIntent`s** (and also deletes `Conflicted` audit records before `max_retain_ms` has elapsed!).
   - Once the clock is corrected back before `root_valid_until_ms`, any active output previously locked by `prepare_l2_send_intent` has lost its durable intent lock and can be spent into a fresh replacement transaction — breaking the Z10 retained-original-choice invariant!
2. **Missing Challenge TTL & Unconditional Challenge Overwrite Race (`l2_intents.rs:189-258`):**
   Compare `begin_checkout_purchase` (`checkout.rs:131-180`) with `begin_intent_reconciliation` (`l2_intents.rs:189-258`):
   - `begin_checkout_purchase` enforces a 30s `CHECKOUT_CHALLENGE_TTL_MS`, preserves the active `recipient_nonce` across intra-TTL retries and IA02 committee refreshes (`checkout.rs:131-152`), and returns `Ok(purchase.context)` without mutating when `purchase.completed`.
   - `begin_intent_reconciliation` has **no `challenge_expires_at_ms`** (a single `stored_challenge` remains valid for **years** until `root_valid_until_ms`!), **unconditionally overwrites `current.stored_challenge = Some(nonce)`** on every invocation (causing any in-flight quorum poll or IA02 committee refresh retry to fail with `"reconciliation challenge mismatch"`), and still mutates `stored_challenge` even if `current.terminal_resolution.is_some()`!
3. **Unauthenticated `now_ms` Commits `Expired` Before Proof Verification + Idle Disk Rewrite (`l2_intents.rs:275, 284-288, 383-398`):**
   - In `complete_intent_reconciliation` (`l2_intents.rs:284-288`), if caller-supplied `now_ms >= intent.root_valid_until_ms`, it commits `IntentTerminalResolution::Expired` **before** calling `verify_live_state_proof` and leaves `intent.stored_challenge` set (`Some(...)`), even if `proof` was a valid `Confirmed` quorum proof obtained 100ms before expiry!
   - In `expire_intent_if_overdue` (`l2_intents.rs:385, 388, 396`) and `complete_intent_reconciliation` (`l2_intents.rs:275`), no-op branches return `TransactionOutcome::Commit(...)` instead of `TransactionOutcome::Abort(...)`, triggering a full encrypted wallet disk rewrite, undo journal cycle, and `WalletSeal.tx_nonce` increment on every idle poll!

#### Step-by-Step Reproduction Scenario
1. Wallet prepares an L2 intent on `L0` (`root_valid_until_ms = T_exp`).
2. Local system clock temporarily skews forward past `T_exp + 30_000`; user creates a transfer on an unrelated voucher `L_other` via `create_transfer_bundle_with_l2_intents`.
3. `stage_l2_send_intent` (`wallet/l2_intents.rs:25`) silently prunes `L0`'s unresolved `L2SendIntent`!
4. Clock skew corrects to `< T_exp`; `L0` is now unlocked and can be spent into a brand-new conflicting transaction `T_1'` instead of retaining `T_1`.

#### Exact Fix
1. **Never delete `terminal_resolution.is_none()` intents in `cleanup_terminal_intents` or `stage_l2_send_intent`!** Require an explicit terminal state (`intent.terminal_resolution.is_some()`) AND `now_ms >= terminal_resolved_at(res).saturating_add(max_retain_ms)` before pruning. Unresolved intents past `root_valid_until_ms` must transition to `IntentTerminalResolution::Expired` first (preserving audit retention for `max_retain_ms`) rather than silently vanishing.
2. Add `challenge_expires_at_ms: Option<u64>` (30s TTL) and `stored_committee: Option<[[u8; 32]; 20]>` to `L2SendIntent` (`#[serde(default)]`):
   - In `begin_intent_reconciliation`, reject or return early with `TransactionOutcome::Abort` if `terminal_resolution.is_some()`; if `now_ms < challenge_expires_at_ms`, preserve `stored_challenge` while refreshing `stored_committee` on IA02 view rotation (matching `begin_checkout_purchase`).
   - In `complete_intent_reconciliation`, enforce `now_ms < challenge_expires_at_ms` and verify `proof` before falling back to `Expired`.
3. Change no-op paths in `expire_intent_if_overdue` (`l2_intents.rs:385, 388, 396`) and `complete_intent_reconciliation` (`l2_intents.rs:275`) from `TransactionOutcome::Commit` to `TransactionOutcome::Abort`.

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_04_unresolved_intent_survives_clock_skew_pruning_and_concurrent_ia02_refresh() {
    // 1. Stage unresolved intent on L0; call cleanup_terminal_intents(86_400_000, root_valid_until_ms + 60_000, pw):
    //    ASSERT unresolved intent is NOT deleted without terminal resolution + max_retain_ms.
    // 2. Call begin_intent_reconciliation at t = created + 31_000 -> ctx1;
    //    call begin_intent_reconciliation again at t = created + 35_000 with rotated RegionalMeshView -> ctx2:
    //    ASSERT ctx1.recipient_nonce == ctx2.recipient_nonce (intra-TTL IA02 refresh preserves challenge).
    // 3. Call complete_intent_reconciliation at t = created + 90_000 (> 30s TTL) without renewal:
    //    ASSERT Err(SecurityViolation("reconciliation challenge expired")).
    // 4. Record WalletSeal.tx_nonce before calling expire_intent_if_overdue when now_ms < root_valid_until_ms:
    //    ASSERT tx_nonce is UNCHANGED (Abort, not Commit).
}
```

---

### [AUDIT-07-05] Differential Backup Clones In-Flight `CheckoutPurchase` Across Devices -> Double Automatic Goods Release (`newly_committed == true` Twice); Rollback Reconciliation Overwrites `Quarantined` Status to `Archived`

- **Severity:** `HIGH`
- **CWE:** CWE-294 (Authentication Bypass by Capture-Replay), CWE-362 (Cross-Device Split-Brain State Desync)
- **Exact File & Line Numbers:**
  - `src/app_service/backup_ops.rs:463-495` (`AppService::restore_backup`)
  - `src/app_service/checkout.rs:247-257, 307-357` (`begin_checkout_purchase` & `complete_checkout_purchase`)
  - `src/app_service/storage_ops.rs:359, 364-368` (`AppService::reconcile_rollback_with_diagnostics`)

#### Mechanics & Root Cause
1. **Cross-Device Replay of Cloned In-Flight `CheckoutPurchase` (`backup_ops.rs:463-495` & `checkout.rs:307-357`):**
   `UserProfile.l2_checkout_purchases` (`src/models/profile.rs:265`) is serialized inside `profile.enc` and included verbatim in differential backups (`create_backup`).
   Suppose Merchant Device A starts a checkout (`begin_checkout_purchase("sale-77", bundle, ...)`), writing `CheckoutPurchase { completed: false, recipient_nonce: N_A, expires_at_ms: t0 + 30_000 }`, and a scheduled/automatic differential backup runs while `"sale-77"` is in flight.
   - Merchant Device A completes `"sale-77"` (`complete_checkout_purchase`), returning `newly_committed: true, can_release_goods_automatically: true` -> **Goods Release #1**.
   - Device B (failover PoS terminal / restored backup) calls `restore_backup` (`backup_ops.rs:463-495`) within the 30s window. `restore_backup` generates a brand-new `local_instance_id` and bumps the recovery epoch (`next_epoch`), **but leaves all `completed: false` entries in `restored_wallet.profile.l2_checkout_purchases` intact with Device A's `recipient_nonce: N_A`!**
   - Replaying the exact same `(purchase_id: "sale-77", bundle, LiveStateProof_over_N_A)` to Device B passes `verify_live_state_proof` (14/20 signatures over `N_A` are still valid!) and imports `bundle` on Device B, returning **`newly_committed: true, can_release_goods_automatically: true` a SECOND time** -> **Goods Release #2 for a single payment!**

2. **Rollback Reconciliation Overwrites `Quarantined` Vouchers to `Archived` (`src/app_service/storage_ops.rs:359-372`):**
   In `reconcile_rollback_with_diagnostics`:
   ```rust
   let quarantined_ids = Vec::new();
   ...
   for (vid, entry_opt) in voucher_verifications {
       if entry_opt.is_some()
           && let Some(inst) = wallet.voucher_store.vouchers.get_mut(&vid)
       {
           inst.status = crate::wallet::instance::VoucherStatus::Archived;
           archived_ids.push(vid.clone());
       }
   }
   ```
   It neither verifies `entry_opt` via `verify_lock_entry_proof`, nor preserves `VoucherStatus::Quarantined` (a quarantined double-spend forensic artifact is silently downgraded to `Archived`, hiding fraud status in UI, while `quarantined_voucher_ids` in `ReconciliationDiagnostics` is hardcoded to `Vec::new()`!).

#### Step-by-Step Reproduction Scenario
1. Merchant Device A calls `begin_checkout_purchase("pos-42", &bundle, &views, 1_000_000, pw)` -> `ctx` with `recipient_nonce = N_A`.
2. Device A calls `create_backup(pw)` -> `backup_bytes`.
3. Device A calls `complete_checkout_purchase("pos-42", &bundle, &proof_N_A, &views, &standards, 1_005_000, pw)` -> `Ok(c1)` with `c1.newly_committed == true` and `c1.verdict.can_release_goods_automatically == true`.
4. Failover Device B calls `restore_backup(&backup_bytes, pw)` and then `complete_checkout_purchase("pos-42", &bundle, &proof_N_A, &views, &standards, 1_010_000, pw)` -> `Ok(c2)` with **`c2.newly_committed == true` and `c2.verdict.can_release_goods_automatically == true`**!

#### Exact Fix
1. **In `AppService::restore_backup` (`src/app_service/backup_ops.rs:463`):** Strip all uncompleted (`!p.completed`) entries from `restored_wallet.profile.l2_checkout_purchases` (and clear any `stored_challenge` on restored `l2_send_intents`):
   ```rust
   restored_wallet
       .profile
       .l2_checkout_purchases
       .retain(|_, purchase| purchase.completed);
   for intent in restored_wallet.profile.l2_send_intents.values_mut() {
       intent.stored_challenge = None;
   }
   ```
   An uncompleted ephemeral 30s challenge generated on Device A must NEVER remain active on a newly restored Device B instance; Device B must issue a fresh `recipient_nonce` if a checkout is retried on Device B.
2. **In `reconcile_rollback_with_diagnostics` (`src/app_service/storage_ops.rs:359-372`):** Verify `L2LockEntry` proofs via `reconcile_voucher_state` (once fixed per `AUDIT-07-01`) and never overwrite `VoucherStatus::Quarantined` with `VoucherStatus::Archived` (populate `quarantined_ids` accurately instead).

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_05_restored_backup_invalidates_inflight_checkout_challenges() {
    // 1. Merchant A calls begin_checkout_purchase("sale-1", &bundle, &views, t0, pw) -> ctx.
    // 2. Merchant A calls create_backup(pw) -> backup_bytes.
    // 3. Merchant A completes "sale-1" with valid 14/20 proof over ctx -> newly_committed == true.
    // 4. Merchant B calls restore_backup(&backup_bytes, pw).
    // 5. Merchant B calls complete_checkout_purchase("sale-1", &bundle, &proof, &views, &standards, t0 + 5_000, pw):
    //    ASSERT Err(SecurityViolation("purchase challenge missing")) — NO second goods release!
}
```

---

### [AUDIT-07-06] `CheckoutReleaseVerdict` Exposes `pub` Fields + `#[derive(Deserialize)]` Bypassing `DurablePurchaseBinding`, and Completed-Replay Fast Paths Skip Fork-Lock & Post-Import Quarantine Checks

- **Severity:** `HIGH`
- **CWE:** CWE-668 (Exposure of Resource to Wrong Sphere), CWE-502 (Deserialization of Untrusted Data Into Capability Struct)
- **Exact File & Line Numbers:**
  - `src/models/layer2_api.rs:621-658` (`CheckoutReleaseVerdict` & `DurablePurchaseBinding`)
  - `src/app_service/checkout.rs:55-62, 66-96, 287-301` (`completed_checkout_completion`, `is_checkout_purchase_completed`, `replay_checkout_purchase`, and `complete_checkout_purchase` early fast-path)

#### Mechanics & Root Cause
1. **Struct Literal & Deserialization Bypass of `DurablePurchaseBinding` (`src/models/layer2_api.rs:621-629`):**
   `DurablePurchaseBinding` (`layer2_api.rs:631-658`) intentionally has a private `()` field and omits `Serialize`/`Deserialize` so that external callers or Tauri/IPC payloads cannot forge automatic goods-release capability (Z01).
   However, `CheckoutReleaseVerdict` itself (`layer2_api.rs:621-629`) is defined as:
   ```rust
   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
   pub struct CheckoutReleaseVerdict {
       pub outcome: L2ProcessingOutcome,
       pub can_release_goods_automatically: bool,
       pub is_goods_release_authorized: bool,
       pub requires_explicit_merchant_confirmation: bool,
   }
   ```
   Because **all fields are `pub`** (no `#[non_exhaustive]`, no private seal field) AND **`Deserialize` is derived without invariant checks**:
   - External Rust consumers (e.g., Tauri wrapper / PoS crate) can construct `CheckoutReleaseVerdict { outcome: L2ProcessingOutcome::Quarantined { ... }, can_release_goods_automatically: true, is_goods_release_authorized: true, requires_explicit_merchant_confirmation: false }` directly without `DurablePurchaseBinding`!
   - Any `serde_json::from_str::<CheckoutReleaseVerdict>(...)` across an IPC boundary trivially deserializes `"can_release_goods_automatically": true` for any outcome (`Provisional`, `Quarantined`, `NotFound`)!

2. **Un-Gated Fast Path in `replay_checkout_purchase` & `complete_checkout_purchase` (`src/app_service/checkout.rs:66-96, 287-301`):**
   Both `replay_checkout_purchase` (`checkout.rs:87-96`) and the early return at the top of `complete_checkout_purchase` (`checkout.rs:287-301`) read `self.with_wallet(...)` **outside `TransactionOrchestrator::prepare`** (skipping `is_locked_due_to_fork`, skipping disk reload/seal verification, and never checking whether the imported voucher for `purchase_id` was subsequently quarantined due to a later double-spend discovery!).

#### Step-by-Step Reproduction Scenario
1. Deserialize `r#"{"outcome":"NotFound","can_release_goods_automatically":true,"is_goods_release_authorized":true,"requires_explicit_merchant_confirmation":false}"#` into `CheckoutReleaseVerdict` -> succeeds with `verdict.can_release_goods_automatically == true` and `verdict.is_goods_release_authorized == true`!
2. Alternatively, trigger a `ForkDetected` hard lock on `seal.enc` (or quarantine the voucher imported by `"sale-1"` after later conflict gossip) and call `replay_checkout_purchase("sale-1", &bundle)` or `complete_checkout_purchase("sale-1", ...)` -> lines `87-96` / `287-301` return `Ok` with `can_release_goods_automatically: true` from stale unlocked RAM despite the fork-lock / quarantined voucher!

#### Exact Fix
1. **Seal `CheckoutReleaseVerdict` (`src/models/layer2_api.rs:621-629`):**
   - Make fields private and expose read-only getters (`outcome()`, `can_release_goods_automatically()`, `is_goods_release_authorized()`, `requires_explicit_merchant_confirmation()`), OR add a private `_sealed: ()` field and remove `#[derive(Deserialize)]` (keep `Serialize` only for outbound UI DTOs so `CheckoutReleaseVerdict` can ONLY be produced by `CheckoutReleaseVerdict::new` + `with_durable_purchase_binding`, never deserialized from untrusted JSON or forged via struct literals).
2. **Gate Completed Replay (`src/app_service/checkout.rs:87-96, 287-301`):**
   - Store `imported_local_instance_id: Option<String>` in `CheckoutPurchase` when `complete_checkout_purchase` commits.
   - Remove the un-gated pre-orchestrator `if completed { return Ok(...) }` shortcut at `checkout.rs:287-301` (line `316` inside `with_transactional_mut` already handles `if purchase.completed { return Ok(false); }` under the fork-lock and seal gate, and change line `354` to `TransactionOutcome::Abort(false)` when `!newly_committed` to avoid redundant disk writes).
   - In both `replay_checkout_purchase` and the `purchase.completed` branch, verify `!storage.is_locked_due_to_fork(&auth)?`, `SealService::verify_state_matches_seal(...)`, and that `imported_local_instance_id` is not `VoucherStatus::Quarantined`.

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_06_replay_checkout_blocked_when_wallet_fork_locked_or_voucher_quarantined() {
    // 1. Complete checkout "sale-1" legitimately.
    // 2. Trigger hard fork-lock on seal (e.g. compare_remote_seal with conflicting foreign seal)
    //    OR receive conflicting L1 proof that transitions the imported voucher to Quarantined.
    // 3. Call replay_checkout_purchase("sale-1", &bundle) and complete_checkout_purchase("sale-1", ...):
    //    ASSERT neither returns can_release_goods_automatically() == true!
}
```

---

### [AUDIT-07-07] `evaluate_multi_node_anchor_verdicts` Falls Back to `verdicts.first()` (Quorum = 1) on Split Responses and Accepts Unverified Lock Entries / Divergent `remote_t_id`s

- **Severity:** `HIGH`
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-840 (Quorum Logic Bypass)
- **Exact File & Line Numbers:**
  - `src/services/l2_gateway.rs:1018-1057` (`evaluate_anchor_verdict`)
  - `src/services/l2_gateway.rs:1069-1136` (`evaluate_multi_node_anchor_verdicts`, specifically lines `1097-1111` & `1131-1132`)

#### Mechanics & Root Cause
`evaluate_multi_node_anchor_verdicts` (`src/services/l2_gateway.rs:1069-1136`) is documented as *"Evaluates multi-node responses with CFT majority-quorum rules and quorum-gated rollback protection"*. For `total_nodes = 20`, `required_q = 11` (`n / 2 + 1`). However:
1. **Single-Node Fallback (`l2_gateway.rs:1131-1132`):**
   ```rust
   } else if let Some(first) = verdicts.first() {
       evaluate_anchor_verdict(first, local_t_id, local_tag)
   ```
   Whenever **no single category reaches `required_q`** (e.g., 12 of 20 nodes timed out so only 8 responded, or responses are split 5 `RollbackDetected` + 5 `PendingLeapLock` + 5 `GenesisRequired` + 1 Byzantine `Synchronized` at index 0), `evaluate_multi_node_anchor_verdicts` **completely abandons `required_q` and returns whatever `verdicts[0]` says**!
   - A single Byzantine node at `verdicts[0]` returning `L2Verdict::Ok` or `Verified(local_t_id)` forces `AnchorSyncVerdict::Synchronized`, hiding a wallet rollback!
   - Conversely, a single Byzantine node at `verdicts[0]` returning a forged `L2Verdict::Conflict` forces `AnchorSyncVerdict::ForkConflict`, hard-locking the victim's wallet!
2. **Unverified Lock Signatures & Split-Target Aggregation (`l2_gateway.rs:1024-1042, 1088-1112`):**
   - `evaluate_anchor_verdict` never calls `verify_lock_entry_proof` on `Verified { lock_entry }` or `Conflict { existing_lock }`, and unconditionally maps unauthenticated `L2Verdict::Ok` / `L2Verdict::Confirmed` to `Synchronized`.
   - `rollback_count` / `fork_count` / `leap_count` increment across **different** `remote_t_id`s or `sync_point`s and return `first_rollback` / `first_fork` / `last_leap_point` without requiring `required_q` nodes to agree on the *same* `t_id` or `sync_point`!
   *(Note: Existing test `audit_00_wildcard_32_multi_node_anchor_quorum_prevents_single_node_spoofing` at `tests/security_audit_wildcard.rs:345` accidentally passed `local_t_id_str` instead of `local_tag` inside `MissingLocks`, causing `leap_count == 4 >= 3` and never hitting line `1131`!)*

#### Step-by-Step Reproduction Scenario
1. Query a 5-node shard (`total_nodes = 5`, `required_q = 3`). Node 0 (Byzantine) responds first with `L2Verdict::Conflict { existing_lock: forged_unverified_entry }`; Nodes 1 & 2 respond `MissingLocks { sync_point: local_tag }` (`Synchronized`, count = 2); Nodes 3 & 4 time out (or respond `UnknownVoucher`, count = 2).
2. Because `fork_count = 1 < 3`, `syncd_count = 2 < 3`, `unknown_count = 2 < 3`, execution falls through to line `1131` (`verdicts.first()`) and returns **`AnchorSyncVerdict::ForkConflict { foreign_entry: forged_unverified_entry }`** from 1 unverified node!

#### Exact Fix
1. Replace the `else if let Some(first) = verdicts.first()` fallback (`l2_gateway.rs:1131-1135`) with a fail-closed **`AnchorSyncVerdict::Inconclusive`** variant (or `Result<AnchorSyncVerdict, VoucherCoreError>` returning `ValidationError::InsufficientQuorum`) whenever no verdict reaches `required_q`.
2. Verify `verify_lock_entry_proof` on every `Verified` / `Conflict` `L2LockEntry` against `anchor_id` and `local_tag` before counting its vote, reject bare `L2Verdict::Ok` in multi-node anchor evaluation, and group counts by `(remote_t_id)` / `(sync_point)` so `required_q` nodes must attest to the **identical** state transition.

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_07_multi_node_anchor_never_trusts_verdicts_first_without_quorum() {
    let local_t_id = [0x11u8; 32];
    let local_tag = "tag_step_5";
    // 1 Byzantine ForkConflict at index 0 + 2 Synchronized + 2 UnknownVoucher (total_nodes = 5, required_q = 3)
    let verdicts = vec![
        L2Verdict::Conflict { existing_lock: dummy_lock([0x99; 32]) },
        L2Verdict::MissingLocks { sync_point: local_tag.into() },
        L2Verdict::MissingLocks { sync_point: local_tag.into() },
        L2Verdict::UnknownVoucher,
        L2Verdict::UnknownVoucher,
    ];
    let res = evaluate_multi_node_anchor_verdicts(&verdicts, &local_t_id, local_tag, 5);
    assert!(!matches!(res, AnchorSyncVerdict::ForkConflict { .. } | AnchorSyncVerdict::Synchronized));
}
```

---

### [AUDIT-07-08] `process_l2_verdict_with_authority` & `verify_checkout_response_with_authority` Bypass Committee Quorum When Unsigned `quorum_certificate` Is Omitted or `L2Verdict::Ok` Is Sent, While Canonical `L2Verdict::Confirmed { proof }` Always Fails

- **Severity:** `MEDIUM`
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Exact File & Line Numbers:**
  - `src/services/l2_gateway.rs:598-606` (`evaluate_quorum_certificate`)
  - `src/services/l2_gateway.rs:728-769, 781-810, 832-835` (`process_l2_verdict_internal`)
  - `src/models/layer2_api.rs:426-455, 560-567` (`From<QuorumProof> for QuorumCertificateDto` & `L2ResponseEnvelope`)
  - `src/app_service/conflicts.rs:340-355, 421-456` (`process_l2_response_internal` & `verify_checkout_response_with_authority`)
  - *(Related legacy helper: `src/services/l2_gateway.rs:119-175` `verify_quorum_plausibility` verifies zero Ed25519 signatures.)*

#### Mechanics & Root Cause
*(Note: Core 14/20 BFT signature math in `humoco_proto::verify::verify_quorum_proof` (`../humoco-proto/src/verify.rs:23-71`) was audited and verified **sound** — duplicate `signer_pubkey` entries are strictly rejected via `HashSet::insert`, committee keys are checked for uniqueness, Ed25519 `verify_strict` is used, and `LiveStateContext` / `original_approval_digest` domain tags are non-overlapping. The bugs below reside in the `human-money-core` adapter layer in `l2_gateway.rs` and `conflicts.rs`.)*

1. **Missing `quorum_certificate` Silently Downgrades to `ConfirmLocal` Even When `authority: Some(&CheckoutAuthority)` Is Provided (`l2_gateway.rs:598-606, 728-740, 832-835` & `conflicts.rs:341, 353`):**
   - `L2ResponseEnvelope.server_signature` (`l2_gateway.rs:728-740`) signs **only `serde_json::to_vec(&envelope.verdict)`**, NOT `envelope.quorum_certificate`!
   - When a caller explicitly invokes `process_l2_verdict_with_authority(..., authority)` or `AppService::verify_checkout_response_with_authority(..., authority)` expecting 14/20 committee verification:
     - In `evaluate_quorum_certificate` (`l2_gateway.rs:604-606`), `let Some(certificate) = certificate_opt else { return Ok(VerdictAction::ConfirmLocal); };` returns `Ok(VerdictAction::ConfirmLocal)` even when `authority.is_some()`!
     - Likewise, `L2Verdict::Ok { .. }` (`l2_gateway.rs:832-835`) returns `Ok(VerdictAction::ConfirmLocal)` without checking `authority` or any lock proof!
     - In `AppService::process_l2_response_internal` (`src/app_service/conflicts.rs:341, 353`), **both** `VerdictAction::ConfirmLocal` (0 committee signatures) and `VerdictAction::ConfirmFinal` (14/20 committee signatures) map to the exact same `L2ProcessingOutcome::Found`!
   - Thus, a compromised gateway node (or an on-path attacker stripping the unsigned `quorum_certificate` field from an `L2ResponseEnvelope` containing `Verified` or idempotent `Conflict`) passes `verify_checkout_response_with_authority` with **zero committee votes**!

2. **Canonical `L2Verdict::Confirmed { proof }` Always Fails Verification (`l2_gateway.rs:756-769` & `layer2_api.rs:426-455`):**
   - When `envelope.verdict` is `L2Verdict::Confirmed { proof }` without a redundant `envelope.quorum_certificate`, line `762` converts `QuorumCertificateDto::from(proof)` (`src/models/layer2_api.rs:426-454`), which hardcodes `lock_id: String::new()` and `parent_lock: String::new()`. `evaluate_quorum_certificate` then immediately fails at lines `610` (`!matches_lock_id(lock_t_id, "")`) and `629` (`hex::decode("") != Some(parent_lock)`)!
   - Conversely, if `envelope.quorum_certificate` IS populated alongside `L2Verdict::Confirmed { proof }`, `unwrap_or_else` at line `761` completely ignores the server-signed `proof` inside `Confirmed` and evaluates only the unsigned `envelope.quorum_certificate`!

#### Step-by-Step Reproduction Scenario
1. Construct a valid `CheckoutAuthority` with a 20-node committee (`threshold = 14`).
2. Have a single gateway `server_key` sign `L2Verdict::Ok { ds_tag: None }` (or `L2Verdict::Verified { lock_entry }` with `quorum_certificate: None`).
3. Call `service.verify_checkout_response_with_authority(&voucher_id, &envelope_bytes, &authority, pw)`:
   - Returns `Ok(CheckoutReleaseVerdict)` with `outcome == L2ProcessingOutcome::Found` despite **0 of 20** committee nodes having signed!

#### Exact Fix
1. In `evaluate_quorum_certificate` (`src/services/l2_gateway.rs:604-606`): if `authority.is_some()` and `certificate_opt.is_none()`, return `Err(ValidationError::InvalidL2Proof)` instead of `Ok(VerdictAction::ConfirmLocal)`. Also reject `L2Verdict::Ok` in `process_l2_verdict_internal` whenever `authority.is_some()`.
2. For `L2Verdict::Confirmed { proof }` (`l2_gateway.rs:756-769`): require `authority: Some(auth)` and verify `proof` directly via `humoco_proto::verify::verify_quorum_proof(&proof, &digest, &auth.committee, threshold)` where `digest = original_approval_digest(auth.network, auth.shard_id, 1, &auth.parent_lock, &auth.child_lock)` (and if `envelope.quorum_certificate` is also present, require it to match `proof`), rather than converting through the lossy `QuorumCertificateDto::from(proof)` with empty `lock_id`/`parent_lock`.
3. Deprecate or gate `pub fn verify_quorum_plausibility` (`l2_gateway.rs:119-175`) so callers cannot mistake HRW-ID plausibility checks for cryptographic quorum verification.

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_08_authority_verdict_rejects_missing_quorum_certificate_and_bare_ok() {
    // 1. Build CheckoutAuthority with 20 distinct committee keys.
    // 2. Sign L2ResponseEnvelope { verdict: L2Verdict::Ok { ds_tag: None }, quorum_certificate: None, .. }
    //    and L2ResponseEnvelope { verdict: L2Verdict::Verified { lock_entry }, quorum_certificate: None, .. }
    //    with server_pubkey only (0 committee votes).
    // 3. Call process_l2_verdict_with_authority(..., &authority):
    //    ASSERT both return Err(ValidationError::InvalidL2Proof).
}
```

---

### [AUDIT-07-09] Wallet Transaction / Orchestrator State Desyncs (`update_seal_after_state_change` Unguarded Commit Without Undo Journal, Failed-Commit Recovery Dropping `StateMergeHook` & Ignoring Seal Gate, and Torn Seal State)

- **Severity:** `MEDIUM`
- **CWE:** CWE-460 (Improper Cleanup on Thrown Exception), CWE-662 (Improper Synchronization)
- **Exact File & Line Numbers:**
  - `src/app_service/storage_ops.rs:659-679, 905-930` (`AppService::update_seal_after_state_change` & `save_encrypted_data`)
  - `src/app_service/orchestrator.rs:338-365, 520-560` (`execute_with_policy` & `execute_reconciliation` error/recovery paths)
  - `src/app_service/orchestrator.rs:414-449` (`execute_seal_with_policy`)\n  - `src/app_service/storage_ops.rs:234-240` (`compare_remote_seal`)

#### Mechanics & Root Cause
*(Note: Closure panics inside `with_transactional_mut` were audited and verified **safe** — `TransactionOrchestrator::prepare` swaps `service.state` to `AppState::Locked` at `orchestrator.rs:92` and writes `.wallet.undo.enc` before calling `f(&mut temp_wallet, ...)`, so a panic leaves `AppState::Locked` and recovers cleanly from `.wallet.undo.enc` on next access.)*

However, three concrete non-panic state desync paths exist between RAM and disk:
1. **`pub fn update_seal_after_state_change` (`src/app_service/storage_ops.rs:659-679`, also called by `save_encrypted_data` at `924`):**
   - Mutates `AppState::Unlocked { wallet, storage, .. }` **in place** by calling `storage.commit_wallet_atomic(wallet, identity, &auth)?` followed by `SealService::persist_seal_for_wallet_state(storage, wallet, identity, &auth)?`:
     - When called directly (`pub fn`), it acquires **no `WalletLockGuard`** and performs **no reload-before-write**.
     - It creates **no `.wallet.undo.enc`** journal and writes **no `.wallet.commit.enc`** marker, yet `commit_wallet_atomic` increments `.wallet.generation` and clears `wallet.pending_events`!
     - If `persist_seal_for_wallet_state` fails (e.g., `seal.tx_nonce == u64::MAX` overflow check at `seal_service.rs:144`, or I/O error writing `seal.enc`), `vouchers.enc` / `own_fingerprints.enc` and in-memory `wallet` hold the new state while `seal.enc` still binds the old `state_hash` — **permanently bricking the wallet with `Error::StateRollbackDetected` on every subsequent transaction or login!**
2. **Failed-Commit Recovery in `orchestrator.rs:338-365, 520-560` Drops Live-Session RAM State & Ignores Seal Verification:**
   - When `commit_res` fails (`Err(error)` at line `353` or `UncertainCommit` at line `330`), the orchestrator aborts the disk journal and reloads `let (recovered_wallet, _) = Wallet::load(&storage, &auth, current_wallet.local_instance_id.clone())?`:
     - It **forgets to call `StateMergeHook::apply(&current_wallet, &mut recovered_wallet)`**, silently wiping `wallet.l2_server_pubkey` (not persisted on disk!) and any unsaved in-memory `pending_events` that existed in `current_wallet` prior to the failed transaction!
     - Lines `340` and `357` write `let _ = SealService::verify_state_matches_seal(&storage, &auth, &recovered_wallet);`, **discarding the `Result`** and unlocking `service.state` even if the seal check failed!
3. **Torn State in `execute_seal_with_policy` (`orchestrator.rs:424-437`) & `compare_remote_seal` (`storage_ops.rs:234-240`):**
   - `execute_seal_with_policy` runs `f(...)` (mutating `seal.enc` on disk without an undo journal), then calls `storage.advance_generation(initial_gen)?` and `storage.record_commit_marker(&auth, new_gen)?`. If either `?` returns `Err`, `service.state` is left **`AppState::Locked`** (because `prepare` mem-replaced it at line `92`) while `seal.enc` is already modified on disk without a matching generation/commit marker!
   - In `compare_remote_seal` (`storage_ops.rs:237`), when `ForkDetected` occurs, `let _ = storage.save_seal(&auth, &locked_record);` ignores disk-write errors AND leaves `service.state` `Unlocked` instead of transitioning or enforcing lock persistence!

#### Step-by-Step Reproduction Scenario
1. Unlock `AppService`, configure `service.set_l2_server_pubkey(pk)` (stored in `wallet.l2_server_pubkey`), set `seal.tx_nonce = u64::MAX` on disk (or trigger a seal write failure), and call `service.update_seal_after_state_change(pw)` (or `save_encrypted_data`):
   - `commit_wallet_atomic` succeeds, `persist_seal_for_wallet_state` returns `Err(NonceOverflow)`, and every subsequent `with_transactional_mut` or `login` fails with `StateRollbackDetected`!
2. Alternatively, configure `set_l2_server_pubkey(pk)`, run any `with_transactional_mut` whose commit fails I/O -> `orchestrator.rs:355` reloads `recovered_wallet` from disk without `StateMergeHook::apply`, silently resetting `wallet.l2_server_pubkey` to `None`!

#### Exact Fix
1. Route `save_encrypted_data` and `update_seal_after_state_change` exclusively through `TransactionOrchestrator::execute` (`with_transactional_mut`) so every state + seal update is protected by `WalletLockGuard`, `.wallet.undo.enc` compensation (`restore_undo_entry` covers `seal.enc` & `integrity.json`), and `.wallet.commit.enc`.
2. In `orchestrator.rs:338-365` and `520-560`:
   - Apply `StateMergeHook::apply(&current_wallet, &mut recovered_wallet);` on `Err(error)` rollback (preserving `l2_server_pubkey` and pre-existing `pending_events`).
   - Replace `let _ = SealService::verify_state_matches_seal(...)` with `SealService::verify_state_matches_seal(...)?` so a corrupted/mismatched seal leaves `service.state = AppState::Locked` instead of unlocking an unverified wallet.
3. Include `seal.enc` inside a `WalletStorageTransaction` undo journal for `execute_seal_with_policy`, and propagate `storage.save_seal(&auth, &locked_record)?` in `compare_remote_seal` (locking `service.state` when `ForkDetected` is triggered).

#### Fail-First Rust Test Design
```rust
#[test]
fn audit_07_09_failed_commit_preserves_l2_pubkey_and_seal_update_rolls_back_atomically() {
    // 1. Unlock AppService, call set_l2_server_pubkey([0x42; 32]).
    // 2. Set seal.tx_nonce = u64::MAX so persist_seal_for_wallet_state fails with NonceOverflow.
    // 3. Call update_seal_after_state_change(pw) (and a with_transactional_mut mutation):
    //    ASSERT call returns Err, wallet.l2_server_pubkey is STILL Some([0x42; 32]),
    //    and SealService::verify_state_matches_seal STILL succeeds (no bricked wallet!).
}
```

---

### Post-Audit Design-Intent Triage Summary

Per `docs/security/ai-audits/DESIGN_INTENT_TRIAGE.md` and `AGENTS.md`, all candidate observations were filtered through the mandatory 4-step triage protocol before reporting:

| Candidate Observation | Step 1–4 Triage Outcome | Rationale & Source Reference |
|---|---|---|
| Pure offline split-brain double-spend (Device A backed up, spends completely offline without L2 contact, Device B restores offline and spends again) | **`[INTENTIONAL DESIGN REQUIREMENT]`** *(Excluded from findings)* | Layer 1 is offline-first P2P cash with **Fraud Detection, Not Prevention** (`AGENTS.md`, `docs/usage/wallet-backups.md:56-57`). Purely offline double-spends cannot be prevented upfront and are caught deterministically by the SST V4 identity trap. *(By contrast, `AUDIT-07-01` & `AUDIT-07-05` report concrete bugs in the **online L2 backup-reconciliation & PoS challenge mechanisms** explicitly built to protect honest users when L2 IS queried.)* |
| `L2Verdict::Conflict { existing_lock }` where `existing_lock.t_id == local_t_id` treated as success/retry instead of `TriggerQuarantine` (`src/services/l2_gateway.rs:795-809`) | **`[INTENTIONAL DESIGN REQUIREMENT]`** *(Excluded from findings)* | Explicit architectural guardrail in `AGENTS.md` (*"L2 Idempotent Retries"*): retrying an already-anchored transaction returns `Conflict` with the same `t_id` and must not self-quarantine the honest sender. |
| Counterparty DID retention in encrypted local `WalletEvent` history (`TransferSent` / `TransferReceived` in `src/wallet/transactions.rs:468-494, 918-948`) | **`[INTENTIONAL DESIGN REQUIREMENT]`** *(Excluded from findings)* | Documented in `DESIGN_INTENT_TRIAGE.md` & `PRIVACY_FAQ.md`: local-only encrypted hop-by-hop forensic trail (`recipient_id` stripped before L1 P2P bundle serialization via `into_wire_voucher()`). |
| Duplicate signer entries / non-strict Ed25519 malleability in `humoco_proto::verify::verify_quorum_proof` (`../humoco-proto/src/verify.rs:23-71`) | **`[FALSE POSITIVE — VERIFIED SECURE]`** *(Excluded from findings)* | Verified in `../humoco-proto/src/verify.rs:34-66`: committee uniqueness is enforced, `seen: HashSet<[u8; 32]>` strictly rejects duplicate `vote.signer_pubkey` entries, and `ed25519_dalek::VerifyingKey::verify_strict` prevents small-order/malleable signature acceptance. |
| Panicking closure inside `with_transactional_mut` leaving half-mutated `Wallet` in `AppService` RAM (`src/app_service/orchestrator.rs:92, 278-291`) | **`[FALSE POSITIVE — VERIFIED SECURE]`** *(Excluded from findings)* | `TransactionOrchestrator::prepare` replaces `service.state` with `AppState::Locked` *before* writing `.wallet.undo.enc` or invoking `f(&mut temp_wallet, ...)`. A panic unwinds with `service.state == AppState::Locked` and `.wallet.undo.enc` intact on disk for deterministic recovery. *(Only the concrete non-panic recovery/helper desyncs in `AUDIT-07-09` are reported.)* |
| Unchecked `u64` timestamp arithmetic underflow/overflow in checkout/intent TTL & pruning (`checkout.rs:166, 252`, `l2_intents.rs:197, 411, 425`) | **`[FALSE POSITIVE — VERIFIED SECURE]`** *(Excluded from findings)* | Verified that arithmetic consistently uses `.saturating_add(...)` / `.saturating_sub(...)` without raw `-` or `+` panics/wraparounds; the actual logic bug on clock skew is the unconditional pruning of unresolved intents reported in `AUDIT-07-04`. |
