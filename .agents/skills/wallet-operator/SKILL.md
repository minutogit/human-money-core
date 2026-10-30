---
name: wallet-operator
description: Operate human_money_core wallets, prepare UI test scenarios, mint vouchers with guarantors, stage offline double-spends via snapshots, and run multi-wallet playbooks via wallet-cli.
---

# AI Wallet Operator Skill — `wallet-cli`

This skill provides comprehensive instructions, command references, and operational recipes for controlling `human_money_core` wallets from AI agents, automated test scripts, and developer tools using the `wallet-cli` binary.

---

## 1. Overview & Golden Rules for AI Agents

`wallet-cli` is an agent-native CLI controller built directly on top of `AppService` and `FileStorage`. It operates on the same on-disk encrypted profile format as the Tauri desktop wallet UI, enabling fast, reproducible test setups, multi-actor playbooks, and forensic analysis.

### Rule 1: Always Request Machine-Readable JSON
Always pass the global `--json` flag. Every command emits a deterministic JSON envelope:
- **Success:**
  ```json
  {
    "ok": true,
    "data": { ... }
  }
  ```
- **Error:** (exits with code `1`)
  ```json
  {
    "ok": false,
    "error": {
      "message": "Top-level failure description",
      "causes": [
        "Root cause description 1",
        "Root cause description 2"
      ]
    }
  }
  ```

### Rule 2: Guarantee Non-Interactive Execution
Always pass `--password <PW>` or set the `HUMOCO_PASSWORD` environment variable. Never rely on interactive TTY prompts.

### Rule 3: Sharing Wallets with the Tauri Desktop UI
You can freely read, modify, and stage wallet profiles in the same directory used by the Tauri desktop wallet application. Keep these invariants in mind:
- **Same Storage Base:** Point `--data-dir <DIR>` (or `HUMOCO_DATA_DIR`) to the UI's wallet directory (e.g. `~/.local/share/human-money/wallets` or a dedicated test fixture path).
- **Concurrency & Lock Files:** Ensure the Tauri UI does not currently hold the target profile unlocked. While unlocked, `AppService` creates an exclusive lock file (`.wallet.lock`). If the UI holds the lock, CLI commands will fail immediately. In CLI commands, lock files are automatically acquired and cleanly released via RAII guards upon command completion.
- **WalletSeal Device Handover:** The core enforces `WalletSeal` epoch and device binding. When switching between the desktop UI and the CLI (or between different test runners), pass `--auto-handover`. This instructs `AppService` to execute a cryptographic device handover (`handover_to_this_device`) if a `DeviceMismatch` is encountered, seamlessly adopting the profile.
- **Forbidden File:** **Never create a file named `instance_id` inside or above `--data-dir`**. In `human_money_core`, instance IDs are unique in-memory session identifiers and storage directory keys; static marker files named `instance_id` violate repository storage hygiene.

### Rule 4: Performance & Build Tip
Running commands via `cargo run --bin wallet-cli -- ...` invokes Cargo's build graph checker on every call (~500ms–1s overhead). For ultra-fast (~20–50ms) execution, build the binary once:
```bash
cargo build --bin wallet-cli
```
Then invoke `./target/debug/wallet-cli` (or `./target/release/wallet-cli`) directly.

---

## 2. Complete Command Reference

### Global Options
All commands accept the following global flags:
```text
  --data-dir <DIR>            Base directory containing profiles.json (default: HUMOCO_DATA_DIR or target/cli-wallets)
  --standards-dir <DIR>       Directory searched recursively for signed *.toml standards (default: HUMOCO_STANDARDS_DIR or voucher_standards)
  -p, --password <PW>         Wallet password (default: HUMOCO_PASSWORD env var)
  --device-id <ID>            Device identifier for WalletSeal (default: HUMOCO_DEVICE_ID or humoco-wallet-cli)
  --auto-handover             Automatically perform WalletSeal device handover if opened on another device/UI
  --json                      Emit deterministic machine-readable JSON envelopes
```

---

### `mnemonic` — BIP-39 Seed Phrase Operations
- **Generate seed phrase:**
  ```bash
  wallet-cli mnemonic generate [--words <12|24>] [--lang <en|de>] --json
  ```
- **Validate seed phrase:**
  ```bash
  wallet-cli mnemonic validate --phrase "<SEED_PHRASE>" [--lang <en|de>] --json
  ```

---

### `profile` — Profile & Identity Management
- **List configured profiles:**
  ```bash
  wallet-cli profile list --json
  ```
- **Create a new encrypted wallet profile:**
  ```bash
  wallet-cli profile create \
    --name "Alice" \
    [--prefix "issuer"] \
    [--mnemonic "<PHRASE>"] \
    [--passphrase "<BIP39_PASSPHRASE>"] \
    [--words 12] \
    [--lang en] \
    [--first-name "Alice"] \
    [--last-name "Smith"] \
    [--gender "2"] \
    [--organization "Acme Corp"] \
    [--community "Berlin"] \
    [--email "alice@example.com"] \
    [--phone "+49151000000"] \
    [--coordinates "52.5200,13.4050"] \
    [--service-offer "Carpentry"] \
    [--needs "Organic Produce"] \
    --password "pass123" --json
  ```
  *(Note: Positional profile name `wallet-cli profile create Alice ...` is also supported).*
- **Display profile details & identity DID:**
  ```bash
  wallet-cli profile info --profile "Alice" --password "pass123" --auto-handover --json
  ```
- **Update public profile metadata:**
  ```bash
  wallet-cli profile update --profile "Alice" --first-name "Alice" --city "Berlin" --country "DE" --password "pass123" --json
  ```
- **View chronological audit events (event sourcing):**
  ```bash
  wallet-cli profile events --profile "Alice" [--offset 0] [--limit 50] --password "pass123" --json
  ```
- **Delete profile permanently:**
  ```bash
  wallet-cli profile delete --profile "Alice" --password "pass123" --json
  ```

---

### `standards` — Voucher Standards Discovery
- **List verified voucher standards in standards directory:**
  ```bash
  wallet-cli standards [--standard-file <PATH_TO_EXTRA_TOML>...] --json
  ```

---

### `balance` — Wallet Balances
- **Show aggregated balances across all active vouchers:**
  ```bash
  wallet-cli balance --profile "Alice" --password "pass123" --auto-handover --json
  ```

---

### `voucher` — Voucher Lifecycle & Management
- **List vouchers in wallet:**
  ```bash
  wallet-cli voucher list \
    --profile "Alice" \
    [--status <active|incomplete|quarantined|archived|endorsed|expired>] \
    [--standard <UUID|NAME|ABBREVIATION>] \
    --password "pass123" --auto-handover --json
  ```
- **Show complete details of a specific voucher:**
  ```bash
  wallet-cli voucher show --profile "Alice" <LOCAL_INSTANCE_ID> --password "pass123" --auto-handover --json
  ```
- **Mint / Issue a new voucher:**
  ```bash
  wallet-cli voucher create \
    --profile "Alice" \
    --standard "freetaler" \
    --amount "50.00" \
    [--validity "P1Y"] \
    [--description "Repair services"] \
    [--test-voucher] \
    --password "pass123" --auto-handover --json
  ```
- **Delete an incomplete voucher before circulation:**
  ```bash
  wallet-cli voucher delete-incomplete --profile "Alice" <LOCAL_INSTANCE_ID> --password "pass123" --auto-handover --json
  ```

---

### `sign` — Detached Signature Workflows (Guarantors & Notaries)
Used to collect required or optional endorsements on vouchers before entering circulation:
1. **Create signing request container (Issuer):**
   ```bash
   wallet-cli sign request \
     --profile "Alice" \
     --voucher <LOCAL_INSTANCE_ID> \
     --out "/tmp/guarantor_req.hc" \
     [--target "Bob"] \
     [--cleartext] \
     --password "pass123" --auto-handover --json
   ```
2. **Inspect received request container (Signer):**
   ```bash
   wallet-cli sign inspect \
     --profile "Bob" \
     --in "/tmp/guarantor_req.hc" \
     --password "pass123" --auto-handover --json
   ```
3. **Endorse and generate signature response (Signer):**
   ```bash
   wallet-cli sign endorse \
     --profile "Bob" \
     --in "/tmp/guarantor_req.hc" \
     --out "/tmp/guarantor_resp.hc" \
     [--role "guarantor"] \
     [--include-details true] \
     --password "pass123" --auto-handover --json
   ```
4. **Attach returned signature to local voucher (Issuer):**
   ```bash
   wallet-cli sign attach \
     --profile "Alice" \
     --in "/tmp/guarantor_resp.hc" \
     --standard "minuto" \
     --password "pass123" --auto-handover --json
   ```
5. **Remove signature from uncirculated voucher:**
   ```bash
   wallet-cli sign remove \
     --profile "Alice" \
     --voucher <LOCAL_INSTANCE_ID> \
     --signature-id <SIG_ID> \
     --password "pass123" --auto-handover --json
   ```

---

### `tx` — P2P Transfers & Payments
- **Send funds (creates encrypted P2P transfer bundle):**
  ```bash
  wallet-cli tx send \
    --profile "Alice" \
    --to "Bob" \
    --standard "freetaler" \
    --amount "25.00" \
    --out "/tmp/transfer.hc" \
    [--notes "Payment for invoice 42"] \
    [--recipient-password "bobpass"] \
    [--source <LOCAL_INSTANCE_ID:AMOUNT>...] \
    [--privacy-mode true] \
    [--with-l2-intents 1] \
    --password "pass123" --auto-handover --json
  ```
  *(Note: `--to` accepts either a local profile name like `"Bob"` or a full DID like `"did:key:z6Mk..."`).*
- **Receive and ingest transfer bundle (Recipient):**
  ```bash
  wallet-cli tx receive \
    --profile "Bob" \
    --in "/tmp/transfer.hc" \
    [--force-accept-tolerance] \
    --password "pass123" --auto-handover --json
  ```

---

### `snapshot` — Atomic Time-Travel & State Rollback
Allows instant state saving and restoring for offline double-spending tests:
- **Save snapshot:**
  ```bash
  wallet-cli snapshot save --profile "Bob" --tag "pre-spend" [--overwrite] --json
  ```
- **Restore snapshot:**
  ```bash
  wallet-cli snapshot restore --profile "Bob" --tag "pre-spend" --json
  ```
- **List snapshots:**
  ```bash
  wallet-cli snapshot list [--profile "Bob"] --json
  ```
- **Delete snapshot:**
  ```bash
  wallet-cli snapshot delete --profile "Bob" --tag "pre-spend" --json
  ```

---

### `scenario` — High-Speed In-Memory Multi-Actor Runner
Executes multi-wallet playbooks in a single process (<3s for 10 steps, caches unlocked actor sessions):
- **Run scenario playbook:**
  ```bash
  wallet-cli scenario run /path/to/scenario.json --json
  ```
- **Show scenario schema & example:**
  ```bash
  wallet-cli scenario schema --json
  ```

---

### `conflict` — Fraud Forensics & Double-Spend Proofs
- **List all recorded double-spend proofs:**
  ```bash
  wallet-cli conflict list --profile "Charlie" --password "pass123" --auto-handover --json
  ```
- **Inspect proof details (shows deanonymized offender DID):**
  ```bash
  wallet-cli conflict show --profile "Charlie" <PROOF_ID> --password "pass123" --auto-handover --json
  ```
- **Find conflict proof for a quarantined voucher:**
  ```bash
  wallet-cli conflict for-voucher --profile "Charlie" <LOCAL_INSTANCE_ID> --password "pass123" --auto-handover --json
  ```
- **Check reputation & trust status of a DID or local profile:**
  ```bash
  wallet-cli conflict reputation --profile "Charlie" <DID_OR_NAME> --password "pass123" --auto-handover --json
  ```
- **Export double-spend proof:**
  ```bash
  wallet-cli conflict export --profile "Charlie" <PROOF_ID> --out "/tmp/proof.json" [--bs58] --password "pass123" --auto-handover --json
  ```
- **Import proof into another wallet / node:**
  ```bash
  wallet-cli conflict import --profile "Alice" --in "/tmp/proof.json" [--container] --password "pass123" --auto-handover --json
  ```
- **Set local trust override:**
  ```bash
  wallet-cli conflict override --profile "Alice" <PROOF_ID> --allow --note "Resolved privately" --password "pass123" --auto-handover --json
  ```
- **Endorse resolution of a settled conflict:**
  ```bash
  wallet-cli conflict endorse-resolution --profile "Charlie" <PROOF_ID> --notes "Reimbursed in full" [--out "/tmp/res.json"] --password "pass123" --auto-handover --json
  ```
- **Import signed resolution endorsement:**
  ```bash
  wallet-cli conflict import-endorsement --profile "Alice" --in "/tmp/res.json" --password "pass123" --auto-handover --json
  ```

---

### `l2` — Layer-2 Gateway Integration
- **Generate L2 lock request payload:**
  ```bash
  wallet-cli l2 lock-request --profile "Alice" <LOCAL_INSTANCE_ID> [--out "/tmp/lock_req.json"] --password "pass123" --auto-handover --json
  ```
- **Generate L2 status query payload:**
  ```bash
  wallet-cli l2 status-query --profile "Alice" <LOCAL_INSTANCE_ID> [--out "/tmp/status_req.json"] --password "pass123" --auto-handover --json
  ```
- **Apply raw L2 HTTP response:**
  ```bash
  wallet-cli l2 apply-response --profile "Alice" <LOCAL_INSTANCE_ID> --in "/tmp/response.json" --password "pass123" --auto-handover --json
  ```
- **List pending L2 send intents:**
  ```bash
  wallet-cli l2 intents --profile "Alice" --password "pass123" --auto-handover --json
  ```
- **Synchronize voucher directly with an L2 gateway:**
  ```bash
  wallet-cli l2 sync --profile "Alice" <LOCAL_INSTANCE_ID> --url "http://localhost:8080/lock" --password "pass123" --auto-handover --json
  ```

---

## 3. Standard-Specific Notes

`human_money_core` dynamically parses and enforces standard definitions (`*.toml`) discovered in `--standards-dir`. Two primary standards are bundled by default:

### FreeTaler v1 (`freetaler`)
- **Standard UUID:** `a1b2c3d4-e5f6-4789-8012-3456789abcde`
- **Unit / Abbreviation:** `Taler`
- **Decimal Places:** `2` (e.g. `10.00`, `25.50`).
- **Guarantors Required:** `0` (`additional_signatures_range = [0, 3]`).
- **Validity Range:** `P1Y` to `P10Y` (default: `P1Y`).
- **Circulation Status:** Becomes immediately `Active` upon creation! No guarantor endorsements are required before it can be transferred.

### Minuto v1 (`minuto`)
- **Standard UUID:** `MINUTO-V1-2025-09`
- **Unit / Abbreviation:** `Minuto`
- **Decimal Places:** `0` (integers only, e.g. `60`, `120`). Fractional amounts like `60.5` are rejected by validation.
- **Validity:** Minimum issuance validity duration is `P3Y` (e.g. `P3Y` or `P5Y`).
- **Guarantors Required:** Exactly `2` guarantors (`additional_signatures_range = [2, 2]`, `allowed_signature_roles = ["guarantor"]`).
- **ISO 5218 Gender Parity CEL Rules:**
  Minuto enforces strict gender balance among guarantors via dynamic Common Expression Language (CEL) rules:
  1. `gender_balance_male`: Exactly one male guarantor (`gender == "1"`).
  2. `gender_balance_female`: Exactly one female guarantor (`gender == "2"`).
- **Issuance Lifecycle:**
  When minted, the voucher starts with status `Incomplete { reasons: ["..."] }`. It **cannot** be transferred until both a male (`--gender 1`) and a female (`--gender 2`) guarantor endorse it using `wallet-cli sign endorse` and `wallet-cli sign attach`. Once both signatures are attached, the voucher automatically transitions to `Active`.

---

## 4. Ready-to-Use Recipes for UI Testing

### Recipe A: Instant Multi-Actor Ecosystem (`scenario run`)

Save this file as `ecosystem_playbook.json` and execute it in one call to generate an entire funded economy:
```bash
wallet-cli --data-dir target/ui-wallets --password testpass scenario run ecosystem_playbook.json --json
```

```json
{
  "description": "Ready-to-use multi-actor ecosystem with FreeTaler & endorsed Minuto",
  "steps": [
    {
      "action": "create_profile",
      "name": "Alice",
      "first_name": "Alice",
      "last_name": "Issuer",
      "gender": "2"
    },
    {
      "action": "create_profile",
      "name": "Bob",
      "first_name": "Bob",
      "last_name": "Trader",
      "gender": "1"
    },
    {
      "action": "create_profile",
      "name": "Charlie",
      "first_name": "Charlie",
      "last_name": "GuarantorM",
      "gender": "1"
    },
    {
      "action": "create_profile",
      "name": "Doris",
      "first_name": "Doris",
      "last_name": "GuarantorF",
      "gender": "2"
    },
    {
      "action": "create_voucher",
      "profile": "Alice",
      "standard": "freetaler",
      "amount": "100.00",
      "save_ref": "v_freetaler_1"
    },
    {
      "action": "transfer",
      "from": "Alice",
      "to": "Bob",
      "standard": "freetaler",
      "amount": "40.00",
      "auto_receive": true
    },
    {
      "action": "create_voucher",
      "profile": "Alice",
      "standard": "minuto",
      "amount": "60",
      "validity": "P3Y",
      "save_ref": "v_minuto_1"
    },
    {
      "action": "endorse_voucher",
      "creator": "Alice",
      "voucher_ref": "v_minuto_1",
      "standard": "minuto",
      "signer": "Charlie",
      "role": "guarantor"
    },
    {
      "action": "endorse_voucher",
      "creator": "Alice",
      "voucher_ref": "v_minuto_1",
      "standard": "minuto",
      "signer": "Doris",
      "role": "guarantor"
    },
    {
      "action": "transfer",
      "from": "Alice",
      "to": "Bob",
      "standard": "minuto",
      "amount": "30",
      "auto_receive": true
    }
  ]
}
```

---

### Recipe B: Staging an Offline Double-Spend 1 Click Before UI Execution (`snapshot`)

This recipe prepares an offline double-spend scenario where **Spend #1** is executed via CLI, and **Bob is left in his pre-spend state ready for the developer to perform Spend #2 interactively in the Tauri UI**.

#### Automation Script (`stage_double_spend.sh`):
```bash
#!/usr/bin/env bash
set -e

DATA_DIR="target/ui-wallets"
PW="pass123"
CLI="./target/debug/wallet-cli --data-dir $DATA_DIR --password $PW --auto-handover"

# 1. Ensure target profiles exist
$CLI profile create --name Alice || true
$CLI profile create --name Bob || true
$CLI profile create --name Charlie || true

# 2. Alice mints 100.00 FreeTaler and sends it to Bob
$CLI voucher create --profile Alice --standard freetaler --amount 100.00
$CLI tx send --profile Alice --to Bob --standard freetaler --amount 100.00 --out /tmp/funding.hc
$CLI tx receive --profile Bob --in /tmp/funding.hc

# 3. Take Bob's snapshot BEFORE spending the voucher
$CLI snapshot save --profile Bob --tag "pre-spend" --overwrite

# 4. Execute Spend #1: Bob sends 40.00 to Charlie via CLI
$CLI tx send --profile Bob --to Charlie --standard freetaler --amount 40.00 --out /tmp/spend1.hc
$CLI tx receive --profile Charlie --in /tmp/spend1.hc

# 5. Restore Bob's snapshot!
# Bob's local state is rolled back: he now holds the unspent 100.00 voucher again.
$CLI snapshot restore --profile Bob --tag "pre-spend"

echo "======================================================================"
echo "STAGING COMPLETE!"
echo "Bob now has his 100.00 FreeTaler voucher back on disk in '$DATA_DIR'."
echo "Charlie already holds Spend #1 (40.00 FreeTaler)."
echo ""
echo "NEXT STEP FOR DEVELOPER IN TAURI UI:"
echo "1. Start the Tauri Desktop UI pointing to '$DATA_DIR'."
echo "2. Log into profile 'Bob' with password '$PW'."
echo "3. Send 50.00 FreeTaler to Charlie (or Alice)."
echo "The moment you click 'Send' in the UI, Spend #2 is committed, completing"
echo "the staged offline double-spend!"
echo "======================================================================"
```

---

### Recipe C: Inspecting & Propagating V3 SST Double-Spend Proofs (`conflict`)

When two conflicting transfers spending the same voucher input collide (or when foreign gossip fingerprints are imported), the Shared-Signature Trap (SST) protocol automatically triggers:
1. Linear reconstruction extracts the offender's Ed25519 public key (`extract_sst_identity`).
2. The offender's `did:key` is deanonymized.
3. The affected voucher is moved to `VoucherStatus::Quarantined`.

#### Step 1: Discover Quarantined Vouchers
```bash
./target/debug/wallet-cli voucher list --profile "Charlie" --status quarantined --json
```

#### Step 2: Retrieve the Double-Spend Proof ID
```bash
./target/debug/wallet-cli conflict for-voucher --profile "Charlie" <LOCAL_INSTANCE_ID> --json
```
Returns:
```json
{
  "ok": true,
  "data": {
    "local_instance_id": "DxS1zhidErdmqA...",
    "proof_id": "7a3f81e..."
  }
}
```

#### Step 3: Inspect Full Proof Details
```bash
./target/debug/wallet-cli conflict show --profile "Charlie" <PROOF_ID> --json
```
Displays:
- Offender identity (e.g. `did:key:z6Mk...`)
- Conflicting transaction IDs (`t_id` branch A vs. branch B)
- Extracted Schnorr signature shards and SST verification status

#### Step 4: Check Offender Reputation
```bash
./target/debug/wallet-cli conflict reputation --profile "Charlie" "did:key:z6Mk..." --json
```
Returns `trust_status: "KnownOffender"`.

#### Step 5: Export & Propagate Fraud Proof to Other Wallets
```bash
# Charlie exports the proof to JSON
./target/debug/wallet-cli conflict export --profile "Charlie" <PROOF_ID> --out "/tmp/proof_bob.json" --json

# Alice imports the proof into her wallet
./target/debug/wallet-cli conflict import --profile "Alice" --in "/tmp/proof_bob.json" --json

# Alice checks Bob's reputation in her own wallet
./target/debug/wallet-cli conflict reputation --profile "Alice" "Bob" --json
# Evaluates to "KnownOffender"
```

#### Step 6: Dispute Resolution & Out-of-Band Settlements
If the parties settle the claim out of band (e.g. Bob compensates Charlie in cash):
1. **Victim endorses resolution:**
   ```bash
   ./target/debug/wallet-cli conflict endorse-resolution \
     --profile "Charlie" <PROOF_ID> \
     --notes "Compensated in cash on 2026-10-30" \
     --out "/tmp/settlement.json" --json
   ```
2. **Third parties import endorsement to clear the quarantine flag:**
   ```bash
   ./target/debug/wallet-cli conflict import-endorsement --profile "Alice" --in "/tmp/settlement.json" --json
   ```
3. **Local trust override (if desired by Alice):**
   ```bash
   ./target/debug/wallet-cli conflict override --profile "Alice" <PROOF_ID> --allow --note "Direct business partner" --json
   ```
