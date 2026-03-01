# L2 Client Simulator

A developer tool for **Layer-2 (L2) Architects** integrating the Human Money protocol.

## Purpose

This binary simulates the cryptographic behavior of independent Human Money wallets —
**without** the overhead of a real wallet instance. It generates mathematically correct
**Ed25519-signed payloads** (identical in structure and cryptographic validity to those emitted
by production wallets) and fires them at a target L2 server.

Use it to:
- **Verify protocol compliance** of your L2 implementation (Compliance Mode)
- **Stress-test** your L2 database and CPU under realistic production load (Stress Mode)
- **Explore complex L2 graphs step by step** — chains, splits, double-spends (Manual Mode)

---

## Build Instructions

```bash
cargo build --release --bin l2_client_simulator
```

The compiled binary is located at `target/release/l2_client_simulator`.

---

## Mode 1: Compliance Test

The Compliance Test performs a structured **integration test** against a running L2 server,
covering five protocol scenarios in sequence. All checks are assertion-based — the process
exits with a non-zero code on any protocol violation.

| # | Scenario | What is tested |
|---|---|---|
| 1 | **Happy Path** | Sends a genesis lock, then queries its status. Expects `Verified` or `Ok`. |
| 2 | **Transfer (chain)** | Sends a non-genesis lock referencing the genesis `t_id` as `ds_tag`. The server must accept it as the canonical successor. |
| 3 | **Double Spend** | Re-submits a lock with the same `ds_tag` but a different `transaction_hash`. The server must either prove the collision (`Verified` + existing lock) or reject the request (`Rejected`). A silent acceptance is treated as a test failure. |
| 4 | **Unknown Voucher** | Queries the status of a voucher ID that was never locked. The server must respond with `UnknownVoucher`. |
| 5 | **Invalid Signature** | Sends a genesis lock with one byte of the Ed25519 signature flipped. The server must reject it with a HTTP error or a `Rejected` verdict. Acceptance is treated as a test failure. |

```bash
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 compliance
```

---

## Mode 2: Stress Test

Generates a **continuous stream of cryptographically valid lock and status requests**.
Every request carries a freshly generated Ed25519 keypair and a correctly signed payload —
the server cannot distinguish these from real wallet traffic.

At 3-second intervals, the simulator prints a live stats line:

```
[Stats] 950 reqs/sec | Total: 28500 | Errors: 12 | Avg Latency: 4 ms
```

The average latency is calculated over the last 3-second window (successful requests only)
and is reset after each print, so it always reflects recent performance rather than a
cumulative average that drifts over time.

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `--rate` | `1000` | Target number of requests per second. |
| `--connections` | `50` | Maximum number of parallel async workers. Increase for higher throughput, but watch your OS file descriptor limits. |

### Usage

```bash
# Default: 1000 req/s with 50 parallel workers
cargo run --release --bin l2_client_simulator -- \
  --url http://127.0.0.1:8080 \
  stress

# Custom: 5000 req/s with 200 parallel workers
cargo run --release --bin l2_client_simulator -- \
  --url http://your-l2-node.example.com:8080 \
  stress --rate 5000 --connections 200
```

> **Note:** Always compile with `--release` for stress testing. The debug binary is significantly
> slower and will skew your throughput and latency measurements.

---

## Mode 3: Stateful Manual Mode

The Manual Mode gives the L2 Architect full interactive control for **step-by-step graph
exploration**. Unlike the automated modes, manual commands maintain cryptographic state across
invocations in a local file.

### How State Management Works

The simulator stores all active voucher state in **`l2_simulator_state.json`** (created in the
current working directory). This file tracks:

- Every registered `layer2_voucher_id`
- Its current **"leaves"** (UTXO-equivalent outputs): the spendable tips of the L2 graph
- For each leaf: the current `t_id` (which becomes the `ds_tag` for the next transaction) and
  the corresponding **Ed25519 signing key**

This means you **never need to copy-paste hashes or keys manually** — the simulator handles
all cryptographic bookkeeping for you. Just use the voucher ID printed by `genesis`.

> ⚠️ **Keep `l2_simulator_state.json` private.** It contains raw signing keys.

---

### Available Manual Subcommands

| Command | Description |
|---|---|
| `genesis` | Create a new genesis voucher and register it on the L2 server |
| `transfer <voucher_id>` | Transfer (spend) the first leaf → creates one new leaf |
| `split <voucher_id>` | Consume the first leaf and create 2 independent successor leaves: **payment** + **change** |
| `double-spend <voucher_id>` | Send two conflicting locks for the same leaf (leaf is NOT consumed from state) |
| `query <voucher_id>` | Query the L2 server for the current status of the first leaf |
| `list` | Show all vouchers and their leaves stored in local state |
| `reset` | Delete `l2_simulator_state.json` and start fresh |
| `offline-transfer <voucher_id> <count>` | Generate `count` transfer locks **locally without sending to the server** |
| `sync <voucher_id>` | Push all pending offline locks to the L2 server using the locator-prefix protocol |

---

### Example: Linear Transfer Chain

```bash
# 1. Create a genesis voucher
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual genesis
#    Output: Voucher ID : a3f8...e21c

# 2. Transfer (spend genesis leaf, create leaf #1)
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual transfer a3f8...e21c

# 3. Transfer again (spend leaf #1, create leaf #2)
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual transfer a3f8...e21c

# 4. Query current status of leaf #2
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual query a3f8...e21c

# 5. Inspect all leaves in the state file
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual list
```

---

### Example: Split into 2 Branches (Payment + Change)

```bash
# 1. Create a genesis voucher
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual genesis
#    Output: Voucher ID : b7c1...44fa

# 2. Split the genesis leaf into payment + change
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual split b7c1...44fa
#    Output:
#      Split anchor t_id : <hash>
#      Leaf [0] (payment): <hash>
#      Leaf [1] (change) : <hash>
#      ✓ 2 new leaves available for independent spending.

# 3. Spend each branch independently
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual transfer b7c1...44fa   # spends leaf [0] (payment)

cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual transfer b7c1...44fa   # spends leaf [1] (change)

# 4. Inspect remaining leaves
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual list
```

**What happens during a split?**
1. The simulator sends **one "split anchor" lock** to the L2 server, consuming the current leaf.
2. Locally, it registers **2 new independent leaves** labelled `payment` and `change` — each with its own simulated `t_id` and fresh Ed25519 key.
3. Each leaf can be spent independently at any time via `transfer`.

> **Note on split semantics:** The split anchor lock is the on-chain record of the consumed
> leaf. The N successor leaves are tracked locally and must each be sent to the server
> individually via `transfer` when you want to spend them.

---

### Example: Double-Spend Probe

```bash
# 1. Create a genesis voucher
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual genesis
#    Output: Voucher ID : d9e2...88ab

# 2. Attempt a double-spend (two conflicting locks for the same ds_tag)
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual double-spend d9e2...88ab
#    Output:
#      Attempt #1: [OK] Accepted as canonical lock
#      Attempt #2: [REJECTED] or [DS DETECTED] – server proves the collision
```

> The leaf is **not consumed** from state during `double-spend`, so you can run `transfer`
> afterwards to legitimately spend it.

---

### Example: Resetting Local State

```bash
# Show current state
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual list

# Clear everything and start fresh (removes l2_simulator_state.json)
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual reset
#    Output: Local state cleared. (l2_simulator_state.json deleted)
```

> `reset` only removes the **local** state file. It does not send any requests to the L2
> server. Locks already registered on the server remain there permanently (as per protocol).

---

## Mode 4: Offline Synchronization

### What it tests

Human Money is an **"offline-first" protocol**: a wallet owner can perform multiple transfers
while having no internet connection. Each transfer is signed and chained locally. When the
wallet goes back online, it must bring the L2 server up to date in a single sync session.

The sync protocol works in two phases:

1. **Discovery** — The client sends a `L2StatusQuery` with:
   - `challenge_ds_tag`: the current (latest) leaf `t_id` — the state the client *wants* the server to confirm
   - `locator_prefixes`: an **exponentially thinned-out** list of 10-character Base58 prefixes
     of historical `ds_tag`s (newest first, steps 1, 2, 4, 8, … backwards), plus the genesis
     prefix always appended — allowing the server to find the **Last Common Ancestor** in
     O(log n) comparisons

2. **Upload** — The server responds with `MissingLocks { sync_point }` where `sync_point` is
   the 10-char prefix of the last lock it knows. The client then sends all offline locks
   **sequentially** starting from (and including) that sync point.

The `sync` command implements this exact protocol flow, so you can test whether your L2
server correctly handles the locator-prefix search and accepts the batch upload.

---

### Example: Offline Sync Workflow

```bash
# 1. Create and register a genesis voucher
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual genesis
#    Output: Voucher ID : a3f8...e21c

# 2. Simulate 5 transfers while "offline" (no HTTP requests sent)
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual offline-transfer a3f8...e21c 5
#    Output:
#      Step [1]: ds_tag=5Xt9Qk2mA8 → new t_id=9fRvK3...
#      Step [2]: ds_tag=9fRvK3....  → new t_id=2pWxB7...
#      ...
#      ✓ 5 offline lock(s) stored in state.
#      Run 'sync a3f8...e21c' to push them to the L2 server.

# 3. Inspect state (shows pending count)
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 manual list
#    Leaf [0]: <t_id> – label='offline-transfer:5x' [5 offline lock(s) pending sync]

# 4. Go back "online" and synchronize
cargo run --bin l2_client_simulator -- --url http://127.0.0.1:8080 \
  manual sync a3f8...e21c
#    Output:
#      locator_prefixes : 5 prefix(es): ["9fRvK3....", "5Xt9Qk2mA8", ...]
#      Server: [MISSING LOCKS] sync_point = '5Xt9Qk2mA8'
#      Sending 5 lock(s) starting from index 0 ...
#        [1/5] ds_tag=5Xt9Qk2mA8 → [OK]
#        [2/5] ds_tag=9fRvK3.... → [OK]
#        ...
#      ✓ Sync complete. offline_locks cleared.
```

**Partial sync (server already knows some locks):**

If the server already knows the first 3 of 5 offline locks (e.g. you previously synced
partially), the server will return a `sync_point` that matches lock #3. The `sync` command
automatically detects this and only uploads locks #4 and #5.

---

## Optional: Server Public Key Verification

The `--server-pubkey` flag accepts a Base58-encoded server public key. This is reserved for
future mutual-authentication flows and is currently a no-op.

```bash
./target/release/l2_client_simulator \
  --url http://127.0.0.1:8080 \
  --server-pubkey <BASE58_PUBKEY> \
  compliance
```
