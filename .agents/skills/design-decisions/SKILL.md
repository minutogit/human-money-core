---
name: design-decisions
description: Architectural design decisions for human_money_core including SAI, instance IDs, TOML standards, and CEL engine choices.
---

# Design Decisions — human_money_core

## Gender Representation in Creator Struct

- **Decision:** `gender` field uses ISO 5218 integer (1=male, 2=female, 0=not known, 9=not applicable)
- **Rationale:** Pragmatic and universal. Complex gender representation is delegated to higher application layers.

## TOML for Voucher Standards

- **Decision:** Standards use TOML format instead of JSON.
- **Rationale:** TOML supports comments, making standards human-readable and self-documenting.

## Local Voucher Instance ID

- **Why needed:** After a `split` transaction, multiple instances share the same `voucher_id`. The `local_voucher_instance_id` is a stable, unique primary key for each instance in the wallet.
- **Calculation:** Traverses transaction history backwards to find the last point where the profile owner had a balance > 0. This is necessary for consistent state management and local double-spending detection.

## Separated Account Identity (SAI)

- **Concept:** One user has one cryptographic identity (Public Key from mnemonic). Separate accounts for different contexts (e.g., "pc", "mobile") use different prefixes.
- **User IDs:** `pc:aB3@did:key:z...xyzA` and `mobil:C4d@did:key:z...xyzA`
- **Key principles:**
  - Unified identity for Web of Trust (only `did:key` matters)
  - Strict account separation (prevents double-spend from state inconsistency)
  - Checksum validation prevents typos
  - Explicit transfers required between own accounts

## Dynamic Business Rules via CEL

- **Decision:** Common Expression Language (CEL) replaces hardcoded validation logic.
- **Rationale:** Turing-incomplete (no DoS risk), native Rust crate, excellent list processing (filter, map, all makros), seamless custom function injection.
- **Implementation:** `src/services/dynamic_policy_engine.rs`
- **Key advantage:** New voucher standards can add validation rules without recompiling the core library.

## Anti-Signature-Reuse-Firewall

- **Decision:** Signature uniqueness is validated at the Public Key level (32-byte `[u8; 32]`), not at the User-ID string level.
- **Rationale:** Different prefixes could disguise the same key. `get_pubkey_from_user_id` extracts the actual `EdPublicKey` for comparison.

## Decentralized Conflict & Reputation Management

- **Decision:** Use a purely decentralized "Local Override" mechanism instead of relying on a global consensus or "ResolutionEndorsements" for the MVP.
- **Rationale:** Global endorsement suffers from Sybil-attacks, lack of incentives for victims to "forgive" publicly, and privacy concerns (de-masking stealth keys). Conflicts are settled socially; users trust contacts locally.
- **Organic Eviction (VIP Gossip):** 
  - **Negative Depth:** Fraud proofs are gossiped with negative `depth` values (`i8`) to distinguish them from organic gossip.
  - **Effective Depth:** Selection for gossip bundles uses `abs(depth) - 2`. This gives new VIP reports a 2-hop "head start" to spread rapidly while allowing them to age naturally if no longer relevant.
  - **Loop & Replay Protection:** External VIP updates are ignored if the fingerprint is already known locally as a VIP (prevents "fresher" negative depths from keeping zombies alive). Symmetrically arriving fingerprints (pairs with matching negative depth) are prioritized; asymmetric pairs are treated as spam and normalized.
- **Conflict Roles:** The UI distinguishes between `Victim` (local active voucher was quarantined) and `Witness` (passive detection).
