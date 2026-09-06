# Privacy & Stealth Mode Security FAQ

This document addresses frequently asked questions regarding the cryptographic architecture, identity verification, privacy boundaries, and offline forensics in `human_money_core`.

---

## 1. Core Architectural Philosophy

### What is the distinction between *Artifact Anonymity* and *Local Forensic Storage*?

In **Stealth Mode** (Private Mode), `human_money_core` strictly separates data visibility across three operational domains:

1. **Voucher Chain (Artifact Anonymity):**
   The transaction records embedded inside the voucher (`voucher.transactions`) contain only ephemeral/blinded identifiers (`sender_id: None`, `recipient_id: ANONYMOUS_ID`, and ephemeral public key hashes). Subsequent holders or third-party chain auditors cannot reconstruct the transaction graph.

2. **Network Transport Envelope (Transit Anonymity):**
   The outer `SecureContainer` (JWE envelope) is encrypted using ephemeral Diffie-Hellman key exchange. In private mode, it carries **no plaintext long-term identity signature**, preventing external network observers from using the envelope as a de-anonymization oracle.

3. **Local Wallet Ledger (Offline Forensic Traceability):**
   The transacting parties' own local wallets record the direct counterparty DID in their encrypted event log (`TransferSent` and `TransferReceived`) and view summaries (`InvolvedVoucherInfo`). This data is strictly private to the local owner's encrypted storage (sealed by `WalletSeal`) and is never transmitted across the network.

---

## 2. Sender Authenticity & Cryptographic Verification

### Q1: How does a direct recipient mathematically verify the sender's authenticity in Stealth Mode?

Even though the on-voucher transaction chain is anonymous to third parties, the direct recipient verifies the sender's authenticity via **two independent cryptographic layers**:

```
+-------------------------------------------------------------------------+
| Layer 1: Transport & Bundle Authentication                              |
|                                                                         |
|  TransactionBundle Content ---> Canonical JSON ---> SHA-256 Hash        |
|                                                          |              |
|                                                    bundle_id            |
|                                                          |              |
|  sender_permanent_key -------- Ed25519 Sign ---------> sender_signature |
|                                                                         |
|  Recipient executes: open_and_verify_bundle()                           |
|  1. Recomputes expected_bundle_id from canonical bytes.                 |
|  2. Verifies Ed25519 signature of sender_id against bundle_id.          |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
| Layer 2: Chain-Level Zero-Knowledge Identity Trap & DLEQ Proof          |
|                                                                         |
|  - tx.privacy_guard: Decrypted via Ephemeral X25519 Diffie-Hellman       |
|    yielding RecipientPayload (sender_permanent_did, next_key_seed).     |
|  - Identity Trap T = u * m + ID (Discrete Logarithm).                   |
|  - DLEQ Proof: Mathematically proves that Trap T and the secret scalar  |
|    belong to the sender's permanent identity key without revealing it.  |
+-------------------------------------------------------------------------+
```

1. **Ed25519 Bundle Signature (`bundle_processor.rs`):**
   The decrypted inner `TransactionBundle` contains `bundle.sender_id` and `bundle.sender_signature`. The recipient recomputes `bundle.bundle_id` from the canonical serialization and executes `verify_ed25519(&sender_pubkey, bundle_id, signature)`.
2. **DLEQ Zero-Knowledge Proof & Privacy Guard (`crypto_dh.rs`):**
   The transaction carries a `privacy_guard` encrypted directly for the recipient's public key. It contains `sender_permanent_did` and the `next_key_seed`. The associated DLEQ proof proves that the sender possesses the private key corresponding to the claimed identity.

---

### Q2: Can an attacker forge or impersonate a sender in Stealth Mode?

**No.** Forgery is mathematically impossible due to the following guarantees:

* **No Signature Forgery:** An attacker (Eve) attempting to claim that Alice sent the bundle would have to set `bundle.sender_id = alice_did`. However, Eve cannot generate Alice's Ed25519 digital signature over `bundle.bundle_id`. `verify_bundle_signature()` fails immediately and rejects the bundle with `ValidationError::InvalidBundleSignature`.
* **No Rebinding / Grafting Attacks:** An attacker cannot steal a legitimate `(bundle_id, signature)` pair from a previous transaction and attach it to modified bundle contents (such as altered amounts, notes, or injected gossip proofs). `open_and_verify_bundle()` recomputes `expected_bundle_id` from raw received bytes before checking signatures.
* **No ZKP Trap Substitution:** The DLEQ proof in `privacy_guard` links the stealth transaction's double-spend trap mathematically to the sender's permanent identity key. An invalid or mismatched proof causes chain validation to fail.

---

## 3. Offline Double-Spend Forensics & Hop-by-Hop Traceability

### Q3: Why does the local wallet event log retain the direct counterparty DID in Stealth Mode?

In an **offline, decentralized peer-to-peer cash network**, there is no central ledger, mempool, or real-time coordinator to prevent double spends before they occur. Double-spend detection and dispute resolution must operate **forensically hop-by-hop**:

```
[ Alice ]  ---(Transfer 1)--->  [ Bob ]  ---(Transfer 2)--->  [ Charlie ]
                                                                   |
                                                      Discovers Double-Spend!
                                                                   |
                                                                   v
                                                  Charlie checks local ledger:
                                                  "I received this from Bob"
                                                                   |
                                                                   v
                                                  Bob checks local ledger:
                                                  "I received this from Alice"
                                                                   |
                                                                   v
                                                  Alice checks local ledger:
                                                  "I received this from Eve"
                                                                   |
                                                                   v
                                                  Eve cannot prove prior hop
                                                  --> Eve is proven fraudulent.
```

If the local wallet wiped the direct counterparty DID (`counterparty_id`) upon sending or receiving in Stealth Mode:
* Bob would have no durable record of who gave him the fraudulent voucher.
* Charlie could accuse Bob, and Bob would be unable to demonstrate that he received the voucher from Alice.
* The entire offline dispute-resolution and social accountability mechanism would collapse.

Therefore, storing the direct `counterparty_id` in `TransferSent` and `TransferReceived` events is an **essential functional requirement** for offline cash resilience, not a security vulnerability.

---

### Q4: Is storing the counterparty DID in local events a privacy leak?

**No**, for the following security reasons:

1. **Confidentiality at Rest:**
   Wallet event logs are stored in monthly encrypted chunks (`YYYY_MM.json.enc`) protected by PBKDF2 key derivation and ChaCha20-Poly1305 AEAD encryption.
2. **Storage Integrity:**
   All local records are cryptographically bound to the hash-chained `WalletSeal` rollback guard and SHA3-256 storage integrity manifests.
3. **No Network Exposure:**
   Local wallet events are never forwarded, gossiped, or included in outgoing vouchers or `SecureContainer` transit bundles.
4. **Isolated Scope:**
   Each participant's log contains only their own direct 1-hop interactions. Alice's log knows she traded with Bob; Alice's log has zero knowledge of Charlie.

---

## 4. Summary of Data Visibility Matrix

| Participant / Observer | Sees Sender Identity? | Sees Recipient Identity? | Sees Transaction Amount? |
| :--- | :--- | :--- | :--- |
| **Network Eavesdropper (Transit)** | ❌ No (no signature on envelope) | ❌ No (trial decryption) | ❌ No (JWE ciphertext) |
| **Subsequent Voucher Holders (Downstream)** | ❌ No (`sender_id: None`) | ❌ No (`ANONYMOUS_ID`) | ✔️ Yes (chain conservation) |
| **Direct Sender (Local Storage)** | ✔️ Yes (self) | ✔️ Yes (local `TransferSent`) | ✔️ Yes |
| **Direct Recipient (Local Storage)** | ✔️ Yes (local `TransferReceived`) | ✔️ Yes (self) | ✔️ Yes |
