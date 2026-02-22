# Threat Model (STRIDE)

This document outlines the systematic threat analysis for `human-money-core` transactions using the **STRIDE** model.

## Asset: Transaction / Voucher

| Threat Category | Description | Potential Attack Vector | Protection Mechanism (Mitigation) |
| :--- | :--- | :--- | :--- |
| **S**poofing | Identity Theft | Attacker replays TrapData from another context to impersonate a sender. | **Context Binding**: TrapData is cryptographically bound to the specific transaction context (Context Hash). |
| **T**ampering | Data Manipulation | Modifying the amount or recipient in a signed voucher. | **Ed25519 Signatures**: Any change invalidates the cryptographic signature. |
| **R**epudiation | Denying Action | Sender claims they didn't authorize a transaction. | **Non-Repudiation**: Valid signature proves possession of the private key. |
| **I**nformation Disclosure | Privacy Leak | Metadata (e.g., sender identity) leaks in Private Mode. | **Private Mode Rules**: Sender ID and Signature MUST be absent. Context binding ensures validity without revealing identity. |
| **D**enial of Service | Resource Exhaustion | Sending malformed or massive vouchers to crash validation. | **Input Validation**: Strict size limits and parsing rules before cryptographic operations. |
| **E**levation of Privilege | Unauthorized Access | User performing actions restricted to the Voucher Creator (Mint). | **Role Enforcement**: Protocol logic distinguishes between `Mint` and `Transfer` operations based on origin signature. |

## Systematic Analysis Matrix

We maintain a matrix of *Attack Vectors vs. Protection Mechanisms* to ensure coverage.

| Attack Vector | Mechanism: Signature | Mechanism: Context Binding | Mechanism: Value Conservation | Mechanism: Private Rules |
| :--- | :---: | :---: | :---: | :---: |
| Replay Attack | | :white_check_mark: | | |
| Forged Amount | :white_check_mark: | | :white_check_mark: | |
| Identity Leak (Private) | | | | :white_check_mark: |
| Double Spend | | :white_check_mark: (via TrapData) | | |

*Note: Empty cells indicate areas where a specific mechanism is not the primary defense, but layers may overlap.*
