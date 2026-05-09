# Human Money Core

## Overview

**Human Money Core** (`human_money_core`) is the foundational Rust library powering the Human Money ecosystem. It is a library for managing and transferring self-issued, cryptographic value documents. It enables a decentralized value exchange that turns fundamental concepts of classical crypto systems upside down, putting humans back in the center.

## Core Concepts

**1. Architecture: Autonomous Containers instead of a Global Ledger**
The system deliberately avoids blockchains and requires no network consensus. Each value document is an isolated, portable JSON file. This file acts as an autonomous container, carrying its complete, cryptographically chained transaction history (signature chain) within itself. Transactions can occur asynchronously and offline through direct, P2P-based handover of the updated file.

**2. "Human Money": Identity, Reputation, and Trust**
Why Human Money? Because the creation of value (like services, time, or goods) focuses on the human, not the technology. Transactions typically use known cryptographic identities (`did:key`). Security and acceptance of the money are therefore not based on an abstract algorithm, but primarily on the real reputation and trustworthiness of the acting individuals.

**3. Security Paradigm: Fraud Detection over Fraud Prevention**
Since there is no global consensus mechanism on Layer 1 to validate transactions before execution, the core architecture relies on deterministic fraud detection. The system guarantees that any fraud attempt (e.g., double-spending) leaves tamper-proof mathematical proofs in the signature chain through NIZK traps (Identity Traps), which mathematically expose the identity of the fraudster.

**4. Privacy vs. Traceability**
The system allows transactions to be equipped with additional privacy layers (encryption, ephemeral keys). This is a deliberate trade-off: While user privacy increases, the resolution of fraud cases and Sybil identities becomes more complex, requiring manual, cryptographic tracing of the chain.

**5. Scaling: Layer 2 for Global Fraud Prevention**
While the Core (Layer 1) functions offline and primarily focuses on detection, the system can be expanded with an additional, optional online layer (Layer 2) for preventive fraud protection. Unlike blockchains, this Layer 2 requires no global consensus. It merely acts as a decentralized registry for cryptographic "locks". Clients can asynchronously check online whether a voucher fingerprint has already been marked as spent, creating a global, preventive protection against double-spending without compromising scalability.

## Technical Features

* **Storage Agnostic:** The core logic is decoupled from persistence via a `Storage` trait. A secure, encrypted file-based implementation (`FileStorage`) is provided out-of-the-box.
* **Separated Account Identity (SAI):** Supports strict account separation (e.g., PC vs. Mobile) derived from a single mnemonic, preventing state inconsistencies.
* **Voucher Standards:** Supports flexible, TOML-defined standards for different types of vouchers (e.g., Minuto, FreeTaler, etc.).
* **Robust Cryptography:** Implements secure cryptography using Ed25519 for signatures and X25519/ChaCha20-Poly1305 for encrypted data containers (`SecureContainer`).

## Architecture

The library is structured into several key modules:

* **`wallet`**: The central facade managing the user's state, voucher storage, and transaction history.
* **`app_service`**: A high-level API wrapper designed for client applications (like Tauri apps). It handles locking/unlocking, profile management, and session security.
* **`storage`**: Defines the abstract `Storage` trait and provides the default encrypted `FileStorage`.
* **`services`**: Contains the stateless business logic for cryptography, voucher validation, conflict management, and standard parsing.

## Getting Started

### Prerequisites

* **Rust:** Ensure you have the latest stable version of Rust and Cargo installed.

### Installation

Clone the repository:

```bash
git clone https://github.com/minutogit/human-money-core.git
cd human-money-core
```

## Running Examples (Playgrounds)

This repository includes several "playground" examples to help you understand the core concepts and APIs. You can run them directly using Cargo.

1. **Basic Utils & Setup**  
   Test basic utilities and configuration loading.

   ```bash
   cargo run --example playground_utils
   ```

2. **Cryptography Playground**  
   Explore how keys are derived, signatures are created, and data is encrypted.

   ```bash
   cargo run --example playground_crypto_utils
   ```

3. **Voucher Lifecycle**  
   Simulate the creation, signing, and local validation of a voucher.

   ```bash
   cargo run --example playground_voucher_lifecycle
   ```

4. **Wallet Simulation**  
   Run a full simulation of a wallet interaction, including profile creation and loading.

   ```bash
   cargo run --example playground_wallet
   ```
Contributing
We welcome contributions! Please see the CONTRIBUTING.md (if available) for guidelines.

Fork the repository.

Create a feature branch (git checkout -b feature/amazing-feature).

Commit your changes (git commit -m 'Add some amazing feature').

Push to the branch (git push origin feature/amazing-feature).

Open a Pull Request.

License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

