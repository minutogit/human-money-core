# Human Money Core

*(Formerly Decentralized Voucher System - Core Library)*

## Overview

**Human Money Core** (`human_money_core`) is the foundational Rust library powering the [Human Money / Minuto](https://github.com/minutogit) ecosystem. It implements the protocol for a decentralized, trust-based, and electronic voucher payment system.

Unlike traditional blockchains, this system does **not** rely on a global ledger. Instead, it uses a unique approach where every voucher carries its own transaction history (micro-chains), enabling true peer-to-peer, offline-capable digital cash with cryptographic integrity.

## Key Features

* **Global-Ledger-Free:** Transactions are stored within the voucher files themselves. No central server or blockchain is required to transfer value.
* **Offline-First:** Designed to work in environments with intermittent or no internet connectivity. Wallets can exchange vouchers directly (e.g., via Bluetooth, NFC, or file transfer).
* **Double-Spend Detection:** Uses a privacy-preserving "Gossip Protocol" and "Transaction Fingerprints" to detect double-spending attempts across the network without revealing transaction details.
* **Storage Agnostic:** The core logic is decoupled from persistence via a `Storage` trait. A secure, encrypted file-based implementation (`FileStorage`) is provided out-of-the-box.
* **Separated Account Identity (SAI):** Supports strict account separation (e.g., PC vs. Mobile) derived from a single mnemonic, preventing state inconsistencies.
* **Voucher Standards:** Supports flexible, TOML-defined standards for different types of vouchers (e.g., Minuto, Silver, etc.).
* **Secure:** Implements robust cryptography using Ed25519 for signatures and X25519/ChaCha20-Poly1305 for encrypted data containers (`SecureContainer`).

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

