# human_money_core Examples

This directory contains examples and playgrounds showcasing how to integrate and use the `human_money_core` library. These files demonstrate core cryptographic concepts, wallet facade usage, Layer 2 integration, and full voucher lifecycles.

## Running the Examples

You can run any example using `cargo run --example <name>`:

| Example Name | Description | Command |
| :--- | :--- | :--- |
| **`check_issuer`** | Resolves the developer's issuer signing key to its corresponding `user_id`. | `cargo run --example check_issuer` |
| **`l2_mock_node`** | Implements a simplified, functional Layer 2 simulation demonstrating status queries, lock requests, and response envelopes. | `cargo run --example l2_mock_node` |
| **`l2_playground`** | Shows how Layer 2 and the "Chain of Authority" (CoA) model link transaction history and prevent double-spending. | `cargo run --example l2_playground` |
| **`playground_crypto_utils`** | Exercises the cryptographic module: mnemonic generation, keypair derivation, Ed25519-to-X25519, and Diffie-Hellman exchanges. | `cargo run --example playground_crypto_utils` |
| **`playground_double_spend_analysis`** | Demonstrates how the system derives identical double-spend tags (DS-Tags) even if amount/recipient details differ. | `cargo run --example playground_double_spend_analysis` |
| **`playground_utils`** | Demonstrates internal timezone-independent timestamp calculations and year-end boundaries. | `cargo run --example playground_utils` |
| **`playground_voucher_lifecycle`** | Walks through a full voucher life: creation, async signing by multiple guarantors, activation, partial splitting, and ownership transfer. | `cargo run --example playground_voucher_lifecycle` |
| **`playground_wallet`** | Demonstrates the high-level `Wallet` facade, multi-transfers, and registration of anonymous transaction fingerprints. | `cargo run --example playground_wallet` |
| **`resign_freetaler`** | Helper script to resign the FreeTaler v1 Standard TOML after modifications to maintain hash signature validity. | `cargo run --example resign_freetaler` |

## Documentation

Each file contains detailed `//!` rustdoc header comments. When generating documentation for the crate:

```bash
cargo doc --no-deps --open
```

The examples will be automatically included in the documentation index under the "Examples" section.
