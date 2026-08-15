//! # src/models/signature.rs
//!
//! Defines a generic wrapper structure for detached signatures,
//! needed for the signing workflow.

use crate::models::voucher::VoucherSignature;
use serde::{Deserialize, Serialize};

/// An enum encapsulating one of the possible detached signatures.
///
/// This is used as a payload for the `SecureContainer` when a signer
/// sends their signature back to the voucher creator. This wrapper allows
/// the `Wallet` logic to remain agnostic to the specific signature type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DetachedSignature {
    // NOTE: This represents a signature *in transit*.
    // We use `VoucherSignature` as a container for the data,
    // since the structure (e.g. `role`) is identical.
    Signature(VoucherSignature),
}
