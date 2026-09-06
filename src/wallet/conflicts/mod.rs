//! # src/wallet/conflicts/mod.rs
//!
//! Contains the implementation of `Wallet` methods responsible for
//! double-spend detection, fingerprint management, proof handling
//! as well as storage maintenance, cleanup and helper utilities.
//! This module consolidates the former `conflict_handler.rs` and
//! `maintenance.rs` into a single coherent domain.

mod proofs;
mod maintenance;
mod ingress;
mod gossip;

pub(crate) use ingress::resolve_conflict_offline;
