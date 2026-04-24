//! # src/wallet/tests.rs
//! Enthält die Modul-Tests für die `Wallet`-Struktur. Diese Datei ist
//! bewusst von `mod.rs` getrennt, um die Lesbarkeit zu verbessern.
//!
//! ACHTUNG: Die meisten High-Level-Integrationstests wurden in das Verzeichnis
//! `tests/wallet_api/` verschoben. Hier verbleiben nur Tests für interne
//! oder pfadabhängige Logik (pub(super)).

use bs58;
use crate::{
    test_utils::{
        ACTORS, setup_in_memory_wallet,
    },
};

/// Bündelt interne Logik-Tests (z.B. für private oder pub(super) Methoden).
mod internal_logic {
    use super::*;

    /// **Test: rederive_secret_seed Logik-Pfad (&& vs || Mutant-Abwehr)**
    #[test]
    fn test_rederive_secret_seed_logic() {
        let identity = &ACTORS.alice;
        let wallet = setup_in_memory_wallet(identity);
        
        let mut dummy_voucher = crate::models::voucher::Voucher::default();
        dummy_voucher.voucher_nonce = bs58::encode(vec![0u8; 32]).into_string(); 
        
        let mut tx = crate::models::voucher::Transaction::default();
        tx.t_type = "transfer".to_string(); // Wichtig: NICHT "init"
        tx.sender_id = Some(identity.user_id.clone()); // Wichtig: == identity.user_id
        tx.sender_remaining_amount = None; // Damit der Split-Zweig ignoriert wird
        
        dummy_voucher.transactions.push(tx);
        
        // rederive_secret_seed ist pub(super)
        let result = wallet.rederive_secret_seed(&dummy_voucher, identity);
        
        // Muss fehlschlagen, da weder init noch split.
        assert!(result.is_err(), "rederive_secret_seed should fail for a non-init, non-split transfer if logic is &&");
        assert!(result.unwrap_err().to_string().contains("No valid ownership strategy found"));
    }

    /// **Test: resolve_conflict_offline (Earliest Wins - pub(super))**
    #[test]
    fn test_resolve_conflict_offline_earliest_wins() {
        use crate::models::conflict::TransactionFingerprint;
        use crate::models::voucher::{Transaction, Voucher};
        use crate::wallet::instance::{VoucherInstance, VoucherStatus};
        use crate::models::profile::VoucherStore;
        use crate::services::conflict_manager::encrypt_transaction_timestamp;
        
        let mut store = VoucherStore::default();
        
        let t_id_early = bs58::encode(b"early").into_string();
        let t_id_late = bs58::encode(b"latee").into_string();

        let tx_early = Transaction {
            t_id: t_id_early.clone(),
            prev_hash: bs58::encode(b"prev").into_string(),
            t_time: "2024-01-01T10:00:00.000000Z".to_string(),
            ..Default::default()
        };
        let enc_early = encrypt_transaction_timestamp(&tx_early).unwrap();
        
        let tx_late = Transaction {
            t_id: t_id_late.clone(),
            prev_hash: bs58::encode(b"prev").into_string(),
            t_time: "2024-01-01T11:00:00.000000Z".to_string(),
            ..Default::default()
        };
        let enc_late = encrypt_transaction_timestamp(&tx_late).unwrap();
        
        let voucher_early = Voucher { voucher_id: "v_early".to_string(), transactions: vec![tx_early.clone()], ..Default::default() };
        let voucher_late = Voucher { voucher_id: "v_late".to_string(), transactions: vec![tx_late.clone()], ..Default::default() };
        
        store.vouchers.insert("local_early".to_string(), VoucherInstance { voucher: voucher_early, status: VoucherStatus::Active, local_instance_id: "local_early".to_string() });
        store.vouchers.insert("local_late".to_string(), VoucherInstance { voucher: voucher_late, status: VoucherStatus::Active, local_instance_id: "local_late".to_string() });
        
        let fp_early = TransactionFingerprint {
            t_id: t_id_early,
            encrypted_timestamp: enc_early,
            ds_tag: "tag".to_string(),
            u: "u".to_string(),
            blinded_id: "b".to_string(),
            layer2_signature: "sig".to_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
        };
        let fp_late = TransactionFingerprint {
            t_id: t_id_late,
            encrypted_timestamp: enc_late,
            ds_tag: "tag".to_string(),
            u: "u".to_string(),
            blinded_id: "b".to_string(),
            layer2_signature: "sig".to_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
        };
        
        // resolve_conflict_offline ist pub(super), daher hier direkt testbar.
        crate::wallet::conflict_handler::resolve_conflict_offline(&mut store, &[fp_early, fp_late]);
        
        assert!(matches!(store.vouchers["local_early"].status, VoucherStatus::Active), "early must win");
        assert!(matches!(store.vouchers["local_late"].status, VoucherStatus::Quarantined { .. }), "late must lose");
    }
}
