//! # src/archive/file_archive.rs
//!
//! Eine Implementierung des `VoucherArchive`-Traits, die jeden Gutschein-Zustand
//! als separate JSON-Datei in einer strukturierten Verzeichnishierarchie speichert.
use super::{ArchiveError, VoucherArchive};
use crate::models::voucher::Transaction;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::utils::to_canonical_json;
use std::{fs, path::PathBuf};

/// Eine Implementierung des `VoucherArchive`-Traits, die auf dem Dateisystem basiert.
///
/// Die Struktur ist: `base_path/voucher_id/transaction_id.json`
pub struct FileVoucherArchive {
    archive_directory: PathBuf,
}

impl FileVoucherArchive {
    /// Erstellt eine neue `FileVoucherArchive`-Instanz für ein bestimmtes Basisverzeichnis.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileVoucherArchive {
            archive_directory: path.into(),
        }
    }

    // TODO: Eine Bereinigungsfunktion (`purge_deep_archive`) implementieren,
    //       die Zustände nach Ablauf einer Aufbewahrungsfrist löscht.
}

impl VoucherArchive for FileVoucherArchive {
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        _owner_id: &str,
        _standard: &VoucherStandardDefinition,
    ) -> Result<(), ArchiveError> {
        // TODO: Die Archiv-Dateien sollten verschlüsselt werden.

        // Jeder Zustand wird durch die ID der letzten Transaktion eindeutig identifiziert.
        let last_tx = voucher.transactions.last().ok_or_else(|| {
            ArchiveError::Generic("Cannot archive voucher with no transactions.".to_string())
        })?;

        // Erstelle ein Unterverzeichnis für jeden Gutschein, um die Zustände zu gruppieren.
        let voucher_dir = self.archive_directory.join(&voucher.voucher_id);
        fs::create_dir_all(&voucher_dir)?;

        let file_path = voucher_dir.join(format!("{}.json", &last_tx.t_id));
        if file_path.exists() {
            return Ok(()); // Bereits archiviert, alles in Ordnung.
        }

        let json_content = to_canonical_json(voucher)?;

        // Atomares Schreiben
        let temp_file_path = voucher_dir.join(format!("{}.json.tmp", &last_tx.t_id));
        fs::write(&temp_file_path, json_content)?;
        fs::rename(&temp_file_path, &file_path)?;

        Ok(())
    }

    fn get_archived_voucher(&self, voucher_id: &str) -> Result<Voucher, ArchiveError> {
        let file_path = self.archive_directory.join(format!("{}.json", voucher_id));

        if !file_path.exists() {
            return Err(ArchiveError::NotFound);
        }

        let file_content = fs::read(file_path)?;
        let voucher: Voucher = serde_json::from_slice(&file_content)?;
        Ok(voucher)
    }

    fn find_transaction_by_id(
        &self,
        t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, ArchiveError> {
        // Durchsuche alle Unterverzeichnisse (jedes `voucher_id`-Verzeichnis).
        for voucher_dir_entry in fs::read_dir(&self.archive_directory)? {
            let voucher_dir_path = voucher_dir_entry?.path();
            if voucher_dir_path.is_dir() {
                for entry in fs::read_dir(voucher_dir_path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && path.extension().map_or(false, |s| s == "json") {
                        if let Ok(voucher) = serde_json::from_slice::<Voucher>(&fs::read(&path)?) {
                            if let Some(tx) = voucher.transactions.iter().find(|t| t.t_id == t_id) {
                                return Ok(Some((voucher.clone(), tx.clone())));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
    fn find_voucher_by_tx_id(&self, t_id: &str) -> Result<Option<Voucher>, ArchiveError> {
        // Nutze die bereits vorhandene Logik von `find_transaction_by_id`.
        if let Some((voucher, _)) = self.find_transaction_by_id(t_id)? {
            Ok(Some(voucher))
        } else {
            Ok(None)
        }
    }
}
