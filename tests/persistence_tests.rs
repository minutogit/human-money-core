// tests/persistence_tests.rs
// cargo test --test persistence_tests
//!
//! Haupt-Einstiegspunkt für die Ausführung aller Persistenz-Tests.
//!
//! Diese Datei bindet das `persistence`-Modul ein, das die eigentlichen
//! Test-Dateien für `FileStorage` und `VoucherArchive` enthält. Durch diese
//! Struktur stellt `cargo test` sicher, dass alle Tests in den untergeordneten
//! Modulen gefunden und ausgeführt werden.

// Binde das Modul ein, das alle Tests zur Persistenz-Schicht enthält.
mod persistence;