// tests/core_logic/security/mod.rs
// cargo test --test core_logic_tests

//! # Test-Suite für Sicherheitsaspekte und Betrugserkennung
//!
//! Diese Datei bündelt zwei kritische Bereiche der Gutschein-Sicherheit:
//!
//! 1.  **Lokale Double-Spending-Erkennung:**
//!     - Überprüfung der Fingerprint-Verwaltung.
//!     - End-to-End-Szenario zur Erkennung eines Betrugsversuchs.
//!
//! 2.  **Sicherheitslücken & Angriffs-Simulationen:**
//!     - Simulation von Angriffen durch einen böswilligen Akteur ("Hacker").
//!     - Überprüfung der Robustheit der Validierungslogik (`voucher_validation.rs`).
//!     - Fuzzing-Tests zur Prüfung der strukturellen Integrität.

// Importiert die Hilfsfunktionen, damit sie für die Submodule
// als `super::test_utils` verfügbar sind.
use human_money_core::test_utils;

// Deklariert die beiden getrennten Test-Dateien als Module.
mod double_spend;
mod standard_validation;
mod state_and_collaboration;
mod vulnerabilities;
mod double_spend_identification;
