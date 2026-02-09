# Dokumentation: Human Money Core

Willkommen in der Dokumentation der `human_money_core` Bibliothek.

## Struktur

Diese Dokumentation ist hierarchisch aufgebaut, um einen einfachen Einstieg und gleichzeitig tiefes technisches Verständnis zu ermöglichen.

### 1. Einstieg & Überblick

*   **[Systemarchitektur](system-architektur.md)**
    *   Starten Sie hier!
    *   Erklärt die Grundprinzipien: Was ist ein Gutschein? Wie funktioniert Offline-Geld?
    *   Definiert die Hauptkomponenten: Wallet, Voucher, Identity.

### 2. Detaillierte Spezifikationen

*   **[Hybride Privatsphäre & Offline-Sicherheit](spec/Spezifikation%20-%20Hybride%20Privatsph%C3%A4re%20und%20Offline-Sicherheit%20f%C3%BCr%20digitale%20Gutscheine.md)**
    *   Technische Referenz für Implementierer.
    *   Beschreibt exakt die kryptographischen Verfahren (Ed25519, Pedersen Commitments, ZK-Proofs).
    *   Definiert die Datenstrukturen für Transaktionen und Privacy Modes.

## Weitere Ressourcen

*   **Code-Dokumentation:** Führen Sie `cargo doc --open` aus, um die API-Referenz direkt aus dem Source Code zu generieren.
*   **Projekt-README:** Die [Haupt-README](../../README.md) im Wurzelverzeichnis enthält Installationsanweisungen und Beispiele ("Playgrounds").
