---
name: design-decisions
description: Architectural design decisions for human_money_core including SAI, instance IDs, TOML standards, and CEL engine choices.
---

# human_money_core — Design Decisions

Dieses Dokument hält die grundlegenden Design-Entscheidungen der `human_money_core`-Bibliothek fest und dient als Referenz für die Architektur.

## 1. Datenformate

**Abbildung des Geschlechts im `Creator` Struct:**
- **Entscheidung:** Das `gender`-Feld im `Creator`-Struct wird als `Int` definiert. Geschlecht des Erstellers nach ISO 5218 (1 = male, 2 = female, 0 = not known, 9 = Not applicable).
- **Begründung:** Diese Wahl ist pragmatisch und universell einsetzbar, ohne sich auf spezifische kulturelle oder rechtliche Definitionen von Geschlecht zu beschränken.

**Voucher Standard Definitionen via TOML:**
- **Entscheidung:** Nutzung von TOML für die Definitionsdateien der Gutschein-Standards.
- **Begründung:** TOML erlaubt Kommentare, was die Lesbarkeit und Dokumentation der Standards erheblich verbessert. JSON bietet diese Möglichkeit nicht.

## 2. Wallet-Architektur

**local_voucher_instance_id:**
- **Entscheidung:** Einführung einer lokalen Instanz-ID als Primärschlüssel.
- **Begründung:** Nach einer `split`-Transaktion teilen sich mehrere Guthaben dieselbe `voucher_id`. Die Instanz-ID (Hash aus `voucher_id` und `t_id`) ermöglicht eine eindeutige Referenzierung im Wallet.

**Separated Account Identity (SAI):**
- **Entscheidung:** Kombination aus einheitlichem Web of Trust und strikter Kontotrennung.
- **Begründung:** Ein Nutzer hat einen Hauptschlüssel (Mnemonic), aber pro Kontext (Präfix oder Root) einen eigenen abgeleiteten Schlüssel (via HKDF). Dies verhindert Identitäts-Hopping und ermöglicht saubere Kontentrennung bei gleicher Identität.

## 3. Sicherheitsschichten

**WalletSeal Rollback Guard:**
- **Entscheidung:** Kryptographisches Epochen-System mit hash-verketteten Siegeln.
- **Begründung:** Verhindert das Wiedereinspielen alter Backups (Rollback-Angriff) und erkennt divergierende Wallet-Zustände (Forking).

**Storage Integrity:**
- **Entscheidung:** SHA3-256 Integritätsnachweise für alle Dateien, gebunden an das `WalletSeal`.
- **Begründung:** Erkennt sofort jede physische Manipulation an den Dateien auf dem Datenträger (Änderung, Löschung, Hinzufügung).

**Anti-Signature-Reuse-Firewall:**
- **Entscheidung:** Validierung der Signatur-Eindeutigkeit auf Ebene des binären Public Keys (`[u8; 32]`).
- **Begründung:** Verhindert Sybil-Angriffe, bei denen dieselbe Identität durch verschiedene Präfixe getarnt wird.

## 4. Geschäftslogik & Engines

**Dynamic Business Rules via CEL:**
- **Entscheidung:** Einsatz der **Common Expression Language (CEL)** für Gutschein-Validierungsregeln.
- **Begründung:** Ermöglicht flexible, komplexe Regeln in den Standards ohne Code-Änderungen im Core. CEL ist sicher, performant und nicht Turing-vollständig.

**Wallet Event Sourcing:**
- **Entscheidung:** Persistenter, append-only Ledger (`WalletEvent`) in monatlichen Chunks.
- **Begründung:** Ermöglicht Audit-Historie und Zustandswiederherstellung bei hoher Performance durch Chunking (`YYYY_MM.json.enc`).

## 5. Konfliktmanagement

**Dezentrales Konfliktmanagement & VIP-Gossip:**
- **Entscheidung:** Fokus auf lokale Overrides und "Very Important Proofs" (VIP).
- **Begründung:** Globaler Konsens wird vermieden, um Privatsphäre zu schützen und Sybil-Anfälligkeit zu reduzieren. Konflikte werden sozial oder via Layer 2 gelöst.
- **VIP Gossip:** Betrugsbeweise werden mit negativer `depth` priorisiert verbreitet.
