# Wave-2 Testphase — Status & Auswahl (Koordinator)

**Baseline:** `cargo nextest run` → 537 passed, 3 skipped (GRÜN) vor Beginn von Phase B.
**Protokoll:** Strikt sequenziell gemäß `temp/security-audit-coordination.md` §0 Phase B. Queue: 01 → 02 → 03 → 04 → 05 → 06 → 00.

## Dedupe-Entscheidungen des Koordinators

- H-04-02 ≙ H-00-2 (Post-Commit-Archivierung): **Eigentümer A-04**, A-00 nur Querverweis.
- Lock-Vektoren getrennt: H-05-03 (Lock-Datei-TOCTOU, A-05) vs. H-00-4 (unlock()/PID-Recycling, A-00).
- crypto_utils-Mutation-Lücken (H-02-7) bleiben bei A-02; bundle_processor-Bypass (H-04-04) bei A-04.

## Ausgewählte Hypothesen für Phase B (Rest = Backlog, dokumentiert in den Modul-Dateien)

| Modul | Getestete Hypothesen (Reihenfolge) | Backlog |
| :--- | :--- | :--- |
| 01 | H-01-01, H-01-02, H-01-03, H-01-04 | H-01-05 |
| 02 | H-02-1, H-02-3, H-02-5, H-02-7 | H-02-2, H-02-4, H-02-6 |
| 03 | H-03-1, H-03-2, H-03-3, H-03-4 | H-03-5, H-03-6 |
| 04 | H-04-01, H-04-03, H-04-04, H-04-07 | H-04-05, H-04-06, H-04-08 |
| 05 | H-05-01, H-05-02, H-05-04 | H-05-03, H-05-05, H-05-06 |
| 06 | H-06-2, H-06-4, H-06-5, H-06-6 | H-06-1, H-06-3 |
| 00 | H-00-1, H-00-3 (+ H-00-4 falls Budget) | H-00-5 |

## Fortschritt

| # | Modul | Status | Ergebnis |
| :--- | :--- | :--- | :--- |
| 1 | 01 | ✅ fertig | F07 CONFIRMED-PENDING (`#[ignore]`, DLEQ-Wire-Format nötig); F08/F09/F10 CONFIRMED+FIXED; Modul-Suite + Konflikt-Suiten grün |
| 2 | 02 | ✅ fertig | 02-04/02-06 CONFIRMED+FIXED (signatures.rs, crypto_identity.rs); 02-05 CONFIRMED-PENDING (`#[ignore]`, Seal-History-Chain-Walk nötig); 02-07 False-Positive→Mutant-Killer-Guards; crypto-Filter 38 grün |
| 3 | 03 | ✅ fertig | M03-003/004/005 CONFIRMED+FIXED (Lexikografik-Bypass, Standard-Overwrite, Eval-Budgets); M03-006 False-Positive→Kontrolltests; 19/19 + Regression 498 grün |
| 4 | 04 | ✅ fertig | SA04-04/05 CONFIRMED+FIXED (Snapshot-Rollback, Anchor-Separation); SA04-06 Mutant-Kill-Guard (Code korrekt); SA04-07 False-Positive+Guard; Full-Suite-Verify 558 grün |
| 5 | 05 | ✅ fertig | SA05-04/05/06 CONFIRMED+FIXED (store_binding_hash-Rollback-Erkennung, Plaintext-Downgrade-Rejektion, Drop-Zeroize); Modul-Filter 6 grün |
| 6 | 06 | ✅ fertig | SA06-08/09/10 CONFIRMED+FIXED (Mixed-Bundle-Oracle, Container-Rebinding, Display-Name-Sanitizing); SA06-07 CONFIRMED-PENDING (`#[ignore]`, Spec-Flaw); Modul 9 grün |
| 7 | 00 | ✅ fertig | WILDCARD-01/02/03/04 CONFIRMED+FIXED (Seal-Kompensation, Best-Effort-Archivierung, Reload-Seal-Verifikation, Lock/Overflow); PID-Recycling dokumentierte Restlimitation |

## Abschluss (Koordinator)

- **Finale Full-Suite:** `cargo nextest run` → **569 passed / 0 failed / 6 skipped** (Baseline 537/3; +32 neue Audit-Tests, 6 by-design Ignores gesamt).
- **Cross-Review-Hinweis aufgelöst:** A-00-Fix in `wallet/transaction_handler.rs` (Post-Commit-Archivierung best-effort) greift nicht A-04s SA04-03/04-Garantien an — beide Tests grün im Final-Run.
- **Offene architektonische Arbeitspunkte (CONFIRMED-PENDING):**
  1. AUDIT-01-F07: DLEQ-Wire-Format-Erweiterung für TrapData (m↔Key-Binding) — Test `#[ignore]`
  2. HMC-SEC-02-05: Seal-History-Sync mit Chain-Walk (Fork-Erkennung bei Nonce-Distanz > +1) — Test `#[ignore]`
  3. HMSEC-SA06-07: Trust-Assertion-Spec-Flaw (Signatur bindet nur assertion_id) — Test `#[ignore]`, Spec-Fix zuerst
- **Dokumentation:** Reports je Modul unter `docs/security/ai-audits/reports/`; Hypothesen-Dateien mit Phase-B-Status je Hypothese.
- **Keine Git-Commits** durchgeführt (nur auf explizite Anweisung).
