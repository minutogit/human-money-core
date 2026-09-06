# Wave-3 Testphase — Status & Auswahl (Koordinator)

**Baseline:** `cargo nextest run` → **585 passed / 0 failed / 5 skipped** (GRÜN) an HEAD `b006cfb` vor Beginn von Phase B.
**Protokoll:** Strikt sequenziell gemäß `temp/security-audit-coordination.md` §0 Phase B. Queue: 01 → 02 → 03 → 04 → 05 → 06 → 00.
**Auslöser:** 3 Commits seit Wave 2 (`fdfeb80`, `d31bd89` V2-Digest, `b006cfb` V3/SST) — kompletter Trap-Protocol-Rewrite.

## Dedupe-Entscheidungen des Koordinators (Sichtung)

| Thema | Hypothesen | Eigentümer | Auflösung |
| :--- | :--- | :--- | :--- |
| Stealth/Guard-less R5-Witness-Gate tot | WH3-01-103 ≙ WH3-02-201 ≙ (Teil von WH3-00-902) | **A-01** (End-to-End) | A-02/A-00 nur Querverweis |
| Junk-Shard-Extraktion → Attribution | WH3-01-102 (Evasion/DoS) ≠ WH3-02-202 (Fehlattribution) | **beide behalten** (verschiedene Invarianten: Availability vs. Misattribution) | |
| Leere Shards → Init-Masking | WH3-02-203 (L1-Chain-Akzeptanz) ≠ WH3-00-902 (Netz-Ingress-Purge → DS-Evasion) | **beide behalten** | |
| V2→V3 Migration | WH3-05-502 (Storage-Serde-Drop) ≠ WH3-00-901 (Wallet-Stranding/State) | **beide behalten** | |
| Bucket-Stuffing/Key-Desync | WH3-01-101 ≙ WH3-02-206 ≙ WH3-01-107 (fold) | **A-01** | A-02 cross-ref |
| Ingress ohne Input-Bindung | WH3-04-403 (Konflikt-Record-Verschmutzung ohne Quarantäne) | **A-04** (abgegrenzt von 101) | |

## Phase-B-Auswahl pro Modul (Reihenfolge innerhalb des Moduls)

| Modul | Getestete Hypothesen | Backlog |
| :--- | :--- | :--- |
| 01 | WH3-01-101 (C), -103 (H), -102 (H), -104 (M), -105 (M), -106 (M) | -107 (L, fold in 101) |
| 02 | WH3-02-202 (H), -203 (M), -204 (M), -205 (M) | -206 (cross-ref 101) |
| 03 | WH3-03-301 (C), -302 (H), -303 (H), -304 (M) | — |
| 04 | WH3-04-401 (C), -402 (H), -403 (M), -404 (L, optional) | — |
| 05 | WH3-05-501 (H), -502 (H), -504 (H), -505 (M), -506 (M) | -503 (M), -507 (L) |
| 06 | WH3-06-601 (H), -603 (H), -602 (M), -604 (M), -605 (M) | — |
| 00 | WH3-00-902 (C, minus Stealth-R5/A-01-Anteil), -901 (C, minus Storage/A-05-Anteil), -903 (H), -904 (M), -905 (M) | — |

## Fortschritt

| # | Modul | Status | Ergebnis |
| :--- | :--- | :--- | :--- |
| 1 | 01 | ✅ fertig (Phase B klassisch) | 6/6 Hypothesen bestätigt: F11/F13/F14/F15/F16 CONFIRMED+FIXED; F12 CONFIRMED-PENDING → in Modul-04-Runde geschlossen (ent-ignored) |
| 2 | 02 | ✅ fertig | 02-08 primitiv FIXED (Protokoll-Korroboration PENDING); 02-09 ent-ignored & grün (via SA04-09 + Wildcard-Init-Regel); 02-10 CONFIRMED+FIXED (NonPrimeOrderKey); 02-11 dokumentiert PENDING (V3.x-Digest-Migration, Plan im Report) |
| 3 | 03 | ✅ fertig | M03-007..010 alle CONFIRMED+FIXED (Panic-Guard fail-closed, Map-Comprehension-Rejekt [Test war initial false-negative], Traversal-Symmetrie, Usage-Time-Signatur-Re-Verifikation); 24/24 grün |
| 4 | 04 | ✅ fertig | SA04-08 = bestätigtes Protocol-Break-Thema (HMC_TX_AUTH_V4-Design im Report, `#[ignore]`); SA04-09/10 CONFIRMED+FIXED |
| 5 | 05 | ✅ fertig | SA05-07..11 alle CONFIRMED+FIXED (keyed Binding-Hash, Legacy-Schema-Gates hart, Archiv-Manifest+Location-Binding, Empty-PW-Guard, Read-Sanitizing) |
| 6 | 06 | ✅ fertig | SA06-11..15 alle CONFIRMED+FIXED (11 teils per Synergie mit validate_shard_structure); audit_02_11 bleibt PENDING (Harness unpassbar + Cross-Module-Migration) |
| 7 | 00 | ✅ fertig | WILDCARD-05/06/07/08/09 alle CONFIRMED+FIXED (Init-Regel: Genesis ⇔ none/none; Protocol-Epoch-Sweep markiert Incomplete statt Active; is_own_transaction kanonisch ×2 Rebuilds; Overflow ×3; L2-Reload-Disziplin) |

## Abschluss (Koordinator)

- **Finale Full-Suite:** `cargo nextest run` → **616 passed / 0 failed / 8 skipped** (Baseline 585/5 → +31 neue Wave-3-Audit-Tests netto).
- **Bilanz:** 37 Hypothesen → 30 bestätigt, davon 27 gefixt; 3 dokumentierte PENDINGs (SA04-08/V4-Design, HMC-SEC-02-05 Seal-History, audit_02_11 V3.x-Digest + audit_02_08 Korroboration-Policy, sa06_07 Spec-Flaw aus Wave 2); 2 Test-Setup-Bugs repariert (SA04-08-Fixture, wildcard_07-Fixture).
- **Pipeline:** Phase A parallel (7 Agenten) → Write-only parallel (5 Agenten, 17 Tests ohne Cargo) → zentrale sequenzielle Verifikation → 5 sequenzielle Fix-Runden (03 → 04 → 05 → 06 → 00).
- **Keine Git-Commits** (nur auf explizite Anweisung).
