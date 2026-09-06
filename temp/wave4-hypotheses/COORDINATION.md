# Wave 4 — Koordinator-Sichtung (Phase A → B Übergang)

**Baseline:** 616 passed / 8 skipped (Commit `0910ae6`, Flaky-Test stabilisiert).
**Eingang:** 25 Hypothesen aus 7 Modulen. **Auswahl für Phase B:** 17 Beweis-Tests in 7 Gruppen.

## Auswahl & Zuordnung (Phase B)

| Gruppe | Findings | Sev. | Testdatei |
| :--- | :--- | :--- | :--- |
| B0 Wildcard | WH4-00-001 (C), -002 (H), -003 (H), -004 (M, optional) | C/H/H/M | `tests/security_audit_wave4_wildcard.rs` |
| B1 Traps | WH4-01-201 (H), -202 (M), -203 (M) | H/M/M | `tests/security_audit_wave4_traps.rs` |
| B2 Crypto | WH4-02-302 (M), WH4-02-301+WH4-06-704 kombiniert (Low-Order-EPK-Parität, Hardening-Beweis) | M/L | `tests/security_audit_wave4_crypto.rs` |
| B3 CEL | WH4-03-101 (C, von W3 explizit auf „future wave" vertagt → diese Welle), -102 (H), -103 (M) | C/H/M | `tests/security_audit_wave4_cel.rs` |
| B4 Integrity | WH4-04-501 (H), -502 (L), K4 (M, optional) | H/L/M | `tests/security_audit_wave4_integrity.rs` |
| B5 Storage | WH4-05-001 (H), -002 (M), -003 (M, N7-Deepdive), -004 (L, optional) | H/M/M/L | `tests/security_audit_wave4_storage.rs` |
| B6 Privacy | WH4-06-701 (M) | M | `tests/security_audit_wave4_privacy.rs` |

## Nicht in Phase B (Disposition)

| Finding | Grund |
| :--- | :--- |
| WH4-02-303 (L) | Vermutlich FALSE POSITIVE: `sanitize_user_id` ist per Unit-Test beabsichtigtes Design (Modul-02-Agent selbst). Nur Report-Notiz. |
| WH4-02-304 (L) | LIKELY-FALSE-POSITIVE, zirkulärer Trust-Anker; Disposition nur dokumentarisch (Report). |
| WH4-02-305 (L) | Kein Defekt (empirisch widerlegt); Proptest-Pinning als Beigabe im Fix-Round möglich. |
| WH4-06-702, -703 | KNOWN-OPEN (N8/W6) → laut User-Entscheidung „nur neue Findings" zurückgestellt. |
| WH4-04-N4 | KNOWN-OPEN (Error-Taxonomie); Dokumentationsthema, kein Beweistest. |
| audit_02_11, SA04-08, Seal-History, sa06_07 | OUT OF SCOPE (User-Entscheidung). |

## Auflösungen aus Phase A

- **W3 (Prefix=None):** durch V3/SST-Rewrite erledigt (punkt-basiert, prefix-agnostisch) → Triage-Report-Notiz kann geschlossen werden.
- **K3:** striktes Scalar-Parsing live bestätigt (`parse_canonical_scalar`) → erledigt.

## Fix-Reihenfolge (Phase D, vorläufig, nach Severity/Betroffenheit)

1. WH4-00-001 (+003 teils gleiche Ingestion-Stelle), dann -002 (gleiche Dateien)
2. WH4-04-501 (Issuance-Attribution, chain.rs/signatures.rs)
3. WH4-03-101 (CEL Struct-Arm), -102 (Standard-Pinning; größter Fix), -103 (String-Arm)
4. WH4-05-001+002 gemeinsam (Manifest-Per-Record-Binding), -003 (Empty-PW-Guard)
5. WH4-01-201 (Import-Gate ephemeral lane), -202 (init trap_data), -203 (Bucket-Cap)
6. WH4-06-701 (Notes-Sanitizer), WH4-02-302 (Container-Empty-PW), Low-Order-EPK-Hardening
7. WH4-00-004/K4/502 falls bewiesen + Budget
