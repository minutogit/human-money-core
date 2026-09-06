# Security-Audit-Koordination & Fehler-Zusammenfassung (Module 00–06)

> **Zielgruppe:** Unteragenten (Sub-Agents), die die Audits aus `docs/security/ai-audits/` ausführen.
> **Quellen:** `00_general_adversarial_wildcard.md` … `06_privacy_and_protocol_bundles.md`, `DESIGN_INTENT_TRIAGE.md`, `README.md` (alle in `docs/security/ai-audits/`).
> **Stand:** 2026-08-24 — basierend auf dem aktuellen Testbestand in `tests/`.

---

## 0. Arbeitsprotokoll für Unteragenten (VERBINDLICH)

### Phase A — Hypothesenphase (PARALLEL erlaubt)

1. Jeder Agent bearbeitet **ausschließlich sein Modul** (Zuordnung siehe §1).
2. Der Agent liest die Scope-Dateien seines Moduls (siehe jeweiliger Modulabschnitt) und schreibt **alle Vermutungen** in seine Hypothesen-Datei:
   - `temp/security-hypotheses/module-01.md` … `module-06.md`, `module-00-wildcard.md`
3. **Hypothesen-Template** (pro Vermutung ein Block):

   ```markdown
   ## H-[MODUL]-[NR] — [Kurztitel]
   - **Vermutung:** Was genau könnte falsch/bypassbar sein und warum?
   - **Betroffene Invariante:** Welche Kern-Invariante (§2) würde gebrochen?
   - **Zielcode:** `src/pfad/datei.rs` + Funktion/Zeile
   - **Geplanter Fail-First-Test:** Welches Soll-Verhalten würde der Test asserten?
     (Der Test MUSS auf unpatched Code FEHLSCHLAGEN, um die Lücke zu beweisen.)
   - **Triage-Vorabcheck:** Könnte es `[INTENTIONAL DESIGN REQUIREMENT]` sein?
     (4-Fragen-Check aus DESIGN_INTENT_TRIAGE.md grob durchdenken)
   - **Priorität:** CRITICAL / HIGH / MEDIUM / LOW
   ```

4. In Phase A wird **KEIN Code geändert, KEIN Test geschrieben, KEIN `cargo`-Befehl ausgeführt**, der das Build-Verzeichnis sperrt (`cargo test/build/check` sind verboten; reines Lesen ist erlaubt). Dadurch ist volle Parallelität kollisionsfrei.
5. Am Ende von Phase A meldet jeder Agent nur den Pfad seiner Hypothesen-Datei zurück.

### Phase B — Testphase (STRIKT SEQUENZIELL, eine Sperre global)

1. Es arbeitet **immer nur EIN Agent gleichzeitig** am Testen. Reihenfolge (Queue): `01 → 02 → 03 → 04 → 05 → 06 → 00`.
   - Begründung: 01–06 haben bestehende Testdateien mit etablierten Fixtures; 00 (Wildcard) läuft zuletzt und braucht den breitesten Blick, um Dopplungen zu vermeiden.
2. Der aktive Agent darf **nur** diese Dateien anfassen:
   - seine Testdatei: `tests/security_audit_module_XX_*.rs` (siehe §1)
   - seine Hypothesen-Datei: `temp/security-hypotheses/module-XX.md`
   - seinen Report: `docs/security/ai-audits/reports/XX_*_report.md`
3. **Vorgehen pro Hypothese (nach und nach, nicht alles parallel im File):**
   1. Eine Vermutung aus der Hypothesen-Datei aufnehmen → Fail-First-Test schreiben.
   2. Nur den eigenen Modul-Filter laufen lassen:
      `cargo nextest run security_audit_module_XX --status-level fail`
   3. Ergebnis dokumentieren: FAIL = Schwachstelle bestätigt → Triage → ggf. Fix; PASS ohne Fix-Bedarf = False Positive / bereits geschützt → als solches markieren.
   4. Erst dann zur nächsten Hypothese übergehen.
4. **Kollisionsregeln (hart):**
   - NIEMALS parallel `cargo nextest/test/build` aufrufen (gemeinsamer Target-Lock, gemeinsame Fixture-Tempdirs).
   - Tests nutzen ausschließlich eigene Temp-Dirs (`tempfile::tempdir()`) — keine festen Pfade unter `temp/` oder `/tmp`, die andere Module nutzen könnten.
   - Keine Änderungen an fremden Testdateien, Reports oder an gemeinsam genutzten Fixtures (`tests/wallet_api/*`) ohne Absprache mit dem Koordinator.
   - Fixes in `src/` erst NACH erfolgreichem Triage-Ergebnis `[CONFIRMED VULNERABILITY]` und immer modul-lokal; danach eigenen Filter erneut laufen lassen.
5. **Am Ende (einmalig, sequenziell):** Komplettsuite `cargo nextest run --status-level fail` durch den Koordinator, danach Triage-Summary-Tabelle je Report aktualisieren.

### Geltende Projektregeln (aus AGENTS.md / README des Audit-Suites)

- Kommentare/Dokumentation im Code: strikt Englisch.
- Standard-Metadaten-Docblock je Finding (Finding-ID, Severity, CWE, Target, Threat Model, Impact, Root Cause, Remediation, Test Semantics) — Vorlage in `docs/security/ai-audits/README.md`.
- Finding-ID-Schema: `AUDIT-0X-[KURZ]-[NR]`; bereits verwendete Schemata je Modul beibehalten (siehe §2).
- Fail-First-Invariantentests: Test asserted Soll-Verhalten und muss auf unpatched Code fehlschlagen.
- `test-utils`-Feature niemals in Release-Builds aktivieren.

---

## 1. Exklusive Datei-Zuordnung (Eigentümerschaft = Kollisionsschutz)

| Agent | Audit-Prompt | Hypothesen-Datei | Testdatei (exklusiv) | Report |
| :--- | :--- | :--- | :--- | :--- |
| A-01 | `01_double_spend_and_conflicts.md` | `temp/security-hypotheses/module-01.md` | `tests/security_audit_module_01_traps.rs` | `reports/01_traps_conflicts_report.md` (existiert) |
| A-02 | `02_cryptography_and_identity.md` | `module-02.md` | `tests/security_audit_module_02_crypto.rs` | `reports/02_crypto_report.md` |
| A-03 | `03_standards_and_cel_engine.md` | `module-03.md` | `tests/security_audit_module_03_cel.rs` | `reports/03_cel_report.md` |
| A-04 | `04_transaction_and_state_integrity.md` | `module-04.md` | `tests/security_audit_module_04_integrity.rs` | `reports/04_integrity_report.md` |
| A-05 | `05_storage_and_key_persistence.md` | `module-05.md` | `tests/security_audit_module_05_storage.rs` | `reports/05_storage_report.md` |
| A-06 | `06_privacy_and_protocol_bundles.md` | `module-06.md` | `tests/security_audit_module_06_privacy.rs` | `reports/06_privacy_report.md` |
| A-00 | `00_general_adversarial_wildcard.md` | `module-00-wildcard.md` | `tests/security_audit_wildcard.rs` (NEU) | `reports/00_wildcard_report.md` |

Zusätzlich existiert (historisch, Modul 01 zugeordnet): `tests/security_audit_conflict_and_traps.rs` — gehört in A-01s Verantwortungsbereich, nicht separat antasten.

---

## 2. Fehler- & Prüfungszusammenfassung je Modul

Legende: ✅ = abgedeckt durch bestehenden Test · 🔍 = offen, als Hypothese zu prüfen · 🛡️ = als Intentional-Design geschützt/invariant

### Modul 01 — Double-Spend Trap, DS-Tags & Konflikte
**Scope:** `services/trap_manager.rs`, `services/conflict_manager.rs`, `app_service/conflict_handler.rs`, `models/conflict.rs`, `services/l2_gateway.rs`, `models/layer2_api.rs`

Kern-Invarianten: DS-Tag u = SHA3-256(prev_hash + sender_ephemeral_pub) hängt NUR von Input-Daten ab; Slope m deterministisch via HKDF(SendPrivKey, prev_hash); Schnorr-NIZK ohne Preisgabe von m; Identitäts-Rekonstruktion V = u·m + ID.

**Bestätigte Fehler (remediated, Tests vorhanden):**
- ✅ F01 (High): Gossip-Poisoning → falsche Quarantäne via gefälschter `encrypted_timestamp` (XOR-Key öffentlich ableitbar). Test: `f01_gossip_poisoning_must_not_quarantine_local_voucher`.
- ✅ F02 (Medium): Schnorr-Response-Malleability (`from_bytes_mod_order` akzeptierte non-kanonische s). Test: `f02_verify_trap_rejects_non_canonical_schnorr_response`.
- ✅ F05 (High): Gefälschte did:key-Attribution beim Proof-Import (Import-Gate fehlte). Test: `f05_import_proof_rejects_forged_did_key_attribution_claim`.
- ✅ F06 (Low): Placeholder-Substring-Skip schwächt ≥2-Trap-Attribution. Test: `f06_placeholder_t_type_must_not_weaken_trap_count`.
- ✅ Weitere (ältere Suite `security_audit_conflict_and_traps.rs`): Stealth-Framing, manipulierte blinded-ID, zeitversetzte Double-Spends, non-kanonisches U, forged Proof-Import, echter Signed-Proof quarantänt Verlierer.

**Offene Prüfvektoren für Phase A (🔍):**
- 🔍 DS-Tag-Kollision/-Manipulation: gleicher Input-Anker zweimal unter unterschiedlichen Identitäten/Prefixen ausgeben → unterschiedliche DS-Tags, Kollisionsdetektion umgangen?
- 🔍 False Dispute Injection: gefälschte L2-Envelopes/Konfliktberichte, die Quarantäne ohne authentische Traps auslösen (über F01/F05 hinaus).
- 🔍 Identitäts-Rekonstruktion Edge-Cases: Division durch Null bei identischem U, identische R-Punkte, Skalar-Grenzwerte → falsche Attribution statt Fehler.
- 🔍 Prefix-/Ableitungs-Angriffe auf `verify_stored_proofs_against_identity` (root vs. prefixed account Ableitung).

### Modul 02 — Kryptografie, Identität & Forward Secrecy
**Scope:** `services/crypto_identity.rs`, `crypto_symmetric.rs`, `crypto_keys.rs`, `crypto_dh.rs`, `crypto_utils.rs`, `signature_manager.rs`, `app_service/seal_handler.rs`, `models/seal.rs`, `models/signature.rs`

Kern-Invarianten: Idle-Vouchers speichern nur Hash-Commitments (SHA3-256) des Empfänger-Keys; Public-Key-Firewall (32-Byte-Rohkeys, keine Rollen-Konflikte trotz did:key-Präfixe); kanonische Signatur-Payloads.

**Bestätigte Fehler (Tests vorhanden):**
- ✅ SA02-01: Forged Privacy Guard mit Low-Order-Ephemeral-Key muss abgelehnt werden (`audit_02_01_...`).
- ✅ SA02-02: Non-kanonische Signer-ID muss in Signaturvalidierung abgelehnt werden (`audit_02_02_...`).
- ✅ SA02-03: Ed25519-Scalar-Malleability muss abgelehnt werden (`audit_02_03_...`, Regression Guard).

**Offene Prüfvektoren (🔍):**
- 🔍 Payload-Komplettheit: sind ALLE strukturellen Felder (Beträge, Daten, Identitäten, Standard-IDs, Parent-Hashes) in der Signatur-Payload, oder tauschbare unsigned Metadaten?
- 🔍 Role-Obfuscation-Bypass: Creator == Guarantor über did:key-Präfixe/Aliase (`company:x@did…` vs `personal:y@did…`)?
- 🔍 HKDF-/Nonce-Hygiene: ChaCha20-Poly1305 Nonce-Wiederverwendung, statische/ableitbare Nonces, schwache Entropie.
- 🔍 Preimage Exposure: liegt `sender_ephemeral_pub` vor Transaktionsautorisierung im Klartext vor?
- 🔍 Container-Seals: Re-Encoding/Modifikation gültiger Seals ohne Invalidierung (Malleability jenseits von Scalar-Fällen).
- 🔍 Aus `temp/uncovered_code.md` (Mutation-Lücken, KRITISCH): `crypto_utils::validate_user_id` (Negation-Bypass, Zeile ~817), `build_hkdf_info` (Salt/Info), `get_short_hash_from_user_id` (Index-Logik).

### Modul 03 — Standards & CEL-Engine
**Scope:** `services/dynamic_policy_engine.rs`, `services/standard_manager.rs`, `models/voucher_standard_definition.rs`, `app_service/standard_container_handler.rs`

Kern-Invarianten: 100 % deterministische CEL-Auswertung; Fail-Closed bei Fehlern/fehlenden Kontextvariablen; Standard-Integrität über Container-Hash-Chain.

**Bestätigte Fehler (Tests vorhanden):**
- ✅ M03-001: Bracket-Zugriff `[]` über fehlende Felder lieferte nicht fail-closed; `!`-Negation über absent field; Out-of-Bounds-Index-Null-Propagation; Sender-Disclosure-Regel per Feld-Omission bypassbar.
- ✅ M03-002: Negative Scale/Grenzwerte bei Decimals müssen abgelehnt werden.
- ✅ Kontroll-Tests: Dot-Access, Ordering-Vergleiche, ungebundene Variablen sind bereits fail-closed.

**Offene Prüfvektoren (🔍):**
- 🔍 Standard-Tampering: modifizierte Standard-TOML oder injizierte CEL-Logik im Bundle, ohne Hash-Chain-Bruch? Container-Swap gegen semantisch gleichen, aber entschärften Standard?
- 🔍 Type-Juggling/Precision: u64/u128-Timestamps & `rust_decimal`-Beträge werden beim CEL-Mapping unsicher in f64/int koerziert?
- 🔍 ReDoS/CPU-Exhaustion: craftete CEL-Ausdrücke (Schachtelungstiefe, Rekursion, riesige Listen) → Timeout/Abbruch garantiert?
- 🔍 Determinismus native vs. wasm32 bei Float-/Decimal-Randwerten.

### Modul 04 — Transaktionslogik & State-Integrity
**Scope:** `services/bundle_processor.rs`, `secure_container_manager.rs`, `integrity_manager.rs`, `decimal_utils.rs`, `models/voucher.rs`, `models/secure_container.rs`

Kern-Invarianten: Σ Inputs = Σ Outputs + Fees (keine Wertschöpfung aus dem Nichts); Split-Anchor-Separation (Transfer- ≠ Change-Branch-Keys); Panic-Freiheit auf untrusted Input.

**Bestätigte Fehler (Tests vorhanden):**
- ✅ SA04-01: Receive-Bundle panic-frei bei Amount-Summen-Overflow (`sa04_01_...`).
- ✅ SA04-02: Chain-Validation panic-frei bei Split-Amount-Overflow (`sa04_02_...`).
- ✅ SA04-03: Abgebrochener Multi-Transfer hinterlässt Archive unverändert (`sa04_03_...`).

**Offene Prüfvektoren (🔍):**
- 🔍 Conservation/Rounding: Rundungs-Tricks in `decimal_utils` (Split-Rest, Fees) sodass Σ Outputs > Σ Inputs?
- 🔍 Split/Change-Anchor-Overlap: gleicher Seed/Ephemer-Key für Transfer- UND Change-Anchor bei crafteten Splits?
- 🔍 Panic-Hazards: systematischer `.unwrap()`/`.expect()`/Index-Scan in Bundle-/Container-Decodern mit Fuzz-artigen Inputs.
- 🔍 Aus `temp/uncovered_code.md` (KRITISCH): `bundle_processor::verify_container_signature` & `verify_bundle_signature` (Security-Bypass-Mutanten survive!), `transaction_handler::_execute_single_transfer` (Negation-Bypass), `process_encrypted_transaction_bundle` (Equality-Check).
- 🔍 Mid-Operation-Failure: Teilschreib-Desync zwischen Wallet-State, VoucherStore und Archiv (jenseits von SA04-03).

### Modul 05 — Storage & Key-Persistence
**Scope:** `src/storage/` (file_storage.rs, mod.rs), `src/archive/`, `services/mnemonic.rs`, `models/profile.rs`, `models/storage_integrity.rs`, `services/integrity_manager.rs`

Kern-Invarianten: At-Rest-Verschlüsselung von Keys/Mnemonics (ChaCha20-Poly1305/passwort-abgeleitet); atomare Writes (temp+rename); Integritäts-Checks vor Deserialisierung; Memory-Hygiene.

**Bestätigte Fehler (Tests vorhanden):**
- ✅ SA05-01: Archivierte Voucher-States müssen at-rest verschlüsselt sein (`sa05_01_...`).
- ✅ SA05-02: Manipulierte Archiv-Records müssen VOR Deserialisierung erkannt werden (`sa05_02_...`).
- ✅ SA05-03: Mnemonic-Validierungsfehler dürfen keine Phrase-Wörter verraten (`sa05_03_...`).

**Offene Prüfvektoren (🔍):**
- 🔍 Weak KDF/Salt/Nonce: statische Salze, schwache KDF-Parameter, vorhersagbare Nonces bei passwort-abgeleiteten Keys.
- 🔍 Crash-Konsistenz: Prozess-Exit mitten in Multi-File-Write → Wallet korrupt? Voucher vor Archiv-Commit entfernt (Reihenfolge remove-vs-archive)?
- 🔍 Plaintext-Leak-Pfade: Export/Backup/unauthentifiziertes Profil-Speichern schreibt Keys/Mnemonics klartextig.
- 🔍 Log/Error-Disclosure: `Display`/`Debug` anderer Typen formatiert Roh-Keys/Secrets (über Mnemonic hinaus).
- 🔍 Aus `temp/uncovered_code.md`: `models/secure_container.rs` Drop/Zeroize ungetestet (Memory-Hygiene-Invariantetest fehlt).

### Modul 06 — Privacy & Protocol Bundles
**Scope:** `services/jws_profile_service.rs`, `app_service/data_encryption.rs`, `app_signature_handler.rs`, `models/wallet_event.rs`, `protocols/{transfer,signing,trust}/1.0/*.md`, `docs/security/PRIVACY_MATRIX.md`

Kern-Invarianten: Private Mode OHNE sender did:key/Plaintext-Signaturen im Bundle; Metadata-Minimization; strikte Envelope-Validierung vor Payload-Processing.

**Bestätigte Fehler (Tests vorhanden):**
- ✅ SA06-01: Private-Bundle-Envelope leakt keine Permanent-Key-Signatur (`sa06_01_...`).
- ✅ SA06-02: Empfangener Bundle-Content matcht signierte bundle_id (`sa06_02_...`).
- ✅ SA06-03: Cleartext-Financial-Container werden beim Empfang abgelehnt (`sa06_03_...`).
- ✅ SA06-04: Malformed Signing Request lässt Signer nicht panicken (`sa06_04_...`).
- 🛡️ SA06-05: Counterparty-DID-Retention im lokalen Event-Log ist INTENTIONAL DESIGN (Offline-Forensik) — Invariantentest vorhanden; NICHT „reparieren“.
- ✅ SA06-06: JWS verwirft manipuliertes `typ` und non-kanonische DIDs (`sa06_06_...`).

**Offene Prüfvektoren (🔍):**
- 🔍 Algorithm-Confusion: JWS `none`/HS256-vs-EdDSA-Verwechslung, fehlende Header-Checks über alle Profile (Transfer/Signing/Trust) hinweg.
- 🔍 Trust-Assertion-Forgery: gefälschte Assertions passieren Verifikation?
- 🔍 Metadata-Minimization: unblinded Timestamps, Kontostände, IP-Hints in Envelopes/Bundles?
- 🔍 Event-Disclosure: `WalletEvent`/`EventBffData` leaket vertrauliche Metadaten an unberechtigte UI/Host-Listener (jenseits der geschützten Retention).
- 🔍 Wrapper-vs-Payload-Spoofing: authentischer innerer Voucher + manipulierter Envelope-Metadata wird akzeptiert?

### Modul 00 — Wildcard / Adversarial (läuft ZULETZT)
**Scope:** gesamtes Repo (Services, Wallet/AppService, Storage/Archive, Models/Protocols, Bindings/CLI)

Die 6 System-Albträume als Hypothesenkatalog:
1. 🔍 Wertschöpfung aus dem Nichts (Inflation, Duplizierung, Rounding)
2. 🔍 Unbefugtes Ausgeben / Diebstahl ohne Private Key
3. 🔍 Cross-Layer-Desync (AppService ↔ Wallet ↔ Store ↔ FileStorage ↔ L2Gateway; Zombie-States, Doppel-Aktiv-Voucher)
4. 🔍 Permanenter Wallet-/Netzwerk-DoS (Gossip-Poisoning, bricking, Memory/CPU-Exhaustion)
5. 🔍 DS-Detection-Evasion & Framing (über Modul 01 hinaus, Multi-Stage-Chains)
6. 🔍 Assumption-Busting: stille Annahmen systematisch verletzen (monotone Timestamps, JSON-Feldordnung, UUID-Kollisionen, ehrliche RNGs, keine konkurrierenden File-Modifier)

**Status:** Noch KEINE dedizierte Testdatei (`tests/security_audit_wildcard.rs` fehlt). A-00 erstellt sie neu; Erkenntnisse aus 01–06 zuerst gegenlesen, um Dopplungen zu vermeiden. Eigene Finding-IDs: `AUDIT-00-WILDCARD-[INDEX]`.

---

## 3. Zeitplan / Ablaufreihenfolge (Koordinator-Sicht)

1. **Wave 1 (parallel):** Alle Agenten A-01…A-06, A-00 erzeugen ihre Hypothesen-Dateien. Kein Cargo-Kontakt.
2. **Sichtung (Koordinator):** Deduplizierung gegen §2 (✅-Liste) und `docs/security/ai-audits/reports/`; Priorisierung; Freigabe der Queue.
3. **Wave 2 (sequenziell):** Queue 01 → 02 → 03 → 04 → 05 → 06 → 00. Je Agent: Hypothese für Hypothese abarbeiten (Test schreiben → eigener nextest-Filter → dokumentieren → nächste).
4. **Abschluss (Koordinator, einmalig):** Full-Suite-Run, Triage-Tabellen finalisieren, Reports ergänzen, ggf. Fixes committen (nur auf explizite Anweisung).

---

## 4. Eskalations- & Triage-Regeln

- Jede bestätigte Schwachstelle VOR einem Fix durch `DESIGN_INTENT_TRIAGE.md` (4-Fragen-Check) filtern:
  - `[CONFIRMED VULNERABILITY]` → Fail-First-Test + minimaler Fix + Full-Suite-Verify.
  - `[INTENTIONAL DESIGN REQUIREMENT]` → NICHTS an Logik ändern; Code-Doku (englisch) + Invariantentest.
  - `[FALSE POSITIVE]` → verwerfen, Begründung in Report.
- Bei Überschneidungen zweier Module (z. B. crypto_utils betrifft 02 UND 04): Koordinator entscheidet Eigentümer; der andere Agent notiert nur Querverweis in seiner Hypothesen-Datei.
- Blocker (flaky Tests, Cargo-Lock-Konflikte, Fixture-Änderungsbedarf): sofort melden und warten — KEINE eigenmächtigen Fremd-Datei-Änderungen.
