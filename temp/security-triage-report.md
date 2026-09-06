# Security-Fix Triage-Report — Letzte 10 Commits gegen DESIGN_INTENT_TRIAGE.md

> **Erstellt:** 2026-08-24 · **Methode:** Pro Security-Fix-Commit ein Subagent, der den vollen Diff gegen
> den 4-Fragen-Katalog aus `docs/security/ai-audits/DESIGN_INTENT_TRIAGE.md` triagiert hat.
> **HEAD:** `3bd4868` (live) · **Geprüfte Commits:** 7 von 10 (3 Docs/Audit-Suite-Commits übersprungen)

---

## 1. Executive Summary

| Commit | Subject (gekürzt) | Findings | Outcome-Verteilung | Re-Thinks |
| :--- | :--- | :--- | :--- | :--- |
| `bd404e7` | Double-spend trap, ds-tag & conflict-detection | 9 Elemente | 6×A, 1×B, 2×Prozess | **8** ⚠️ |
| `cba156e` | Non-contributory DH bypass & identity parser desync | 5 Elemente | 2×A, 3×C | **4** |
| `42d0c33` | CEL fail-open bracket indexing & decimal wraparound | 2 Findings | 2×A (01 grenzwertig zu C) | **6** |
| `66a8da8` | Decimal overflow panics & archive state desync | 3 Findings | 3×A | **3** |
| `7877bfc` | Plaintext voucher archive, integrity bypass & mnemonic disclosure | 9 Elemente | 4×A (+Residual-Lücken) | **8** |
| `48d9b82` | Bundle signature rebinding, envelope de-anonymization & cleartext bundles | 6 Elemente | 4×A, **1×B/C (SA06-05)**, 1×Randfall | **4** |
| `382bad8` | Retain direct counterparty in local events (Revert) | 7 Elemente | 1×C (Ursprungs-Finding), 4×B | **3** |

**Kernaussage:** Die überwiegende Mehrheit der Fixes war berechtigt (Outcome A). Es gab jedoch
**einen bestätigten False Positive mit folgeschwerem Fix** (HMSEC-SA06-05, Counterparty-DID-Stripping,
bereits via `382bad8` revertiert) sowie **mehrere Fixes, die entweder unvollständig sind oder neue
funktionale Probleme eingeführt haben** — insbesondere ein harter Protokollbruch für zirkulierende
Voucher (`bd404e7`) und ein Downgrade-Bypass im verschlüsselten Archiv (`7877bfc`).

---

## 2. Priorisierte Liste: Elemente, die nochmal durchdacht werden müssen

### 🔴 Kritisch (sofort prüfen)

| # | Element | Commit | Problem |
| :-- | :--- | :--- | :--- |
| K1 | **Protokollbruch U-Ableitung (F2):** `compute_u_input()` mit `t_time` macht alle ≤0.2.22 Public-Mode-Voucher an ≥0.3.0-Wallets **unvalidierbar/unspendbar** ("Trap Scalar U does not match"). Offline-Cash ist nicht zentral migrierbar; es gibt keinen Legacy-Verifikationszweig oder Epochen-Flag. | `bd404e7` | Ist das System pre-launch? Falls nein: Migrations-/Epochenstrategie zwingend. |
| K2 | **Downgrade-Bypass im Archiv:** `read_record` (`src/archive/file_archive.rs:189–192`) akzeptiert jedes JSON ohne Envelope-Marker als "Legacy" und deserialisiert es **ohne Integritätsprüfung**. Ein Angreifer ersetzt den verschlüsselten Envelope durch manipulierten Klartext-Voucher-JSON und umgeht AEAD vollständig. Der Fail-First-Test testet nur Bitflips, nicht Whole-File-Substitution. | `7877bfc` | Legacy-Support hinter Opt-in-Flag/Migration oder Manifest-Bindung; Test um File-Substitution erweitern. |
| K3 | **S-Skalar-Malleabilität offen (F3):** Kanonische Prüfung des Schnorr-Response-Skalars `s` in `verify_trap` fehlt am committeten HEAD — liegt nur als **uncommittete Arbeitskopie-Änderung** (AUDIT-01-Nachfolgearbeit). Gleiches gilt für den strukturellen Placeholder-Skip (F1) und Import-Gate 3b. | `bd404e7` | WIP committen + Regressionstests, sonst bleibt (R, s+l)-Malleabilität und Placeholder-Umgehung offen. |
| K4 | **Archiv-Fehler nach Commit (04-03):** Schlägt `archive_voucher` NACH dem Wallet-Commit fehl, rollt der AppService (`with_transactional_mut`) den bereits persistierten State zurück, während die Archiveinträge geschrieben sind → **Geister-Einträge erneut**, nur über den selteneren Pfad. Zusätzlich Teil-Archivierung bei Mid-Loop-Fehler (`?` in Loop, `transaction_handler.rs:984–998`). | `66a8da8` | Archivfehler entkoppeln (Warnung + Retry/Journal) statt `Err` nach Commit. |

### 🟡 Wichtig (kurzfristig klären)

| # | Element | Commit | Problem |
| :-- | :--- | :--- | :--- |
| W1 | **Identity-Parser-Desync nur punktuell gefixt:** Die Firewall (`validate_user_id` vor Extraktion) wirkt nur in `verify_signatures`. Der tolerante Parser `get_pubkey_from_user_id` (rfind('@')) bleibt an ~9 weiteren netzwerkexponierten Stellen ohne Grammatik-Check: `chain.rs:346,741`, `bundle_processor.rs:176,189`, `transaction_handler.rs:274`, `conflict_manager.rs:247`, `standard_manager.rs:60`, `seal_manager.rs:141`, `integrity_manager.rs:52`, `secure_container_manager.rs:102`, `conflict_handler.rs:308`. | `cba156e` | Zentrale strenge Auflösung (`validate_user_id` + Extract) an allen signaturrelevanten Stellen. |
| W2 | **CEL Pre-Check ist Shim, keine semantische Korrektur:** (a) Comprehension über Non-Array-Range gibt `Ok(Null)` zurück, ohne Body-Unterknoten zu prüfen → fail-open-Pfade können durchsickern; (b) Fallback-Arm `_ => Ok(Null)` skippt Kind-Prüfung komplett; (c) Interpreter selbst ungepatcht; (d) `loop_env = env.clone()` pro Iteration → O(Items×State) CPU/Speicher auf angreiferbeeinflussten Daten (DoS-Fläche); (e) Dual-Evaluator-Divergenz (fail-closed, aber kann legitime Programme ablehnen). | `42d0c33` | Langfristig Variante (a) aus dem Docblock (Interpreter-Fork/Vendor) oder Import-Zeit-Ablehnung von `_[_]`. |
| W3 | **Attributionslücke Prefix=None (F1):** `verify_stored_proofs_against_identity(..., None)` hardcoded — User mit Account-Präfix (SAI-Konzept!) erhalten **nie** did:key-Attribution trotz voller Beweislage. Am HEAD skippt die Funktion zudem Placeholders noch via angreifbarem `t_type.contains("placeholder")`. Altdaten im ProofStore werden nicht re-evaluiert. | `bd404e7` | Präfix-Erweiterung; Placeholder-Skip strukturell (fehlendes trap_data) statt String-Filter; Re-Check beim Load erwägen. |
| W4 | **Import-Gates vs. Beweis-Teilbarkeit (F4):** Struktur-Gate verwirft partielle/gossip-artige Beweise per `Err` statt Witness-Notes zu persistieren → gemischte Proofs (1 echtes + 1 manipuliertes Tx) unterdrücken auch authentische Beweise; anonymes Reporten ist nun unmöglich. Abwägung DoS-Schutz vs. forensischer Informationsfluss erneut prüfen. | `bd404e7` | Bewusste Entscheidung dokumentieren (ADR). |
| W5 | **Fail-closed-Archivscan:** Ein einziger korrupter Record (auch Bit-Rot auf realen Offline-Geräten) legt `find_transaction_by_id`/`get_archived_voucher` komplett lahm → Verfügbarkeit der Forensik vs. Tamper-Detection braucht dokumentierte Architektur-Entscheidung. Zudem schützt AEAD nicht vor Löschen/Trunkieren/Replay ganzer Records (ursprünglich empfohlenes signiertes Manifest analog `LocalIntegrityRecord` wurde nicht umgesetzt). | `7877bfc` | ADR; mittelfristig Archiv-Manifest gebunden an WalletSeal-Epoch andenken. |
| W6 | **App-Layer-Restfrage zu SA06-05 (der revertierte False Positive):** Der Core hält Counterparty-DIDs korrekt lokal-verschlüsselt, aber `WalletEvent.bff_data.counterparty_id` wird im Klartext an Host/UI emittiert (`app_queries.rs:167`). Ohne DTO-Grenze/Guard könnten Frontends DIDs in unverschlüsselten Persistenzschichten (LocalStorage, Cloud-Sync) ablegen — das ursprüngliche Szenario käme über die Anwendungsschicht zurück. Auch: Quarantäne-/Konflikt-Events hardcoden weiterhin `counterparty_id: None` (`transaction_handler.rs:563,594,660`) — forensisch inkonsistent zur neuen Design-Entscheidung. | `382bad8` / `48d9b82` | FAQ-Ergänzung + ggf. Guard/Test für Event-Klartext-Weitergabe; Quarantäne-Events in Folgetriage prüfen. |

### 🟢 Nachholen / dokumentieren

| # | Element | Commit | Problem |
| :-- | :--- | :--- | :--- |
| N1 | **Stealth-Residual-Lücke als B-Element nicht verankert (F1c):** Stealth-Chains mit manipuliertem `blinded_id` passieren Chain-Level-Validierung weiter — strukturell unavoidable, konsistent mit "Fraud Detection, not Prevention", aber weder im design-decisions-Skill noch in PRIVACY_FAQ/ADR festgehalten. | `bd404e7` | ADR/FAQ-Eintrag nachholen (Muster wie bei `382bad8`). |
| N2 | **Severity-Framing HMC-SEC-02-01:** Realer Vor-Fix-Impact des DH-Bypasses war durch Bundle-Sig-Bindung, optionale DLEQ und stateless Seed eher Griefing/Invariantenbruch als HIGH — abfedernde Kontrollen in STATUS.md/ADR nennen, damit der Decrypt-Pfad-Check nicht als redundant entfernt wird. | `cba156e` | Dokumentation schärfen. |
| N3 | **Decimal-Finding 02 grenzwertig zu C:** `max_places` stammt aus der signierten Immutable Zone (issuer-kontrolliert, nicht runtime-angreifbar). Konsequenter wäre Import-Zeit-Ablehnung unplausibler Werte bei `load_and_verify_standard` statt Runtime-Stummschaltung (`false`). Cap `0..=18` vs. rust_decimal-Maximum 28 dokumentieren. | `42d0c33` | Boundary-Diskussion führen; ggf. Reklassifikation B/C. |
| N4 | **Overflow-Fehlertyp generisch (04-01):** `VoucherCoreError::Generic("Amount overflow …")` nicht maschinell unterscheidbar; dedizierter Variant (z. B. `AmountOverflow`) verbessern Client-Handling. Bei direkter Core-Nutzung: partielle Voucher-Ingestion vor Summary-Overflow (nur AppService rollt zurück). Verhalten "Near-MAX-Bundles werden komplett abgewiesen" dokumentieren. | `66a8da8` | Dedizierter Fehlertyp + Doku. |
| N5 | **Traversal-Härtung asymmetrisch:** `save_arbitrary_data` sanitisiert, aber `load_arbitrary_data` (file_storage.rs:827–849) und `get_item_hash` (Zeile 1019–1026) joinen `name` unsanitisiert → Read-/Hash-Orakel-Traversal bleibt. | `7877bfc` | Sanitizing symmetrisch auf Read-Pfade ausweiten. |
| N6 | **Roh-IDs als Dateinamen:** `voucher_id`/`t_id` bleiben trotz Verschlüsselung als Datei-/Verzeichnisnamen sichtbar (Metadaten-Lek). Empfohlene Hash-Namen wurden nicht umgesetzt. | `7877bfc` | Hash-Namen nachziehen oder bewusst als akzeptiert dokumentieren. |
| N7 | **Host-Abhängigkeit ohne Erzwingung:** `FileVoucherArchive::new_secure(path, "")` kompiliert mit leerem Passwort; im Crate existiert keine Produktionsinstanziierung — Sicherheit hängt allein am Host-Setup. Zudem PBKDF2 (100k) **pro Record** pro Lese-/Schreibvorgang → O(N·KDF)-Forensik-Scans; Produktions-Wiring sollte session-abgeleiteten Key via `with_key` nutzen. | `7877bfc` | Empty-Password-Guard/Debug-Assert + Integrationsdoku für Tauri-Wrapper. |
| N8 | **Randfall `is_anonymous_bundle`:** Bundles ohne Voucher (`vouchers.is_empty()` → `false`) behalten die Permanent-Key-Envelope-Signatur auch bei privater Intentionslage; gemischte Bundles ebenfalls. | `48d9b82` | Prüfen, ob metadaten-only Bundles in privaten Kontexten vorkommen; Guard erweitern oder dokumentieren. |
| N9 | **Stranding-Risiko Strictness (Finding 02):** Extern/fremdimplementierte Vouchers mit nicht-kanonalen Signer-IDs scheitern nun unwiderruflich fail-closed — Risiko niedrig (Format seit `5ebd720` unverändert), aber Offline-Cash ist unversöhnlich gegenüber Stranding. Diagnose-/Validierungsreport statt silent reject erwägen. | `cba156e` | Migrations-/Diagnosepfad prüfen. |
| N10 | **Audit-Doku-Konsistenz:** Revert-Historie (`48d9b82` → `382bad8`) in `docs/security/ai-audits/06_privacy_and_protocol_bundles.md` nachtragen, damit Folgelaudits dieselbe CWE-359-Falschmeldung nicht erneut melden. "Totpfad-Fix" in `get_archived_voucher` war Funktionsbug, kein CWE-354/345-Teil — STATUS.md-Etikettierung schärfen. | `48d9b82` / `7877bfc` | Docs aktualisieren. |
| N11 | **JWS typ-Pinning Zukunftshinweis:** Schützt erst real, wenn weitere Artifact-Klassen denselben Verifier nutzen — dann differenzierend implementieren. | `48d9b82` | Bei Erweiterung beachten. |

---

## 3. Bestätigte saubere Fixes (Outcome A, kein Handlungsbedarf)

Diese Remediationen bestanden die volle Triage ohne Vorbehalte:

- **`48d9b82` (a)** Bundle-Signature-Rebinding: Rekalkulation von `container.i`/`bundle_id` vor Signaturcheck — Hash-Parität zur Creation geprüft.
- **`48d9b82` (b1)** Envelope-Signatur als De-Anonymisierungs-Oracle: Weglassen der Permanent-Key-Signatur bei Stealth-Ketten (genuine netzwerkseitige Schwachstelle).
- **`48d9b82` (c)** Cleartext-Bundle-Ablehnung empfangsseitig (Symmetrievervollständigung zur Sender-Fuse).
- **`48d9b82`** Index-Panics `transactions[0]` → graceful Error (DoS gegen Guarantoren).
- **`cba156e` (01)** `was_contributory()` im Dekryptierungspfad — kryptographisch korrekt gem. RFC 7748 §6.2, alle Low-Order-Punkte erfasst, kein Kompatibilitätsrisiko.
- **`42d0c33` (01)** CEL Bracket-Indexing fail-closed: keine ausgelieferte Standard-TOML nutzt Bracket-Syntax → keine Regression für bestehende Standards.
- **`66a8da8` (02)** Chain-Validator `checked_add`: Overflow ⇒ Summe kann nie einem Saldo entsprechen → keine False Rejections legitimer Ketten.
- **`bd404e7`** Fail-closed `sender_id` in `verify_transactions`, Import-Gates (Grundrichtung), `compute_u_input` gegen Identical-U, kanonische U-Skalare, L2 fail-closed Lock-Requests, VIP-Depth-Anti-Poisoning.
- **`7877bfc` (03)** Mnemonic-Wort-Disclosure: Position-only-Fehlermeldung, vollständig (Crate-Pfad bereits index-basiert).
- **`382bad8`** Der Revert selbst: Invariantentest grün, Doku (design-decisions, PRIVACY_FAQ, STATUS.md CORE-004) vollständig — modellhafte Umsetzung eines Outcome-B-Action-Plans.

---

## 4. Detailberichte pro Commit

---

### 4.1 Commit `bd404e7b448cfe102468a3c5340f2bc4ff793cc4`
**fix(security)!: remediate double-spend trap, ds-tag & conflict-detection vulnerabilities (bump to 0.3.0)**

#### Änderungen nach Finding-Bereich

**F1 — Stealth-Trap-Evasion & Third-Party-Framing (CRITICAL)**
- `src/services/voucher_validation/chain.rs::verify_transactions`: Fail-closed – vorhandene, aber malformed `sender_id` führt zu hartem Fehler statt stillem Überspringen von `verify_trap`.
- `src/services/trap_manager.rs`: neue `verify_stored_proofs_against_identity()` – did:key-Zuschreibung nur bei ≥2 kryptographisch verifizierten Schnorr-Trap-Proofs.
- `src/wallet/conflict_handler.rs::verify_and_create_proof`: kanonischer Offender-Identifier fällt auf unverfälschbare Ephemeral-Verknüpfung zurück (`ephemeral:<pub>`); mathematische Extraktion nur noch als beratendes `suspected_identity`-Metadatum.
- `src/models/conflict.rs`: neues Feld `ProofOfDoubleSpend.suspected_identity` (`#[serde(default)]` → wire-kompatibel).

**F2 — Identical-U besiegt Identitäts-Extraktion (HIGH)**
- Neue gemeinsame Funktion `compute_u_input()` (length-prefixed über ds_tag, amount, receiver_anchor **und t_time**), gespiegelt in `create_transaction`, `verify_transactions`, `verify_stored_proofs_against_identity` sowie Test-Helper.

**F3 — Non-canonical Scalar Bypass (MEDIUM)**
- `trap_manager.rs::parse_canonical_scalar()` für U; Identical-U-Guard vergleicht reduzierte Skalare; expliziter `delta_u == Scalar::ZERO`-Error vor der Inversion.
- ⚠️ Kanonische Prüfung des Response-Skalars **s** fehlt am HEAD (nur uncommittete WIP).

**F4 — Unauthentifizierter Proof-Import (HIGH)**
- `src/services/conflict_manager.rs`: Gates `derive_proof_id()`, `verify_reporter_signature()`, `verify_proof_structure()`.
- `import_proof`: 4-Gate-Pipeline; ohne lokalen Kontext Witness-Note ohne Quarantine.

**Minor:** `l2_gateway.rs::generate_lock_request` fail-closed; Gossip-VIP-Depth-Schutz; bs58/base64-Dokfix.

#### Triage-Matrix

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| F1a: chain.rs fail-closed bei malformed sender_id | CWE-347/754 | **A** | Echter Signaturverifikations-Bypass; blockiert keine legitimen Offline-Txs. | nein |
| F1b: Anti-Framing-Attribution | CWE-345 | **A** (Lücken) | Framing real; aber Prefix=None hardcoded, Placeholder-Skip angreifbar, Alt-Proofs nicht re-evaluiert. | **ja** |
| F1c: Stealth-Residual-Lücke (blinded_id) | CWE-347 | **B** | Strukturell unavoidable ohne Privacy-Bruch; konsistent mit Systemphilosophie. Nur Doku fehlt (ADR/FAQ). | ja (Doku) |
| F2: compute_u_input inkl. t_time | CWE-347 | **A**, aber Backward-Compat-Problematik | Angriff real (delta_u==0); **aber** harter Protokollfork für ≤0.2.22 Public-Mode-Voucher, kein Legacy-Pfad. | **ja (kritisch)** |
| F3: Kanonische Skalar-Parsings | CWE-347 | **A**, unvollständig am HEAD | Korrekt für ehrliche Wallets; S-Skalar-Prüfung fehlt committet. | **ja** |
| F4: import_proof-Gates | CWE-20/345 | **A**, mit Vorbehalten | Remote-Quarantine real; aber Beweis-Teilbarkeit reduziert, anonyme Reporter unmöglich. | **ja** |
| Minor: l2_gateway fail-closed | CWE-20/754 | **A** | L2 ohnehin Online-Grenze → kein Offline-Verlust. | nein |
| Minor: VIP-Depth-Schutz | CWE-697 | **A** | Stärkt Forensik-Propagierung. | nein |
| Minor: bs58-Dokfix | – | **C** | Reine Dokkorrektur. | nein |
| Version bump 0.3.0 | – | Prozess | SemVer korrekt, aber Validierungs-Inkompatibilität zirkulierender Voucher nicht adressiert. | **ja** |

#### Prüfstatus an HEAD
Kein späterer Commit altert das Verhalten. Uncommittete Arbeitskopie enthält genau die benannten Lücken (Gate 3b, struktureller Placeholder-Skip, S-Skalar-Canonicalisierung, `tests/security_audit_module_01_traps.rs`) — Nachfolge-Audit-Iteration sieht die Lücken, ist aber **noch nicht committed**.

---

### 4.2 Commit `cba156e6afcded97618c9a95e845f7db5a5c9329`
**fix(security): remediate non-contributory DH bypass & identity parser desync**

#### Änderungen

**HMC-SEC-02-01 (HIGH, CWE-325):** `src/services/crypto_dh.rs::decrypt_recipient_payload` (~Z.214–223): `shared_point.was_contributory()` nach X25519 — spiegelbildlich zum bereits gehärteten Encrypt-Pfad. Test schmiedet privacy_guard unter All-Null-Ephemeral-Key inkl. HKDF-Info-Replik.

**HMC-SEC-02-02 (MEDIUM, CWE-20/172):** `src/services/voucher_validation/signatures.rs::verify_signatures` (Z.44–55): `validate_user_id(&signer_id)` vor Key-Extraktion ("Canonical Identity Firewall") — schließt Desync zwischen strikter Grammatik (`crypto_identity.rs:119–168`) und tolerantem `rfind('@')`-Parser (`crypto_identity.rs:209`).

**Sonstige:** Ed25519 s+L-Malleability-Guard (INFO), Testumbau `signature_reuse.rs` (kanonische Aliase, Intent bewahrt), Dev-Dependencies ergänzt.

#### Triage-Matrix

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| HMC-SEC-02-01: Fehlende was_contributory()-Prüfung (Decrypt) | CWE-325 | **A** | Fix korrekt gem. RFC 7748 §6.2, symmetrisch, getestet. Reale Vor-Fix-Impact eher Griefing als HIGH (Bundle-Sig-Bindung, optionales DLEQ, stateless Seed). | Nein (Severity-Doku ja) |
| HMC-SEC-02-02: Parser-Desync | CWE-20/172 | **A** (unvollständig) | Desync real; Fix nur im Voucher-Signatur-Pfad, ~9 weitere exponierte Stellen ohne Firewall. | **ja** |
| HMC-SEC-02-03: Ed25519-Malleability-Guard | CWE-347 | **C** | ed25519-dalek 2.x wirft nicht-kanonische Skalare strukturell weg; Test dient als Invariant-Guard. Korrekt als INFO klassifiziert. | nein |
| Testumbau signature_reuse.rs | – | **C** | Notwendig, damit Tests nicht am neuen Grammatik-Check vorbeilaufen (grün aus falschem Grund). | nein |
| Dev-Dependencies | – | **C** | Kein Release-Impact; test-utils-Feature unberührt. | nein |

#### Elemente, die nochmal durchdacht werden müssen
1. **Firewall nur in verify_signatures:** Zentrale strenge Auflösung (`resolve_canonical_pubkey` = validate + extract) an allen signaturrelevanten Stellen: `chain.rs:346,741` (Public-Mode sender_id, Transaktionskette!), `bundle_processor.rs:176,189`, `transaction_handler.rs:274`, `conflict_manager.rs:247` (proof.reporter_id), `standard_manager.rs:60` (issuer_id), `seal_manager.rs:141`, `integrity_manager.rs:52`, `secure_container_manager.rs:102`, `conflict_handler.rs:308`. Sonst wandert derselbe Befund im nächsten Audit wieder ein.
2. **Stranding-Risiko:** Fremdimplementierte Vouchers mit nicht-kanonalen Signer-IDs scheitern unwiderruflich fail-closed. Format seit `5ebd720` unverändert (Risiko niedrig), aber Diagnose-/Validierungsreport statt silent reject erwägen.
3. **Severity-Dokumentation 02-01:** Abfedernde Kontrollen (`MismatchedPrivacySenderId` transaction_handler.rs:266 etc.) explizit in STATUS.md/ADR nennen.

---

### 4.3 Commit `42d0c33e8ca135f7361fa5c1c8ed10ff782770b4`
**fix(security): remediate CEL fail-open bracket indexing & decimal check wraparound**

#### Änderungen

**HMC-SEC-03-01 (HIGH, CWE-636/754):** `src/services/dynamic_policy_engine.rs::evaluate_rule`: paralleler AST-Pre-Check via neuem Dependency-Zweig `cel-parser = "0.10"` (~370 Zeilen Mini-Evaluator). Bracket-Indexing über fehlende Keys/OOB-Indices → Err. Hintergrund: `cel-interpreter 0.10.0` koalesziert fehlende Keys zu `Null`; `Null != <string>` = true → negierte Prädikate über weggelassenen Pflichtfeldern = Bypass. Dot-Access war bereits korrekt. Library NICHT geforkt — Engine-seitiger Pre-Check-Shim.

**HMC-SEC-03-02 (LOW, CWE-195):** `check_decimals`: vorher `(-1 i64) as u32` → Wraparound auf 4_294_967_295 deaktivierte die Restriktion stillschweigend; jetzt `!(0..=18).contains(&max_places)` → false.

Plus: neue Suite `tests/security_audit_module_03_cel.rs` (9 Tests grün an HEAD), STATUS.md-Einträge.

#### Triage-Matrix

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| HMC-SEC-03-01: Bracket-Indexing Null-Coalescing | CWE-636/754 | **A** | Verletzt dokumentierte Invariante #2 "Fail-Closed". Ausdruck issuer-signiert, aber Daten peer-kontrolliert → Weglassen restricted Felder ist reale Angreiferaktion. | Ja (Vollständigkeit, s.u.) |
| HMC-SEC-03-02: Signed-to-Unsigned-Wraparound | CWE-195 | **A (LOW)**, grenzwertig zu C | Codefehler real und korrekt behoben; aber max_places aus signierter Immutable Zone → zur Runtime NICHT angreiferkontrollierbar. Defense-in-Depth gegen stille Policy-Inversion. | Ja (Boundary-Diskussion) |

Keine B- oder reinen C-Elemente.

#### Elemente, die nochmal durchdacht werden müssen
1. **Rest-Gaps des Pre-Check-Shims:**
   - `Expr::Comprehension`: Non-Array-Range → nur `Ok(Null)` zurückgegeben, **ohne** accu_init/loop_cond/loop_step/result zu prüfen → fail-open-Pfade können durchsickern.
   - Fallback-Arm `_ => Ok(JsonValue::Null)` (dynamic_policy_engine.rs:430): unbehandelte AST-Knoten skippen Kinderprüfung komplett.
   - Interpreter bleibt ungepatcht: verpasste Pfad-Referenzen fallen zurück aufs alte Null-Coalescing. Langfristig Interpreter-Fork/Vendor oder Import-Time-Ablehnung von `_[_]` evaluieren.
   - Performance/DoS: `loop_env = env.clone()` pro Comprehension-Iteration klont den kompletten Voucher-State → O(Items × Stategröße) auf angreiferbeeinflussten Daten während Validierung.
   - Dual-Evaluator-Divergenz (size() Bytes vs. Chars etc.): derzeit nur fail-closed, kann legitime Programme ablehnen.
2. **Finding 02 Boundary:** Klassifizierung C ("Input nicht angreiferkontrollierbar") wäre vertretbar gewesen. Konsequenter: negatives/unplausibles max_places schon bei `load_and_verify_standard` (Import-Zeit) ablehnen statt Runtime-still `false` (macht jede Regel mit solchem Limit zur harten Ablehnung — gewollt?). Cap 18 vs. rust_decimal-Maximum 28 dokumentieren.
3. **ENTWARNUNG (zur Doku):** Offline-Resilienz unberührt; alle ausgelieferten Standards nutzen ausschließlich Dot-Access mit has()-Guards → keine Regression.

---

### 4.4 Commit `66a8da89909adc4d3de98c7e6917287c3b49fada`
**fix(security): remediate decimal overflow panics & forensic archive state desync**

#### Änderungen

| Finding | Ort | Änderung |
| :--- | :--- | :--- |
| HMC-SEC-04-01 (CRITICAL, CWE-190/248) | `transaction_handler.rs::process_encrypted_transaction_bundle` (Summary-Akkumulation ~Z.410–419) | `val1 + val2` → `checked_add` → `VoucherCoreError::Generic` |
| HMC-SEC-04-02 (HIGH, CWE-190/248) | `voucher_validation/chain.rs::verify_transactions` (Erhaltungssumme ~Z.198, Split-Gleichheit ~Z.455) | `checked_add` → typisierte Fehler |
| HMC-SEC-04-03 (HIGH, CWE-667) | `_execute_single_transfer` / `execute_multi_transfer_and_bundle` (Post-Commit-Pass Z.978–999) | Archivierung aus Simulationsfunktion herausgelöst, strikt NACH Commit |

#### Triage-Matrix

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| 04-01: unchecked + in TransferSummary | CWE-190→248 | **A** | Remote deterministischer Panic-DoS auf valide Eingabe; Fix korrekt. | **Ja**: Generic-Fehlertyp; partielle Ingestion bei direkter Core-Nutzung; Near-MAX-Bundles komplett abgewiesen (Doku fehlt) |
| 04-02: unchecked + in verify_transactions | CWE-190→248 | **A** | Overflow ⇒ Summe nie repräsentierbar → Zurückweisung mathematisch zwingend, keine False Rejections. | Nein (nur Kosmetik: Overflow als InsufficientFundsInChain-String semantisch überladen) |
| 04-03: Archivierung in simulierter Transaktion | CWE-667 | **A** | Geister-Einträge vergiften Double-Spend-Beweiskette; Fix-Richtung richtig. | **Ja**: Archiv-Fehler nach Commit → AppService-Rollback erzeugt Geister-Einträge erneut; Teil-Archivierung bei Mid-Loop-Fehler |

Keine B-/C-Elemente — alle drei zurecht echte Schwachstellen.

#### Elemente, die nochmal durchdacht werden müssen
1. **04-03 Interaktion mit `with_transactional_mut`** (`command_handler.rs`): `ArchiveError` nach `*self = temp_wallet` rollt den committeten Zustand zurück, während Archiveinträge persistiert sind → erneute Archive/State-Divergenz (die Fehlerklasse, die beseitigt werden sollte). Lösungsideen: Journal-and-Replay, oder Archivfehler als nicht-fatale Warnung/Retry-Queue.
2. **04-01 Vollständigkeit:** dedizierter `AmountOverflow`-Variant; strukturelle Lösung Issuance-Magnitude-Cap in der Standard-Validierung; Verhalten "Bundles > Decimal::MAX werden als Ganzes abgewiesen" dokumentieren (FAQ/ADR-würdig).
3. Stand an HEAD: beide Remediationen intakt; `7877bfc` verschlüsselte das Archiv ohne Änderung der Post-Commit-Archivierung. Tests 3/3 grün.

---

### 4.5 Commit `7877bfc941aea28c7cc7dacdec7ee00e858d2051`
**fix(security): remediate plaintext voucher archive, archive integrity bypass & mnemonic word disclosure**

#### Änderungen

**(a) HMSEC-SA05-01 (CWE-312):** `src/archive/file_archive.rs`: neuer verschlüsselter Konstruktor `new_secure(path, password)` (PBKDF2-HMAC-SHA512, 100k, frischer Salt pro Record) und `with_key(path, [u8;32])`; Plaintext-Konstruktor entfernt. `seal_record()`/`read_record()` mit JSON-Envelope `{"format":"hmc-archive-v1",…}` + ChaCha20-Poly1305.

**(b) HMSEC-SA05-02 (CWE-354/345):** `ArchiveError::IntegrityViolation`; Fehler werden propagiert statt still geschluckt; AEAD-Tag vor Deserialisierung. Bonus: Reparatur eines latenten Totpfads in `get_archived_voucher`.

**(c) HMSEC-SA05-03 (CWE-209):** `mnemonic.rs::validate_german` (Z.423–436): nur Positions-Metadaten, nie das Wort selbst.

**Bonus-Hardening:** `save_arbitrary_data`: Path-Traversal-Guard + atomares Schreiben (file_storage.rs:799–821).

#### Triage je Finding (Kurzfassung)
- **(a) = A:** Verletzte eigene Invariante "At-Rest Confidentiality"; Archiv lag außerhalb WalletSeal-Domäne; Code-TODO belegte bekannten Defekt (kein Design-Intent). Encryption korrekt umgesetzt.
- **(b) = A, aber Fix unvollständig** — kritischer Downgrade-Bypass: Legacy-Plaintext-Fallback in `read_record` (s. unten).
- **(c) = A (LOW):** sauber remediert, vollständig (Crate-Pfad bereits index-basiert).

Kein Element als B oder C — anders als beim Counterparty-Fall lagen alle Findings außerhalb versiegelter Storage bzw. betrafen Fehlerhygiene.

#### Triage-Matrix (inkl. Residual-Elemente)

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| SA05-01: Klartext-Archiv außerhalb sealed Storage | CWE-312 | **A** | Eigene Invariante verletzt; admitted TODO. | Nein |
| SA05-01-Rest: Roh-Dateinamen voucher_id/t_id | CWE-312 (Meta) | A-Teil | Metadaten-Lek bleibt; empfohlene Hash-Namen nicht umgesetzt. | **Ja** |
| SA05-01-Rest: Keine Erzwingung sicherer Konstruktion | – | A-Doubt | `new_secure(path, "")` kompiliert; kein Production-Wiring im Crate. | **Ja** |
| SA05-02: Silent-Skip + Integritätsprüfung | CWE-354/345 | **A** | Tampered Data floss in Double-Spend-Pipeline; AEAD-vor-Deserialisierung richtig. | Ja (Folgezeilen) |
| **Legacy-Plaintext-Fallback in read_record** | CWE-354/345 (wieder eingeführt) | **A-Lücke** | `looks_like_envelope` attacker-kontrollierbar; Substitution umgeht AEAD vollständig; kein Test deckt File-Substitution ab. | **Ja (kritisch)** |
| Fail-closed-Scan (Bit-Rot → Totalausfall) | – | Trade-off | Offline-Geräte altern real; Verfügbarkeit vs. Tamper-Detection. | **Ja** (ADR) |
| AEAD deckt nicht Löschen/Trunkieren/Replay; kein Manifest | CWE-345 (residual) | A-Residual | Ursprüngliche Remediation-Empfehlung (signiertes Manifest analog LocalIntegrityRecord) NICHT umgesetzt. | **Ja** |
| Totpfad-Fix get_archived_voucher | – | C-Komponente | Latenter Funktionsbug, kein exploitabler Defect; Etikettierung überzeichnet. | Nein |
| SA05-03: Mnemonic-Echo | CWE-209 | **A (LOW)** | Hygiene-Leck; Fix vollständig, begründet, getestet. | Nein |
| Bonus: Traversal asymmetrisch | CWE-22 | A-Teil | `load_arbitrary_data` (Z.837) und `get_item_hash` (Z.1020) sanitizen nicht. | **Ja** |

---

### 4.6 Commit `48d9b8270fa26ada2eecb23082fb1c6fe29aae59`
**fix(security): remediate bundle signature rebinding bypass, private-mode envelope de-anonymization & cleartext bundle acceptance**

#### Änderungen

**(a) HMSEC-SA06-02 (CRITICAL, CWE-347):** `bundle_processor.rs::open_and_verify_bundle`: Rekalkulation von `container.i` und `bundle_id` aus empfangenen Bytes vor jeder Signaturprüfung. ✅ aktiv an HEAD.

**(b1) HMSEC-SA06-01 (HIGH, CWE-359/202):** Bei anonymen Ketten bleibt `SecureContainer.signature` leer (keine dauerhafte Ed25519-Signatur über öffentliches `i` → De-Anonymisierungs-Oracle eliminiert); Authentizität allein via innerer Bundle-Signature. ✅ aktiv.

**(b2) HMSEC-SA06-05 (MEDIUM, CWE-359/778):** Lokales Event-Metadata-Stripping an 4 Stellen in `transaction_handler.rs` — **VOLLSTÄNDIG REVERTIERT durch `382bad8`** (Invariantentest invertiert, design-decisions + PRIVACY_FAQ Q3/Q4 dokumentiert, STATUS.md → "ARCHITECTURAL DECISION CORE-004"). Am HEAD nichts mehr vom Remediation-Code vorhanden.

**(c) HMSEC-SA06-03 (HIGH, CWE-311):** Empfangsseitige Ablehnung `EncryptionType::None` + TransactionBundle. ✅ aktiv.

**Nebenfundе:** SA06-04 Index-Panics → graceful Error; SA06-06 JWS `typ`-Pinning + kanonisches did:key-Parsing. Beide aktiv.

#### Triage-Matrix

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| (a) SA06-02 Rebinding | CWE-347 | **A** | Netzwerk-exponiert (Signature-Transplantation); kein Offline-Bruch; Hash-Parität geprüft. | Nein |
| (b1) SA06-01 Envelope-Oracle | CWE-359/202 | **A** | O(1)-Attribution via öffentlich verifizierbarer Permanent-Key-Signatur; innere Signatur bleibt autoritativ. | Ja (Randfall: vouchers.is_empty()) |
| **(b2) SA06-05 Event-Stripping** | CWE-359/778 | **B/C — Original-Finding FALSE POSITIVE** | Generische CWE-359-Logik auf lokal verschlüsselten, nie transmisgierten Zustand angewandt; Entfernen zerstört Hop-by-Hop-Forensik irreversibel. Revert korrekt. | Ja (App-Layer-Restfrage, s. 382bad8) |
| (c) SA06-03 Cleartext-Akzeptanz | CWE-311 | **A** | Symmetrievervollständigung; Library konnte solche Container nie legitim erzeugen. | Nein |
| SA06-04 Index-Panics | CWE-617/125 | **A** | Remotely erreichbarer Panic → DoS gegen Guarantoren. | Nein |
| SA06-06 JWS | CWE-347/20 | **A (teils präventiv)** | Trailing-Garbage-Aliase brechen Autorisierungslogik; typ-Pinning derzeit nicht ausnutzbar, aber korrekte Härtung. | Nein (Zukunftshinweis) |

Tests an HEAD: `tests/security_audit_module_06_privacy.rs` 6/6 grün.

---

### 4.7 Commit `382bad81ad4bf90c38cd923a9c19987b0e931fdb`
**fix(privacy): retain direct counterparty in local events for offline forensics**

#### Zusammenfassung
Rollback der über-aggressiven SA06-05-"Reparatur" aus `48d9b82`. Stellt `extract_sender_from_transaction(...).or(bundle.sender_id)` im Empfangspfad (~Z.442–464) und bedingungslose `counterparty_id`-Retention im Sendepfad (~Z.847–870) wieder her; löscht den Stripping-Block für `involved_sources_details` (~Z.916–936). Invertiert den Test zu `sa06_05_events_must_retain_counterparty_did_in_private_mode_for_offline_forensics` (läuft grün). Dokumentiert in design-decisions SKILL.md, PRIVACY_FAQ.md (133 Zeilen neu), STATUS.md (CORE-004).

#### Triage-Matrix

| Element/Finding | Suspected CWE | Outcome | Rationale (kurz) | Re-think? |
| :--- | :--- | :--- | :--- | :--- |
| Ursprungs-Finding HMSEC-SA06-05 (Stripping) | CWE-359/778 | **C [FALSE POSITIVE]** | Generische Log-Heuristik auf lokalen verschlüsselten Zustand; Widerspruch zu Q1/Q2 des Triage-Regelwerks. Revert korrekt. | Nein |
| TransferSent-Retention | – (Design) | **B** | Sender muss protokollieren, wem er übergeben hat; nur lokale, versiegelte Ablage. | Ja (Host-Grenze, s. unten) |
| TransferReceived + Summary-Retention | – | **B** | Empfänger-Herkunft (1 Hop) belegbar; Quelle authentifiziert. | Nein |
| View-Data-Retention involved_sources_details | – | **B** | Gleiche Vertrauensdomäne. | Nein |
| Test-Inversion | – | **B** (Action-Item) | Invariantentest vorhanden, grün. | Nein |
| Doku (design-decisions, FAQ, STATUS) | – | **B** (Action-Item) | Vollständig. | Nein |
| Asymmetrie: Quarantäne-/Konflikt-Events mit `counterparty_id: None` (transaction_handler.rs:563,594,660) | – | – (nicht Teil des Commits) | Forensisch inkonsistent zur neuen Entscheidung. | **ja** |

#### Elemente, die nochmal durchdacht werden müssen
1. **Host-App-Grenze:** Events verlassen Core unverschlüsselt Richtung UI (`app_queries.rs:167` liefert `Vec<WalletEvent>`); Cloud-Backup/Sync darf Events niemals im Klartext führen — explizite Invariante/Doku + ggf. Test fehlen.
2. **Quarantäne-Events:** Gerade bei Double-Spend-Quarantäre wäre die Gegenpartei-Info am nützlichsten — offener Punkt für Folgetriage.
3. Kein Re-Change nach dem Commit (`git diff HEAD 382bad8 -- src/ tests/` leer).

---

## 5. Methodik & Verifikation

- Pro Commit: voller Diff via `git show`, Parent-Vergleich für Vorher-Zustand, HEAD-Status aller betroffenen Codepfade geprüft (kein späterer Commit revertiert etwas außer dem dokumentierten `382bad8`).
- Referenzdokumente: `DESIGN_INTENT_TRIAGE.md`, `PRIVACY_FAQ.md`, `THREAT_MODEL.md`, `.agents/skills/design-decisions/SKILL.md`.
- Testverifikation durch die Agenten: Module-02 (3/3), Module-03 (9/9), Module-04 (3/3), Module-05 (3/3), Module-06 (6/6) jeweils grün an HEAD; signature_reuse-Tests 3/3.
- **Wichtiger Querbefund:** Auf der Arbeitskopie existiert **uncommittete AUDIT-01-Nachfolgearbeit** (S-Skalar-Canonicalisierung, Import-Gate 3b, struktureller Placeholder-Skip, neue Test-Suite `tests/security_audit_module_01_traps.rs`), die mehrere der in diesem Report benannten Lücken (K3, W3) bereits addressiert — aber noch nicht committed ist.
