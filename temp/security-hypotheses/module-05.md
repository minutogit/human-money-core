# Security-Hypothesen — Modul 05: Storage & Key-Persistence

> Agent: A-05 · Phase A (Research only, kein Cargo-Kontakt)
> Scope: `src/storage/` (file_storage.rs, mod.rs), `src/archive/` (file_archive.rs, mod.rs),
> `services/mnemonic.rs`, `models/profile.rs`, `models/storage_integrity.rs`,
> `services/integrity_manager.rs` (+ Querverweise auf `models/secure_container.rs`, `bin/voucher-cli.rs`)
> Bereits abgedeckt (NICHT erneut vorgeschlagen): SA05-01 (Archive at-rest verschlüsselt),
> SA05-02 (Manipulierte Archiv-Records vor Deserialisierung erkannt), SA05-03
> (Mnemonic-Validierungsfehler ohne Phrase-Disclosure).

---

## H-05-01 — Stiller Leer-State & unentdeckter Rollback von vouchers.enc (Crash-Konsistenz)

- **Status Phase B:** CONFIRMED+FIXED (Rollback-Hälfte; Missing-Store-Hälfte = INTENTIONAL) —
  Test `sa05_04_rolled_back_voucher_store_must_not_load_silently` (HMSEC-SA05-04) schlug auf
  unpatched Code fehl (Ok mit wiederbelebtem Voucher); Fix: `store_binding_hash`
  (SHA3-256 über VoucherStorageContainer-Bytes, `#[serde(default)]`, rückwärtskompatibel) in
  `ProfileStorageContainer`, gesetzt in save_wallet, verifiziert in load_wallet →
  `Err(StateConflict)` bei Mismatch. Fehlende Datei bleibt bewusst tolerant (dokumentiert:
  tests/persistence/README.md + `test_load_with_missing_voucher_store`) und wird von der
  signierten Storage-Integrity-Schicht als `MissingItems` gemeldet — im Test als
  Kontroll-Assertion dokumentiert. 62 Speicher-affine Tests (persistence/architecture/
  double_spend) zusätzlich grün.

- **Vermutung:** `FileStorage::load_wallet` behandelt eine fehlende `vouchers.enc` still als
  leeren Store (`else { VoucherStore::default() }`). Ein Crash zwischen den beiden `fs::rename`
  Calls in `save_wallet` (Profile zuerst, Store danach; kein fsync dazwischen), ein
  Sync-/Backup-Restore oder ein lokaler Angreifer, der nur `vouchers.enc` löscht, führen somit
  NICHT zu einem harten Fehler, sondern zu einer scheinbar validen, aber leeren Wallet. Zusätzlich
  bleibt bei Updates der `file_key` über alle Saves konstant (Update-Pfad lädt den existierenden
  Container und wickelt nur neue Payloads um) — d. h. eine ZURÜCKGEROLLTE alte `vouchers.enc`
  entschlüsselt weiterhin fehlerfrei unter demselben Key. Es gibt keine Cross-File-Bindung
  (Generation/Epoche) zwischen `profile.enc` und `vouchers.enc`; ein Mismatch wird nie als
  `StorageError::StateConflict` sichtbar. Folge: stiller Datenverlust bzw. stiller State-Rollback,
  der Double-Spend-Forensik und "Earliest Wins"-Auflösung verfälschen kann.
- **Betroffene Invariante:** Crash-Konsistenz / atomare Writes (System-Invariante 2) und
  Storage-Integrity (Invariante 3): Verlust/Korruption/Rollback eines Stores darf niemals still
  als valider Leer-Zustand durchlaufen.
- **Zielcode:** src/storage/file_storage.rs :: load_wallet (~269–283, stiller Default-Fallback);
  save_wallet (~387–405, zwei unabhängige tmp+rename-Paare ohne fsync/Cross-File-Bindung)
- **Geplanter Fail-First-Test:** Wallet mit 1 Voucher speichern, `vouchers.enc`-Bytes snapshotten,
  zweiten Voucher hinzufügen + speichern, dann die alten `vouchers.enc`-Bytes zurückspielen
  (simulierter Torn-Write/Rollback); ferner in einem zweiten Szenario `vouchers.enc` komplett
  löschen. Soll-Assertion: `storage.load_wallet(...)` muss in BEIDEN Fällen `Err(StorageError::...)`
  liefern (oder einen expliziten Integritäts-Signalpfad exponieren). Unpatched liefert
  `Ok((profile, leerer/alter Store, identity))` → Test schlägt fehl und beweist die Lücke.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Der Default-Fallback ist
  vermutlich für die Erst-Erstellung gedacht (`store_path` existiert beim ersten Login noch nicht).
  Das ist legitim unterscheidbar (`profile_exists()` == true + fehlender Store ≠ frisches Wallet).
  Die Remove-vor-Archive-Reihenfolge ist dagegen DOKUMENTIERT intentional (HMC-SEC-04-03,
  transaction_handler.rs ~830/978: Archivierung erst NACH Commit) → nicht Teil des Fix-Anspruchs;
  nur der fehlende Mismatch-/Missing-Store-Fehlerpfad ist Kandidat.
- **Priorität:** HIGH

---

## H-05-02 — Legacy-Downgrade-Bypass: Klartext-JSON im Archiv umgeht die AEAD-Integritätsprüfung

- **Status Phase B:** CONFIRMED+FIXED — Test `sa05_05_plaintext_archive_record_must_be_rejected_as_integrity_violation`
  (HMSEC-SA05-05) schlug auf unpatched Code fehl (`Ok(Some(forged voucher))` mit aufgeblähtem
  Betrag). Triage: kein dokumentiertes Legacy-Leserecht als Sicherheitsanforderung (nur
  Code-Kommentar); seit HMSEC-SA05-01 schreibt jeder Writer versiegelt → Fallback dient nur
  Angreifern. Fix: `read_record` liefert jetzt `IntegrityViolation` für nicht-Envelope-Records
  (strenge Zurückweisung erdgestützter Klartext-Records, dokumentierte Kompatibilitäts-
  Entscheidung); Modul-Doku aktualisiert. 38 Archiv-affine Tests (persistence/archive, sa04,
  double_spend) grün.

- **Vermutung:** `read_record` akzeptiert JEDES JSON, das nicht wie ein Sealed Envelope aussieht,
  als "Legacy-Klartext-Record" und deserialisiert es direkt als `Voucher` — OHNE jede Integritäts-
  oder Authentizitätsprüfung. Ein lokaler Angreifer kann damit die SA05-02-Remediation gezielt
  unterlaufen: statt Bits in einem Envelope zu flippen (wird als `IntegrityViolation` erkannt),
  ERSETZT er den Record einfach durch kanonisches Klartext-Voucher-JSON mit manipuliertem Betrag /
  manipulierter Transaktionskette. `looks_like_envelope` (ODER-Verknüpfung dreier Marker) schlägt
  fehl → der gefälschte Klartext wird akzeptiert, fließt in `find_transaction_by_id` /
  Double-Spend-Analyse ein und vergiftet Forensik genau so, wie SA05-02 es verhindern sollte.
  Der Fallback verwandelt "Verschlüsselung at-rest" in eine OPT-IN-Integrität: Wer das Format
  stript, entkommt der Prüfung.
- **Betroffene Invariante:** Storage-Integrity (Invariante 3): Manipulationen müssen deterministisch
  VOR Deserialisierung erkannt werden — für ALLE Records, nicht nur für Envelope-förmige.
- **Zielcode:** src/archive/file_archive.rs :: read_record (~189–192, Legacy-Fallback) +
  looks_like_envelope (~299–303, rein strukturelle Heuristik ohne Authentizität)
- **Geplanter Fail-First-Test:** Validen Voucher via `FileVoucherArchive::new_secure` archivieren;
  dann den Record auf Disk durch das manipulierte, kanonische Klartext-JSON eines gefälschten
  `Voucher` (z. B. verdoppelter `nominal_value.amount`, injizierte zusätzliche Transaktion)
  überschreiben. Soll-Assertion: `find_transaction_by_id` / `get_archived_voucher` müssen
  `Err(ArchiveError::IntegrityViolation(_))` liefern (unverschlüsselte Records sind nach
  Remediation HMSEC-SA05-01 kein gültiger Zustand mehr); unpatched liefert
  `Ok(Some(manipulierter Voucher))` → FAIL beweist den Downgrade-Bypass.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Der Doc-Kommentar nennt
  den Fallback "read-only compatibility" für Altbestände. Frage 1 des Triages: Gibt es reale
  Legacy-Installationen, deren History zwingend lesbar bleiben MUSS? Falls ja: Minimalfix wäre
  ein Migration-Gate (Legacy-Records nur bei explizit aktivierter Migration akzeptieren, danach
  hart ablehnen bzw. beim ersten Zugriff sealed neu schreiben) statt bedingungsloser Akzeptanz.
  Tendenz: `[CONFIRMED VULNERABILITY]` mit Design-Note.
- **Priorität:** HIGH

---

## H-05-03 — Lock-Protokoll: TOCTOU-Doppelacquire (kein O_EXCL) + Reflektion angreiferkontrollierten Lock-Datei-Inhalts in Fehlerausgabe

- **Vermutung:** Zwei Schwächen in derselben Funktion: (1) `lock()` prüft Existenz/Lesbarkeit der
  Lock-Datei und erstellt sie DANNEBEN mit `fs::File::create` (truncate, kein
  `OpenOptions::new().create_new(true)` = O_EXCL). Zwei Prozesse, die gleichzeitig eine Stale-Lock
  vorfinden (oder im Fenster zwischen exists()-Check und create() laufen), entfernen/überschreiben
  sich gegenseitig und ERHALTEN BEIDE `Ok(true)` → zwei Live-Prozesse schreiben concurrently in
  dieselbe Wallet (torn writes, Generation-Desync). Auch `write_generation` ist check-then-write
  ohne diese Absicherung. PID-Recycling kann zudem einen fremden, lebenden Prozess fälschlich als
  Lock-Inhaber deklarieren (DoS) — bekannt-pragmatisch. (2) Der Inhalt der Lock-Datei wird als
  Fehlermeldung refligiert: `format!("Ungültige PID in Lock-Datei: {}", pid_str)` — ein Angreifer
  (oder korrupter Inhalt) kann beliebige Bytes inkl. Steuerzeichen/Log-Injection-Payload in
  Fehlerlogs der Host-App einspeisen (CWE-117/CWE-209-Familie, jenseits der bereits getesteten
  Mnemonic-Disclosure). Querverweis: Fremd-Löschung durch `unlock()` ohne Owner-Check ist bereits
  in module-00-wildcard.md gehypothetisiert — hier NUR Acquisition-Race + Log-Reflektion.
- **Betroffene Invariante:** Exklusiver Wallet-Zugriff als Vorbedingung für atomares Schreiben
  (Invariante 2) und Memory-/Log-Hygiene (Invariante 4).
- **Zielcode:** src/storage/file_storage.rs :: lock (~868–916, insb. 874–908 Check-then-create,
  879–881 Reflektion, 912 `File::create`); src/storage/mod.rs :: WalletLockGuard::drop (~350–364)
- **Geplanter Fail-First-Test:** (a) In einer Tempdir eine Stale-Lock mit PID eines toten Prozesses
  anlegen; dann N Threads an einer Barriere gleichzeitig `lock()` auf identischem `FileStorage`-
  Pfad aufrufen (mehrere Runden). Soll-Invariante: In KEINER Runde erhalten ≥2 Threads gleichzeitig
  `Ok(true)`; unpatched kollidieren sie gelegentlich im Check/Create-Fenster → FAIL (race-window-
  basiert, daher mit hoher Rundenzahl und Toleranz-Notiz). (b) Lock-Datei mit Payload
  `"9999\n[ERROR] injected"` anlegen → `lock()`-Fehler darf ausschließlich Ziffern (PID) enthalten,
  keine Steuerzeichen/Payload; unpatched reflektiert den Rohinhalt → FAIL.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Für (1) spricht der
  bewusst einfache PID-Ansatz inkl. sysinfo-Stale-Check — aber O_EXCL wäre drop-in-kompatibel,
  daher eher `[CONFIRMED VULNERABILITY]` (MEDIUM). Für (2) kaum rechtfertigbar; Sanitizing ist
  trivial. Cross-Check nötig gegen A-00 (unlock-Thema), um Doppelung zu vermeiden.
- **Priorität:** MEDIUM

---

## H-05-04 — SecureContainer Drop/Zeroize: Memory-Hygiene-Invariante ungetestet + Feldabdeckungslücken (recipients/salt/unprotected)

- **Status Phase B:** CONFIRMED+FIXED — Test `sa05_06_secure_container_drop_must_zeroize_all_sensitive_fields`
  (HMSEC-SA05-06, unsafe Heap-Inspektion mit Canary-Buffers, Offset 32 wegen Allocator-
  Freelist-Metadaten) schlug auf unpatched Code gezielt bei `encrypted_key` fehl
  (ciphertext-Assert grün → Technik validiert). Fix: Drop nullisiert jetzt zusätzlich alle
  `recipients[].encrypted_key` und `salt`; `unprotected`/`recipient.header` (serde_json::Value,
  nicht zuverlässig nullisierbar) werden auf None gesetzt — Limitation ehrlich im Rust-Doc
  dokumentiert. 48 Container/Bundle/Krypto-affine Tests grün.

- **Vermutung:** Laut temp/uncovered_code.md (KRITISCH, Zeile ~124) ist das `Drop`-Impl von
  `SecureContainer` UNGETESTET — ein Mutant, der Zeroize entfernt, würde survive. Zudem deckt das
  `Drop`-Impl nur `protected/iv/ciphertext/tag/signature` ab; NICHT nullisiert werden:
  `recipients[].encrypted_key` (Base64 der pro-Empfänger gewrappten Payload-Keys — sensitivste
  Rest-Metadaten), `salt` (PBKDF2-Salt bei Symmetric) und `unprotected` (kann Sender-ID tragen).
  Ohne invarianten Test ist die Memory-Hygiene-Garantie (Invariante 4) rein deklarativ.
- **Betroffene Invariante:** Memory Hygiene: sensitive Schlüsselmaterial-Reste dürfen nach Drop
  nicht unnullisiert im Heap verbleiben; die Garantie muss test-regressions-gesichert sein.
- **Zielcode:** src/models/secure_container.rs :: impl Drop for SecureContainer (~182–190;
  uncovered_code-Ref ~124) + JweRecipient (~117–124, `encrypted_key` ungeschützt)
- **Geplanter Fail-First-Test:** Unsafe-Inspektionstest: `SecureContainer` mit bekannten Buffer-
  Inhalten (ciphertext, recipients[0].encrypted_key) via `Box::into_raw` leak-en, Buffer-Pointer/
  Längen vorher capturen, dann `ptr::drop_in_place` und beide Buffer via
  `slice::from_raw_parts` lesen. Soll-Assertions: (a) ciphertext-Buffer komplett nullisiert —
  Regression-Guard gegen Mutanten; (b) `encrypted_key`-Buffer komplett nullisiert — DIESER Assert
  schlägt auf unpatched Code FEHL (Feld wird im Drop gar nicht angefasst) und beweist die
  Abdeckungslücke. Fix: `recipients.iter_mut().for_each(|r| r.encrypted_key.zeroize())` etc.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Nein für die Lücke —
  gewrappte Payload-Keys sind klar sensitive Reste, keine dokumentierte Ausnahme. Einschränkung
  ehrlich benennen: Zeroize auf String erfasst Realloc-Kopien nicht (defense-in-depth, kein
  Hard Guarantee) — Test dokumentiert das Soll-Niveau, ersetzt keine Allocator-Strategie.
- **Priorität:** HIGH

---

## H-05-05 — KDF-Politik-Regression: PBKDF2-Runden unter OWASP-Richtwert, undokumentierte Argon2-Defaults, test-utils-Kollaps nur durch Konvention geschützt

- **Vermutung:** Drei verbundene Befunde: (1) Archiv-Records nutzen PBKDF2-HMAC-SHA512 mit
  100_000 Runden — unter dem OWASP-2023-Richtwert (≥210_000 für HMAC-SHA512); passwortbasierte
  Offline-Attacken auf gestohlene Archive werden dadurch günstiger. (2) `get_argon2()` nutzt
  `Argon2::default()` ohne explizite, dokumentierte m/t/p-Parameter — ein Crate-Upgrade könnte
  Defaults still verschlechtern, ohne dass ein Test es bemerkt. (3) Unter
  `cfg(any(test, feature = "test-utils"))` kollabieren ALLE KDFs auf einrundiges SHA-256 bzw.
  PBKDF2_ROUNDS=1 — abgesichert NUR durch die AGENTS-Regel "test-utils nie in Release"; kein
  Test/Bewachung verhindert, dass ein Release-Build versehentlich mit test-utils gebaut wird
  (dann wäre Passwort-KDF = SHA256(password||salt)).
- **Betroffene Invariante:** At-Rest-Confidentialität (Invariante 1): passwort-abgeleitete Keys
  müssen gegen Offline-Brute-Force angemessene KDF-Kosten haben — release UND test-profile-trennbar.
- **Zielcode:** src/services/crypto_symmetric.rs :: encrypt_symmetric_password/decrypt_symmetric_password
  (~214–218, PBKDF2_ROUNDS=100_000); src/storage/file_storage.rs :: get_argon2 (~1372–1375),
  derive_key_from_password (~1378–1401), derive_key_from_signing_key (~1404–1427)
- **Geplanter Fail-First-Test:** KDF-Konfiguration als öffentliche, cfg-selektierte Konstante/
  Getter exponieren (Fix-Bestandteil) und invariant testen: `assert!(kdf_rounds_for_profile() >= 210_000)`
  bzw. `assert!(argon2_params_documented_and_meet_policy())`. Auf unpatched Code liefert der Getter
  im Test-Profil 1 → FAIL beweist die Lücke; Triage entscheidet, ob Test-Profil bewusst schnell
  bleibt ([INTENTIONAL DESIGN REQUIREMENT] für Testlaufzeit → dann Guard-Test auf RELEASE-Wert +
  compile-time Assertion gegen test-utils-in-release statt Wert-Test).
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Ja, teilweise: Die
  Test-Profil-Vereinfachung ist legitimes Test-Speed-Design; kritisch ist nur der fehlende Schutz
  gegen test-utils-im-Release. Runden-/Default-Anhebung (1)+(2) ist normales Härtungs-Budget,
  kein Design-Bruch. Erwartetes Triage-Ergebnis: Split — (3) Guard-Pflicht, (1)/(2) Härtung.
- **Priorität:** MEDIUM

---

## H-05-06 — Plaintext-Leak-Pfad: voucher-cli persistiert Mnemonic und Roh-Private-Key unverschlüsselt

- **Vermutung:** Das Dev-Binary `voucher-cli generate-keys` schreibt die komplette BIP-39-Mnemonic
  (`issuer.mnemonic`) und die rohen Ed25519 Private-Key-Bytes (`issuer.key`) KLARTEXTIG nach
  `target/dev-keys/`. `target/` liegt typischerweise in Cloud-Sync-, Backup- oder CI-Artefakt-
  Pfaden; zudem verletzt Klartext-Key-Persistenz systematisch die Architektur-Annahme "nie
  plaintext at rest", die die Core-Library überall erzwingt. Sweep-Ergebnis (negativ, zur Doku):
  Innerhalb des Library-Codes (storage/, archive/, wallet/, app_service/) existiert KEIN weiterer
  Plaintext-Persistenzpfad für Mnemonics/Keys — Exportfunktionen (`export_own_fingerprints`,
  `export_profile_jws`) führen nur Public-Material aus und gehören zu Modul 01/06.
- **Betroffene Invariante:** At-Rest-Confidentiality (Invariante 1): Private Keys und Seed-Phrases
  dürfen NIE im Klartext persistiert werden.
- **Zielcode:** src/bin/voucher-cli.rs :: generate_keys (~79–104, fs::write mnemonic_path/key_path)
- **Geplanter Fail-First-Test:** `generate_keys`-Logik (in testbare Funktion extrahiert oder via
  Dateisystem-Inspektion nach Aufruf) ausführen und alle erzeugten Dateien scannen: Keine Datei
  darf die Mnemonic-Wörter oder die 32 rohen Key-Bytes (Base58/Hex/Rohvergleich) enthalten.
  Unpatched enthält `issuer.mnemonic` die Phrase im Klartext → FAIL. Alternativ (falls Binary
  außerhalb der Test-Reichweite bleibt): mindestens Warn-/Permission-Invariantetest
  (0600 + Outside-target-Dir) als dokumentierte Schwächung.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Plausibel: reines Dev-
  Tool für Standard-Issuer-Keys ("dev-keys"), kein Wallet-Pfad. Wenn triaget als intentional:
  Code-Doku ergänzen (Warum, Threat-Model-Ausnahme) + Invariantentest, der sicherstellt, dass der
  Pfad strikt auf Dev-Builds/`target/` beschränkt bleibt — NICHT die Logik "reparieren".
- **Priorität:** LOW

---

## Abdeckungs-Matrix (Phase A)

| Hypothese | Koordination §2 Modul 05 🔍 | Neu |
|---|---|---|
| H-05-01 | Crash-Konsistenz ✚ novel: stiller Default-Fallback/Rollback | teils |
| H-05-02 | — (novel Downgrade-Bypass über SA05-02-Remediation hinweg) | ✔ |
| H-05-03 | Filesystem-Race/Lock-Handling + Log/Error-Disclosure | teils |
| H-05-04 | uncovered_code.md CRITICAL: Drop/Zeroize untested | ✔ |
| H-05-05 | Weak KDF/Salt/Nonce | teils |
| H-05-06 | Plaintext-Leak-Pfade (Export/Backup/unauth. Speichern) | teils |

Keine Überschneidung mit SA05-01/02/03 (bereits grün). Cross-Ref: unlock-Fremdlöschung →
module-00-wildcard.md; Mid-Operation-Desync Wallet↔Store↔Archiv → module-04.md (H-05-01 deckt nur
die Storage-Layer-Sicht ab).

---

# Wave 3 (Stand: HEAD b006cfb)

> Agent: A-05 · Phase A (Research only, kein Cargo-Kontakt). Basis: Commits `fdfeb80`,
> `d31bd89` (HMC_TX_AUTH_V2), `b006cfb` (HMC_TX_AUTH_V3/SST). Storage/Archive selbst wurden
> seit Wave 2 kaum direkt geändert (`tests/persistence/file_storage.rs` ±1..4 Zeilen);
> die neuen persistierten Strukturen (TrapData{ds_tag,trap_r,trap_s},
> TransactionFingerprint{sender_ephemeral_pub,trap_r,trap_s}) stammen aus den Protokoll-
> Commits und wirken auf gespeicherte States in `known_fingerprints.enc`,
> `own_fingerprints.enc`, `proofs.enc` und `vouchers.enc`.

## Statusverifikation der Wave-2-Restgaps (keine neuen Blöcke, keine Duplizierung)

- **H-05-03 (Lock-TOCTOU + PID-Reflektion): WEITERHIN UNFIXED, Code verifiziert.**
  `src/storage/file_storage.rs :: lock` (Zeilen ~907–955): Check-then-create mit
  `fs::File::create` (Zeile 951, kein `create_new(true)`/O_EXCL); Roh-Inhalt-Reflektion in
  `format!("Ungültige PID in Lock-Datei: {}", pid_str)` (Zeile ~919). Hypothese bleibt
  unverändert offen (MEDIUM); nur Acquisition-Race + Log-Reflektion, unlock-Thema → A-00.
- **H-05-05 (KDF-Politik): unverändert offen.** `crypto_symmetric.rs` Zeilen ~216/254:
  PBKDF2-HMAC-SHA512 100_000 Runden (< OWASP-Richtwert), test-utils-Kollaps auf 1 Runde nur
  durch Konvention geschützt; `get_argon2()` weiter `Argon2::default()`
  (file_storage.rs ~1429–1432).
- **H-05-06 (voucher-cli Plaintext-Keys): unverändert offen (LOW).**
  Neu beobachtet, aber kein eigener Block: `src/test_utils/voucher_setup.rs` wurde stark
  erweitert (V2/V3-Resign-Helfer, `make_signed_fingerprint`, `sign_fingerprint_in_place`),
  enthält jedoch KEINEN neuen Produktions-Plaintext-Persistenzpfad (Fixture-Code,
  `#[cfg]`-gebunden an test-utils) — für Wave 3 kein eigenständiger Finding-Kandidat.
- **K2 (Legacy-Downgrade, SA05-05): FIX VERIFIZIERT.** `read_record`
  (src/archive/file_archive.rs ~183–214) verwirft nicht-Envelope-Records jetzt hart mit
  `IntegrityViolation`. Umwege-Suche: Teil-Envelope/Gemischt-Format führt zwar durch die
  Marker-Heuristik `looks_like_envelope` (ODER aus `format`/`ciphertext`/`kdf_salt`,
  ~321–325), scheitert aber an der nachgelagerten KDF-Auswahl (unbekannter `kdf` → Reject;
  `raw`/`pbkdf2-sha512` ohne gültiges AEAD-Tag → Reject). Verbleibende Restlücke ist der
  **ganze-Record-Angriff** (Replay/Swap/Löschen authentischer Envelopes) → WH3-05-504.
- **Debug/Display-Sweep (Angriffsvektor 4): negativ.** `UserIdentity` und `ProfilePayload`
  leiten kein `Debug` ab; die neuen Konflikt-Modelle (`TransactionFingerprint`,
  `ProofOfDoubleSpend`, `TrapData`) formatieren nur Public-/Gossip-Material (Ephemeral-Keys,
  Shard-Werte sind Netzwerkdaten) bzw. lokale Forensik-Daten — kein Key-/Mnemonic-Leak
  über `Display`/`Debug` gefunden (über SA05-03 hinaus).

---

## WH3-05-501 — store_binding_hash ist unauthentifiziert und strippbar (SA05-04-Umgehung)

- **Status Phase B (A-05, Pipeline):** WRITE done, Test `sa05_07_store_binding_hash_must_be_authenticated_and_mandatory`
  (HMSEC-SA05-07), **erwartet FAIL** auf unpatched Code. Zielcode frisch verifiziert:
  Klartextfeld `#[serde(default)]` (~110–121), Check-Skip via `if let Some` (~293),
  unkeyed SHA3-Binding (~425–427). Beide Angriffe im Test implementiert:
  (a) Feld aus profile.enc strippen + Gen1-vouchers.enc zurückspielen,
  (b) Hash per öffentlichem `get_hash` über Gen1-Bytes neu eintragen.
  Soll: je Variante `Err(StorageError::StateConflict)`; unpatched liefert Ok mit
  wiederbelebtem Voucher → FAIL beweist die Umgehung.

- **Vermutung:** Die SA05-04-Remediation bindet `store_binding_hash` als schlichtes
  SHA3-256-Feld in den **KLARTEXT-JSON-Bereich** von `ProfileStorageContainer` ein (der
  Container ist unverschlüsseltes JSON; nur die Payloads darin sind AEAD-verschlüsselt).
  Ein lokaler Angreifer mit Schreibrecht kann den Schutz daher auf zwei Wegen komplett
  ausschalten: (a) Feld einfach **entfernen** — `#[serde(default)]` macht es zu `None`,
  und `load_wallet` überspringt die Prüfung vollständig (`if let Some(expected_hash)`);
  (b) den Hash **neu berechnen**: `get_hash` ist plain SHA3-256 über die Datei-Bytes von
  `vouchers.enc` — kein Schlüssel nötig. Gen1-Backup zurückspielen + Hash darüber schreiben
  → ausgegebene Voucher werden wiederbelebt, exakt der Angriff, gegen den SA05-04 gebaut
  war. Das Binding detektiert nur *zufällige* Torn Writes, nicht den adressierten Angreifer;
  die einzige authentifizierte Schicht (signierter `LocalIntegrityRecord`) läuft separat und
  optional. Zusätzlich fehlt eine Migrations-Gate: Auch NACH dem ersten Re-Save mit neuem
  Code wird ein gestripptes Feld als "legacy" toleriert statt als Verstoß gewertet.
- **Betroffene Invariante:** Storage-Integrity (Invariante 3): Rollback-Erkennung darf nicht
  vom Angreifer abschaltbar sein; SA05-04-Invariante ("rolled-back vouchers.enc MUST NOT
  load silently") gilt nur gegen Crash, nicht gegen Manipulation.
- **Zielcode:** `src/storage/file_storage.rs` :: `ProfileStorageContainer.store_binding_hash`
  (~110–121, Klartextfeld + `#[serde(default)]`), `load_wallet` (~293–302, `if let Some`),
  `save_wallet` (~425–427, ungeschützter Hash)
- **Geplanter Fail-First-Test:** Wallet zweimal speichern (Gen1: 1 aktiver Voucher, Gen2:
  leer), Gen1-`vouchers.enc` zurückspielen UND `store_binding_hash` aus `profile.enc`
  entfernen (Szenario b alternativ: Hash über Gen1-Bytes neu eintragen). Soll-Assertion:
  `load_wallet` liefert `Err(StorageError::StateConflict)` bzw. verweigert das Laden
  (post-Migration: fehlendes Feld nach erstem V3-Save = Tamper). Unpatched: `Ok` mit
  wiederbelebtem Voucher → FAIL beweist die Umgehung.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Das `serde(default)` selbst ist
  legitime Rückwärtskompatibilität für PRE-Fix-Container; nicht gerechtfertigt ist die
  dauerhafte Strip-Toleranz nach Migration sowie der Verzicht auf Authentizität des Bindings
  (Key oder Aufnahme in den signierten IntegrityRecord wäre drop-in möglich). Erwartung:
  `[CONFIRMED VULNERABILITY]` mit Design-Note zur Legacy-Toleranz.
- **Priorität:** HIGH

---

## WH3-05-502 — V2→V3-Migration: Serde-Feld-Drop zerstört Trap-/Fingerprint-Daten still (kein Schema-Versionierungs-Gate)

- **Status Phase B (A-05, Pipeline):** WRITE done, Test `sa05_08_legacy_v2_fingerprint_data_must_not_be_silently_degraded`
  (HMSEC-SA05-08), **erwartet FAIL** auf unpatched Code. Storage/Serialisierungs-Seite
  (Abgrenzung Wallet-State → A-00): Zielcode frisch verifiziert — `TransactionFingerprint`
  (conflict.rs ~17–63) defaulted `sender_ephemeral_pub/trap_r/trap_s`, `TrapData` (voucher.rs
  ~88–99) ebenso; `load_own_fingerprints` (file_storage.rs ~542–566) deserialisiert ohne
  jedes Schema-Gate. Test craftet ein byte-exaktes V2-Payload (`u`/`blinded_id` + L2-Signatur,
  ohne Shard-Felder) in einem VALIDEN verschlüsselten Container (File-Key via
  session-key-unwrap aus profile.enc rekonstruiert, Control-Roundtrip vorab grün).
  Soll: Schema-Gate (Err) ODER Verbatim-/Upgrade-Erhalt inkl. Write-back; unpatched:
  Ok mit degradiertem Hybrid (L2-Sig gesetzt, Shards leer) + verlustbehaftetes
  Zurückschreiben → FAIL.

- **Vermutung:** Der V3-Wechsel ersetzte `TransactionFingerprint{u, blinded_id}` durch
  `{sender_ephemeral_pub, trap_r, trap_s}` (letzte beiden `#[serde(default)]`) und
  `TrapData{u, blinded_id}` durch `{ds_tag, trap_r, trap_s}` (`trap_r/trap_s` defaulted).
  Alte verschlüsselte Stores (`known_fingerprints.enc`, `own_fingerprints.enc`,
  `vouchers.enc`-Payload) deserialisieren damit ERFOLGREICH: unbekannte Felder (`u`,
  `blinded_id`) werden ignoriert (= still vernichtet), neue Felder werden Leerstrings.
  Folgen: (1) Spend-Fingerprints mit leerem Shard fallen unter `is_init_fingerprint`
  (`trap_r.is_empty() || == "none"`, conflict_manager.rs ~180–186) in die Init-Klasse und
  verlieren jede Trap-Bedeutung; (2) die im Code als "complete and immutable history" /
  "critical component for backups and conflict verification" dokumentierte
  `OwnFingerprints.history` wird beim nächsten `save_*` verlustbehaftet im V3-Shape
  zurückgeschrieben — V2-Identitätsrekonstruktion (V = m·U + ID) alter Konflikte ist dann
  unwiederbringlich weg; (3) asymmetrisches Gate: `scan_and_rebuild_fingerprints` purge
  Foreign-Fingerprints sauber per Signatur-Gate (conflict_handler.rs ~41–49), merge
  `local_history` aber OHNE jedes Gate/Dedup-Upgrade (~52–60) — degradierte Alt-Einträge
  bleiben t_id-basiert ewig stehen und können nie durch frische V3-Entries ersetzt werden.
  Es existiert KEIN Schema-Versionsfeld/Manifest in diesen Containern: Das Protokoll erklärt
  "All V1/V2 fingerprints invalidated", die Persistenzschicht lädt sie trotzdem still als
  scheinbar valide Objekte statt fail-loud zu migrieren.
- **Betroffene Invariante:** Storage-Integrity/Kompatibilität (Invariante 3): Formatwechsel
  dürfen gespeicherte Beweisdaten nie still entwerten; Offline-Forensik (Hop-by-Hop-Kette)
  beruht auf persistenten Traps — stiller Datenverlust verfälscht Double-Spend-Aufklärung.
- **Zielcode:** `src/models/conflict.rs` :: `TransactionFingerprint` (~17–63,
  `#[serde(default)]`-Felder); `src/models/voucher.rs` :: `TrapData` (~88–99);
  `src/wallet/conflict_handler.rs` :: `scan_and_rebuild_fingerprints` (~32–65, Gate-Asymmetrie)
- **Geplanter Fail-First-Test:** V2-ära JSON einer `KnownFingerprints`/`OwnFingerprints`
  (mit `u`/`blinded_id`, ohne `trap_r`/`trap_s` und ohne `sender_ephemeral_pub`) via
  `save_known_fingerprints` wegschreiben, mit aktuellem Code laden. Soll-Assertion:
  entweder `Err(StorageError::InvalidFormat/UnsupportedSchemaVersion)` ODER ein expliziter
  Migrationsreport (Anzahl degradierter Entries > 0 als Fehler-/Signalpfad); zusätzlich
  Assert, dass ein geladener Fingerprint niemals gleichzeitig `layer2_signature != ""` und
  `trap_r == ""` sein darf (inkonsistenter Hybrid). Unpatched: stilles `Ok` mit
  leer-Shard-Objekten → FAIL.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Das Purge von FOREIGN
  Fingerprints am Load-Gate ist dokumentiert intentional (V2-Load-Time-Purge, Doc-Comment
  conflict_handler.rs ~28–31) — NICHT Bestandteil des Findings. Nicht dokumentiert ist das
  stiller Löschen der eigenen History-Felder und die Gate-Asymmetrie bei `local_history`;
  Breaking Change allein rechtfertigt keine lautlose Vernichtung beweiskriger Eigendaten.
- **Priorität:** HIGH

---

## WH3-05-503 — Torn-Write-Fenster des SA05-04-Fix: StateConflict ohne Recovery-Pfad (Wallet-Brick)

- **Vermutung:** `save_wallet` benennt ZWEI Dateien sequenziell um: erst `profile.enc`
  (mit neuem Binding-Hash), dann `vouchers.enc` (~443–444). Stirbt der Prozess dazwischen
  (Crash/OOM/Strom — genau das Szenario, das SA05-04 abdecken sollte), liegt
  `profile.enc(gen2, hash_G2)` + `vouchers.enc(gen1)` vor. Jeder weitere `load_wallet`
  liefert nun permanent `Err(StateConflict)` — es gibt NIRGENDWO einen Selbstheilungs-/
  Recovery-Pfad (kein Fallback auf letzten konsistenten Stand, kein Reparatur-Hinweis,
  kein Rollback des Profil-Bindings). Der User ist von seinen Mitteln abgeschnitten, bis
  er manuell Dateien chirurgisch entfernt. Der Wave-2-Fix hat damit die alte Lücke
  (stiller Rollback) in eine neue getauscht (detektierbarer, aber irreversibler Brick):
  Detect-only ohne Recover-Story verletzt Invariante 2 auf Availability-Seite. Korrekte
  Ordnung (Store zuerst / Journal-Recovery) oder ein dokumentiertes Repair-Kommando fehlen.
- **Betroffene Invariante:** Crash-Konsistenz & atomare Writes (Invariante 2): Ein Crash
  mid-write darf nie zu unrecoverable Zustandsverlust/-abschluss führen.
- **Zielcode:** `src/storage/file_storage.rs` :: `save_wallet` (~430–446, Rename-Ordnung
  ohne Journal), `load_wallet` (~293–302, harter Abort ohne Recovery-Semantik)
- **Geplanter Fail-First-Test:** Zwei Saves (Gen1/Gen2) wie im SA05-04-Test; dann den
  Crash deterministisch simulieren: `profile.enc`-Bytes von Gen2 schreiben, `vouchers.enc`
  auf Gen1-Bytes lassen (exaktes Nachbild des Rename-Fensters). Soll-Assertion: Es muss
  einen definierten Wiederherstellungsweg geben — z. B. `load_wallet` signalisiert den
  Konflikt strukturiert (maschinenlesbarer Fehler mit Gen-Paaren) und ein begleitender
  Storage-API-Recovery-Aufruf stellt Gen1-konsistenten Ladezustand her; pures endgültiges
  `Err(StateConflict)` bei jedem weiteren Versuch ohne jeden Ausweg = FAIL.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Hard-fail ist gegenüber dem
  alten Still-Rollback sicher korrekt gewählt; ob Bricking-without-recovery intendiert ist,
  ist nirgends dokumentiert (tests/persistence/README.md behandelt nur Missing-Store).
  Erwartetes Triage: Design-Lücke im Fix, nicht Intentional.
- **Priorität:** MEDIUM

---

## WH3-05-504 — Archiv W5: Replay/Swap/Löschen ganzer Records unentdeckbar (keine Location-Bindung, kein Manifest)

- **Status Phase B (A-05, Pipeline):** WRITE done, Test `sa05_09_archive_record_deletion_and_relocation_must_be_detectable`
  (HMSEC-SA05-09), **erwartet FAIL** auf unpatched Code. Zielcode frisch verifiziert:
  `read_record` authentisiert nur Klartext (keine Pfadbindung), `get_archived_voucher`
  sortiert nach Kettenlänge und serviert still ältere Stände weiter (~362–393),
  globaler Scan in `find_transaction_by_id` (~396–419). Beide stärksten Aspekte
  getestet: (a) Löschen des neuesten Records → Soll Err, unpatched Ok(älterer Stand);
  (b) echtes Envelope von A nach B kopiert → `get_archived_voucher(B)` liefert
  Voucher mit A's voucher_id (Fehlattribution). Unpatched scheitert mindestens (a).

- **Vermutung:** `read_record` authentisiert ausschließlich den Klartext (AEAD) — NICHT
  die Ablageposition. Envelope-Bytes sind frei rekombinierbar: (1) **Delete/Rollback:**
  Löschen der neuesten `<t_id>.json` eines Voucher-Verzeichnisses lässt
  `get_archived_voucher` stumm den ältesten Rest-Stand wählen (Sortierung nach
  Kettenlänge) — Forensik wird auf alten Stand zurückgerollt, ohne jeden Fehler;
  (2) **Swap:** ein gültiger Envelope aus Voucher A ins Verzeichnis von B verschiebt
  dessen Transaktionen in B's Historie — `find_transaction_by_id` (Scan über ALLE
  Unterverzeichnisse) attribuiert die Transaktion fortan zum falschen Voucher und
  vergiftet "Earliest Wins"-Auflösung; (3) **Pre-Seed-DoS:** Existiert eine Datei schon,
  bricht `archive_voucher` mit `Ok(())` ab (Existenz-Check ~344–346) — ein Angreifer kann
  Schreibvorgänge blockieren; noch schlimmer: eine beliebige envelope-förmige Mülldatei
  lässt `get_archived_voucher` dauerhaft mit `IntegrityViolation` abstürzen, weil der
  erste Lesefehler die gesamte Suche abbricht (~375–377) — permanente forensische
  Verfügbarkeitssperre pro Voucher. Die signierte Storage-Integrity-Schicht deckt diese
  Lücke NICHT: `get_all_item_hashes` scannt Unterverzeichnisse ausschließlich unter
  `events/` (~1160–1177) — Archiv-Unterverzeichnisse (`<voucher_id>/<t_id>.json`) liegen
  außerhalb und bleiben hash-/manifestlos.
- **Betroffene Invariante:** Storage-Integrity (Invariante 3) bezogen auf Ganze-Datensatz-
  Operationen: Löschung/Vertauschung/Rollback kompletter Records muss mindestens
  deterministisch erkennbar sein; SA05-02 deckt nur Bit-Manipulation IN einem Record ab.
- **Zielcode:** `src/archive/file_archive.rs` :: `read_record` (keine Pfadbindung),
  `archive_voucher` (~340–357, Existenz-Skip + rohe IDs), `get_archived_voucher`
  (~362–393, stille Auswahl älteren Stands, Error-Propagation), `find_transaction_by_id`
  (~396–419, globaler Scan); `src/storage/file_storage.rs` :: `get_all_item_hashes`
  (~1120–1180, Archiv-Subdirs unabgedeckt)
- **Geplanter Fail-First-Test:** Drei Teilassertionen je Szenario: (1) zwei archivierte
  States, neueste Record-Datei löschen → `get_archived_voucher` muss den Verlust melden
  (z. B. Err/IntegrityViolation via Manifest-Zähler) statt still den alten Stand zu
  liefern; (2) Envelope von Voucher A nach B kopieren → `find_transaction_by_id(txVonA)`
  darf A's Transaktion nicht unter B's Pfad/Kontext zurückgeben; (3) fremde
  envelope-artige Junk-Datei im Voucher-Dir → Lookup muss strukturiert melden statt
  pauschal zu crashen UND nachfolgendes `archive_voucher` darf den echten Stand nicht
  wegen Existenz-Checks verlieren. Unpatched scheitert mindestens (1)+(2) → FAIL.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Fail-closed bei korrupten
  Records ist intentional (SA05-02) und wird nicht angegriffen; fehlendes Manifest/
  Location-Binding ist nirgends als Entscheidung dokumentiert. Cross-Check: Überschneidung
  mit Modul-04 (Mid-Operation-Desync) nur bzgl. (3)-Blockier-Aspekt — Replay/Swap/Delete
  ist reines Modul-05-Terrain.
- **Priorität:** HIGH

---

## WH3-05-505 — N7: FileVoucherArchive::new_secure akzeptiert Empty-Password ohne Guard

- **Status Phase B (A-05, Pipeline):** WRITE done, Test `sa05_10_archive_construction_with_empty_password_must_be_rejected`
  (HMSEC-SA05-10), **erwartet FAIL** auf unpatched Code. Zielcode frisch verifiziert:
  `new_secure` (file_archive.rs ~122–127) speichert Passwort ungeprüft,
  `encrypt_symmetric_password`/`decrypt_symmetric_password` (crypto_symmetric.rs
  ~206/~247) ohne is_empty-Guard. Test: `new_secure(dir, "")` + `archive_voucher`;
  Soll: Err beim Seal (konstruktorseitige Signaturänderung als gleichwertige
  Alternative im Docblock vermerkt) und keine Record-Datei auf Disk;
  unpatched: glattes Ok(()) unter PBKDF2("") → FAIL.

- **Vermutung:** Weder `FileVoucherArchive::new_secure` (Konstruktor speichert den
  String ungeprüft, file_archive.rs ~122–127) noch `encrypt_symmetric_password` /
  `decrypt_symmetric_password` (crypto_symmetric.rs ~206/247, keine `is_empty`-Prüfung)
  wehren sich gegen ein leeres Passwort. `PBKDF2-HMAC-SHA512("", salt, 100k)` ist voll
  deterministisch und in Sekunden offline rekonstruierbar: Ein mit `""` erzeugtes Archiv
  ist nur noch obfuscatorisch geschützt — jeder Scanner mit dem öffentlichen Format
  (`hmc-archive-v1` + `pbkdf2-sha512`) decryptet alle Records. Damit kollabieren
  Invariante 1 (At-Rest-Confidentiality) und die Integritätsprüfung (AEAD-Tag unter
  bekanntem Key fälschbar → gefälschte, SA05-02-konforme Records werden akzeptiert!) für
  alle Host-Apps, die den offensichtlichen Default `" "`/"" durchreichen. FileStorage
  hat dasselbe Problem generell, dort fängt aber `AuthMethod::Password("")` immerhin der
  natürliche Login-Fail ab; im Archiv gibt es keinen zweiten Faktor.
- **Betroffene Invariante:** At-Rest-Confidentiality (Invariante 1) + Integrität (3):
  passwort-abgeleitete Record-Keys müssen von einem Geheimnis ≥ Entropie des Passworts
  abhängen; Empty-String darf nie einen validen Key liefern.
- **Zielcode:** `src/archive/file_archive.rs` :: `new_secure` (~122–127);
  `src/services/crypto_symmetric.rs` :: `encrypt_symmetric_password`/~206,
  `decrypt_symmetric_password`/~247
- **Geplanter Fail-First-Test:** `FileVoucherArchive::new_secure(dir, "")` + ein Voucher
  archivieren. Soll-Assertion: Konstruktion ODER erster Seal-Vorgang muss fehlschlagen
  (`ArchiveError::Generic("empty password rejected")` bzw. Panic mit dokumentierter
  Policy); zusätzlich Gegenprobe: `decrypt_symmetric_password` mit `""` auf
  Angreifer-Sicht (bekanntes Format) darf niemals Klartext liefern. Unpatched: Archiv
  wird erfolgreich und glatt verschlüsselt-abgelegt → FAIL.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Kaum — ein leerer
  Passwort-String trägt keine Entropie; kein Doc/ADR verteidigt das. Minimal-invasiver
  Fix (Guard im Konstruktor) ändert keine Serialisierung/Logik für legitime Nutzer.
- **Priorität:** MEDIUM

---

## WH3-05-506 — N5: get_item_hash ohne Traversal-Sanitization (Absolutpfad-Ersetzung, Hash-Orakel) + Save/Load-Asymmetrie bei arbitrary_data

- **Status Phase B (A-05, Pipeline):** WRITE done, Test `sa05_11_arbitrary_data_read_paths_must_enforce_name_sanitization`
  (HMSEC-SA05-11), **erwartet FAIL** auf unpatched Code. Zielcode frisch verifiziert:
  `get_item_hash` (file_storage.rs ~1076–1083) joint roh (`join(name)`, Absolutpfad
  ersetzt Basis), `load_arbitrary_data` (~866–888) ohne Validation vs. Save-Guard
  (~838–842). Test: Save-Reject als Kontroll-Assert (heute grün, Konvention),
  dann `get_item_hash(<abs outside>)` und `get_item_hash("../../outside_secret.txt")`
  → Soll `Err(Generic)`; `load_arbitrary_data("../outside")` → Soll dieselbe
  Reject-Klasse wie Save (Konsistenz), nicht NotFound. Unpatched: Hash-Orakel Ok /
  NotFound → FAIL.

- **Vermutung:** `get_item_hash(name)` joint den Namen ROH: `user_storage_path.join(name)`
  (file_storage.rs ~1076–1083) — ein absoluter Pfad ERSETZT den Basispfad vollständig
  (`join("/etc/passwd")` → `/etc/passwd`), Relativtraversal (`../../…`) liest beliebig
  weit outside. Ergebnis ist ein SHA3-256-Hash-Orakel über jede prozesslesbare Datei.
  Zwar nutzen heutige interne Aufrufer (`get_all_item_hashes` → seal_handler/lifecycle)
  nur selbst gescannte Verzeichnisnamen, aber die Methode ist öffentliches Trait-API
  (Storage ist exportiert; Tauri-Hosts reichen UI-Input durch) und verletzt die eigene
  Konvention: `save_arbitrary_data` validiert denselben Namensraum explizit
  (`'/'|'\\'|".."`-Reject, ~838–842) — `load_arbitrary_data` (~866–888) hingegen gar
  nicht (strukturell durch `generic_{}.enc`-Präfix entschärft, aber inkonsistent und nur
  zufällig sicher). Zusätzlich unterscheidet `load_arbitrary_data` `NotFound` vs.
  `AuthenticationFailed` → Existenz-Orakel für `generic_*.enc`-Muster in erreichbaren
  Pfaden.
- **Betroffene Invariante:** Speicher-Grenzdisziplin: Storage-Operationen dürfen nie
  außerhalb des Wallet-Verzeichnisses wirken (Vertraulichkeit anderer Dateien des
  Prozesses/Users; Defense-in-Depth gegen Host-Layer-Injection).
- **Zielcode:** `src/storage/file_storage.rs` :: `get_item_hash` (~1076–1083),
  `load_arbitrary_data` (~866–888, fehlende Sanitization analog save ~838–842)
- **Geplanter Fail-First-Test:** In Tempdir: `storage.get_item_hash("/etc/hostname")`
  (bzw. `../../<bekannte Datei>` außerhalb der Basis) und Vergleich gegen selbst
  berechneten SHA3 der Zieldatei. Soll-Assertion: `Err(StorageError::Generic("Invalid
  item name"))` gemäß der existierenden save-Konvention; unpatched liefert `Ok(<Hash
  der Fremd-datei>)` → FAIL. Zweiter Assert: `load_arbitrary_data("../x")` muss
  denselben Reject wie save liefern (Konsistenz-Assert).
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Nein — die interne Nutzung
  mit gescannten Namen bleibt vom Fix unberührt; die Validierung existiert in save
  bereits als etablierte Projektkonvention. Kein Offline-Resilienz-Feature hängt an
  Traversal-Fähigkeit.
- **Priorität:** MEDIUM

---

## WH3-05-507 — N6: Rohe voucher_id/t_id als Dateinamen im Archiv (Defense-in-Depth-Rest)

- **Vermutung:** `archive_voucher` bildet Pfade direkt aus Domänen-IDs:
  `archive_directory.join(&voucher.voucher_id)` + `format!("{}.json", last_tx.t_id)`
  (file_archive.rs ~340–357), `get_archived_voucher(voucher_id)` ebenso (~363). Im
  regulären Fluss ist das durch Chain-Validierung abgedeckt: `verify_transaction_basics`
  erzwingt Base58-Format der `voucher_id` via prev_hash-Bindung
  (voucher_validation/chain.rs ~485–492; Base58 kennt weder `/` `\` noch `.`), t_ids
  sind Hash-Ausgaben. ABER: `FileVoucherArchive` ist öffentliche API (lib.rs:37), und
  ProofStore/gossip-Importe enthalten angreiferkontrollierte
  `conflicting_transactions`-Chains, die NIEMALS die volle Chain-Validierung durchlaufen
  (Modul-01-Pfad); ein Host, der solche Strukturen (oder importierte Fremd-Voucher vor
  Validierung) archiviert, erhält einen CWE-22-Write (create_dir_all außerhalb der Basis!)
  bzw. ein Read-/Directory-Listing-Orakel via `get_archived_voucher("../../x")`. Zudem
  fehlt eine Length-Cap (Dateisystem-Limit-DoS durch riesige IDs).
- **Betroffene Invariante:** Speicher-Grenzdisziplin (wie WH3-05-506): Archiv-Schreib-
  und Leseoperationen bleiben strikt innerhalb des Archiv-Basisverzeichnisses,
  unabhängig davon, welche Strukturen der Host übergibt.
- **Zielcode:** `src/archive/file_archive.rs` :: `archive_voucher` (~340–343, 355),
  `get_archived_voucher` (~363), `find_transaction_by_id` (~403–410)
- **Geplanter Fail-First-Test:** `FileVoucherArchive::new_secure(base,…)`; Voucher mit
  `voucher_id = "../escape_test"` (und t_id mit `/`) direkt archivieren. Soll-Assertion:
  `Err(ArchiveError::Generic("invalid identifier"))`; danach Assert, dass `base/../`
  kein Verzeichnis `escape_test` enthält. Unpatched: `Ok(())` + Verzeichnis outside base
  → FAIL. (Leseseite: `get_archived_voucher("../other")` muss ebenfalls rejecten.)
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Die
  Base58-Garantie der Validierungskette ist real, aber implizit und nicht an der
  Archiv-Grenzfläche verankert — klassisches Defense-in-Depth-Rest; kein Funktionsverlust
  durch sanitizing. Niedrige Priorität, da Ausnutzung einen nicht-standardmäßigen
  Host-Aufruf erfordert.
- **Priorität:** LOW

---

## Abdeckungs-Matrix Wave 3

| Hypothese | Anlass (Wave-3-Fokus) | Neu/Rest |
|---|---|---|
| WH3-05-501 | store_binding_hash über neue Felder? → unauthentifiziert/strippbar | ✔ novel (SA05-04-Umgehung) |
| WH3-05-502 | V3-Deserialisierung alter States / serde-Defaults | ✔ novel (Persistenz-Kompatibilität) |
| WH3-05-503 | SA05-04-Fix-Nebenwirkung: Torn-Write-Brick ohne Recovery | ✔ novel (Regression) |
| WH3-05-504 | AEAD-Grenzen W5 (Löschen/Trunkieren/Replay ganzer Records) | ✔ novel |
| WH3-05-505 | N7 Empty-Password-Guard `new_secure(path,"")` | ✔ Restgap N7 verifiziert |
| WH3-05-506 | N5 unsanitized `get_item_hash`/`load_arbitrary_data` | ✔ Restgap N5 verifiziert |
| WH3-05-507 | N6 Roh-ID-Dateinamen Archiv | ✔ Restgap N6 verifiziert (eingeschränkt durch Base58-Kettenvalidierung) |

Nicht erneut nummeriert (Status siehe Abschnittsanfang): H-05-03 (Lock-TOCTOU, weiterhin
offen), H-05-05/H-05-06 (KDF-Politik, CLI-Keys, weiterhin offen), K2-Downgrade (SA05-05-Fix
verifiziert; Restaspekt in WH3-05-504 aufgegangen), Debug/Display-Sweep (negativ).

### Phase B (A-05, Pipeline) — Testzuordnung

| WH3-ID | Test (tests/security_audit_module_05_storage.rs) | Erwartung unpatched | Status nach Fix (Wave 3) |
|---|---|---|---|
| WH3-05-501 | `sa05_07_store_binding_hash_must_be_authenticated_and_mandatory` (HMSEC-SA05-07) | FAIL | **FIXED/GREEN** — keyed (file-key) + mandatory binding; Absenz ⇒ StateConflict |
| WH3-05-502 | `sa05_08_legacy_v2_fingerprint_data_must_not_be_silently_degraded` (HMSEC-SA05-08) | FAIL | **FIXED/GREEN** — harte Schema-Gates (InvalidFormat) für Fingerprint-Stores (`u`/`blinded_id`) UND Voucher-Store (`trap_data`: `u`/`blinded_id`/`proof`); Marker dokumentiert für Wildcard |
| WH3-05-504 | `sa05_09_archive_record_deletion_and_relocation_must_be_detectable` (HMSEC-SA05-09) | FAIL | **FIXED/GREEN** — Location-Bindung in `read_record` + versiegeltes per-voucher Manifest |
| WH3-05-505 | `sa05_10_archive_construction_with_empty_password_must_be_rejected` (HMSEC-SA05-10) | FAIL | **FIXED/GREEN** — Seal-time-Guard gegen Empty-Password/All-Zero-Key in `seal_record` |
| WH3-05-506 | `sa05_11_arbitrary_data_read_paths_must_enforce_name_sanitization` (HMSEC-SA05-11) | FAIL | **FIXED/GREEN** — symmetrische Sanitization auf `load_arbitrary_data` + komponentenbasierte Validierung in `get_item_hash` (erlaubt weiterhin `events/*.json.enc`) |

Fix-Report: `docs/security/ai-audits/reports/05_storage_report.md`, Wave-3-Addendum.
SA05-08-Shape-Entscheidung für Wildcard-Agent: **hart ablehnen** (StorageError::
InvalidFormat mit matchbaren Markern „legacy V2 fingerprint schema" bzw. „legacy
V2 trap_data schema"); Wallet-Seite kann diese Fehler für Quarantäne-/Migrations-
Flows abfangen. Rest-Case der wildcard_06-Fixture (leerer typisierter TrapData-
Residue ohne Legacy-Keys on disk) verbleibt laut deren Scope-Note beim Wallet-
seitigen Chain-Validation-Gate (lifecycle.rs).

Backlog (bewusst NICHT getestet, report-only): **WH3-05-503** (Torn-Write-Fenster des
SA05-04-Fix → StateConflict-Brick ohne Recovery-Pfad; deterministischer Test bräuchte
Fault-Injection/einen Recovery-API-Soll, der noch nicht spezifiziert ist) und
**WH3-05-507** (Rohe voucher_id/t_id als Archiv-Dateinamen; Defense-in-Depth-Rest hinter
der Base58-Kettenvalidierung, Ausnutzung nur via nicht-standardkonforme Host-Aufrufe).
