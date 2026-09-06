# Wave 4 Hypotheses — Module 03: Standards & CEL Policy Engine

> Agent: A-03 (Wave 4, research-only) · Stand: 2026-08-26 · Branch: live
> Scope: `src/services/dynamic_policy_engine.rs`, `src/services/standard_manager.rs`,
> `src/models/voucher_standard_definition.rs`, `src/app_service/standard_container_handler.rs`,
> standard.toml parsing/verification, TOML zones, CEL evaluator.
> Out of scope (per assignment): sa06_07 spec flaw, audit_02_11, SA04-08, Seal-History.
> Baseline dedupe sources fully read: `03_cel_report.md` (M03-001..010),
> `STATUS.md`, `temp/security-triage-report.md` (K1-K4/W1-W6/N1-N11).

---

## WH4-03-101: CEL Message-Literals (`T{...}`) erreichen Interpreter-`todo!()` — Prozessabbruch während Validierung

- Severity: CRITICAL | CWE: CWE-248 (Uncaught Exception) / CWE-636 (Not Fail-Closed)
- Target: `src/services/dynamic_policy_engine.rs:597` (Pre-Check-Catch-all `_ => Ok(JsonValue::Null)`); third-party abort in `cel-interpreter-0.10.0/src/objects.rs:706` (`Expr::Struct(_) => todo!("Support structs!")`); Parser-Produktion `cel-parser-0.10.1/src/parser.rs:798-826` (`visit_CreateMessage` → `Expr::Struct`)
- Status-Vermutung: KNOWN-OPEN-DEEPDIVE (als "Residual risk … candidate for a future wave" explizit im Wave-3-Bericht AUDIT-M03-008 vertagt; hier vertieft und Angriffspfad verifiziert)
- Threat Model: CEL-Regeln stammen aus signierten `[immutable]`-Zonen, sind aber laut etablierter Triage-Linie (M03-005/007) angreiferbeeinflussbar (kompromittierter Issuer, socially engineered `.standard`). Der Ausdruck `Foo{a: 'x'}.a == 'x'` passiert Budget-Scan (`{}` zählt Tiefe 1), `Program::compile` (parst nur, resolviert nicht) und den projektseitigen AST-Pre-Check (Catch-all gibt `Ok(Null)` zurück, Kinder werden nicht geprüft). Erst `program.execute()` löst den Knoten auf und trifft im Interpreter auf ein uncatchable `todo!()` → SIGABRT des gesamten Wallet-Prozesses während routinemäßiger Voucher-Validierung (`get_failing_custom_rules` → `evaluate_rule`).
- Broken Invariant: Audit-Invariante #2 (Fail-Closed): Jeder nicht auswertbare/kompilierbare Ausdruck MUSS zu `Err(...)` führen, niemals zum Prozessabbruch. Ebenfalls verletzt: Determinismus-Invariante #1 (kontrollierter Fehler statt Abort).
- Fail-First-Test-Skizze:
  ```rust
  // tests/security_audit_module_03_cel.rs — Muster wie finding07 (catch_unwind-Harness)
  let result = std::panic::catch_unwind(|| {
      DynamicPolicyEngine::evaluate_rule(
          "human_money_core{a: 'x'}.a == 'x'", // CreateMessage -> Expr::Struct
          &serde_json::json!({}), None)
  });
  // SOLL: Ok(Err(PolicyEngineError::_)) — d.h. catch_unwind fängt KEINEN Abort,
  // evaluate_rule liefert kontrolliert Err (fail-closed).
  // IST (unpatched): Prozess-SIGABRT in objects.rs:706 ("Support structs!") —
  // nextest meldet SIGABRT statt Test-FAIL (identisch zur finding07-Signatur).
  ```
  Fix-Richtung: explizite `Expr::Struct`-Arm im Pre-Check → `Err(EvaluationError("struct/message literals are not supported"))` vor dem Interpreter (Spiegel von M03-007); defense-in-depth-Hinweis: `Expr::Unspecified => panic!("Can't evaluate Unspecified Expr")` (objects.rs:707) ist derselben Klasse zuzuordnen (aktuell vermutlich unerreichbar, da Parser-Fehlerpfade `report_error` + `Err` setzen).
- Dedupe-Check: M03-007/008 deckten ausschließlich Comprehension-Ranges (List/Map/non-container) ab; der Wave-3-Bericht dokumentiert `Expr::Struct` ausdrücklich als NICHT behandeltes Residuum ("out of wave scope"). W2 des Triage-Reports nennt generisch den Catch-all-Arm, ohne das Struct-todo! konkret zu benennen. Kein Fix existiert; die Verifikation (Parser-Produktion + Pre-Check-Miss + exakte Interpreter-Zeile) ist neu.

---

## WH4-03-102: Issuer-Identität wird nirgends gepinnt — Angreifer-re-signierte Mutable Zone (inkl. konsensrelevantem `round_up_validity_to`) passiert das Usage-Time-Gate

- Severity: HIGH | CWE: CWE-347 (Improper Verification of Cryptographic Signature / self-consistent key) / CWE-345 (Insufficient Verification of Data Authenticity)
- Target: `src/services/standard_manager.rs:133` (`get_pubkey_from_user_id(&signature_block.issuer_id)` — Key stammt AUS DER DATEI; Import-Zwilling Z.60); `src/services/voucher_validation/identity.rs:11-25` (uuid/hash-Anker selbst-konsistent gegen dieselbe Datei); konsensrelevanter Mutable-Leak: `src/services/voucher_validation/identity.rs:167-169` (`round_up_validity_to` lockert die Max-Validity-Grenze)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: Lokaler Angreifer mit FS-Schreibrecht (Malware, Cloud-Sync-Folder-Swap — genau die Bedrohungsklasse, die AUDIT-M03-010 ausdrücklich für in-scope erklärt hat) ersetzt `voucher_standards/<uuid>/standard.toml` komplett durch eine Datei mit IDENTISCHER `[immutable]`-Zone (gleicher uuid ⇒ Identity-Check ✓, gleicher Hash ⇒ Hash-Check ✓) und eigener `[mutable]`-Zone plus EIGENER Signatur unter eigenem `did:key`. Beide Verifikationen (`verify_and_parse_standard`, `verify_standard_signature`) extrahieren den Public Key aus der Datei selbst → selbst-konsistent gültig → Gate akzeptiert. Impact zweistufig: (1) Phishing-Metadaten (issuer_name/homepage/i18n-Vertragstexte), (2) schwerwiegender: `mutable.app_config.round_up_validity_to` fließt in `verify_validity_duration` ein und rundet die OBERE Validitätsgrenze nach oben — ein Re-Sign mit `"P100Y"` lässt Voucher passieren, die die issuer-intendierte Max-Laufzeit massiv überschreiten (Konsenslockerung über die nominell "nur-UI"-Zone).
- Broken Invariant: "Immutability & Integrity": Eine installierte Standard-Definition kann nicht ausgetauscht werden, ohne dass dies an der Integritätskette/hartnäckigen Verankerung sichtbar wird. Tatsächlich ist der Standards-Ordner der einzige ungeschützte Store (Klartext-TOML außerhalb WalletSeal/Integrity-Record/AEAD-Wallet-Stores); M03-004 schützt nur den Import-Moment (Raw-String-Vergleich), M03-010 nur gegen Stale-/Strip-Signaturen, nicht gegen Re-Signs.
- Fail-First-Test-Skizze:
  ```rust
  // tests/security_audit_module_03_cel.rs oder _06
  // 1. Legitimes Standard U importieren (AppService::import_voucher_standard, echte Sig).
  // 2. Attacker: def klonen, immutable UNVERÄNDERT lassen;
  //    mutable.metadata.issuer_name = "Phish Community";
  //    mutable.app_config.round_up_validity_to = Some("P100Y");
  //    signature_block = sign(fresh_ed25519_key, canonical(def_without_sig));
  //    issuer_id = did:key:fresh;  Datei über <dir>/<U>/standard.toml schreiben.
  // 3. Production-Pfad:
  let (def, _) = verify_and_parse_standard(&swapped_toml)?; // Ok — self-consistent
  assert!(validate_voucher_against_standard(&voucher_bound_to_U, &def).is_err());
  // IST (unpatched): Ok(()) — fremdsignierte Definition inkl. gelockertem
  // Max-Validity-Window wird akzeptiert. Ein überlange-Validität-Voucher, der
  // zuvor an verify_validity_duration scheitert, passiert das Gate.
  ```
  Fix-Richtung: Trust-on-first-use-Pinning — bei Import issuer_id (oder Hash der Canonical-Bytes) in einem geschützten Sidecar/Integrity-Record verankern und `verify_standard_signature` gegen den Pin prüfen (analog `store_binding_hash`-Pattern aus SA05-07); alternativ Standards-Ordner in die Storage Integrity aufnehmen.
- Dedupe-Check: M03-010 behandelt exclusively Stale-Signature/Strip-Varianten (Report: "mutable-zone rewrites **with or without retained stale signature** -> InvalidSignature" — stimmt nur, solange NICHT neu signiert wird); M03-004/009 wirken nur am Import-Moment. Kein Bericht, kein STATUS.md-Eintrag, keine W/N-Position des Triage-Reports betrachtet Re-Signing mit angreiferkontrolliertem Key oder die Konsensrolle von `round_up_validity_to`. Neu.

---

## WH4-03-103: String-Index-Dual-Evaluator-Divergenz — Interpreter koalesziert Byte-Index-OOB/Misaligned zu `Null`, Pre-Check modelliert Char-Semantik und fabriziert NUL

- Severity: MEDIUM | CWE: CWE-176/178 (Encoding/Comparison-Divergenz) / CWE-636 (Not Fail-Closed)
- Target: `src/services/dynamic_policy_engine.rs:293-328` (String-Arm von `_[_]`: Bound-Check `idx < s.len()` in BYTES Z.319, Zugriff `chars().nth(idx)` in CHARS Z.320, Fabrikation `unwrap_or('\0')` Z.320); Interpreter-Realität: `cel-interpreter-0.10.0/src/objects.rs:545-548` (`str.get(idx..idx+1)` → `None => Ok(Value::Null)`)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: Regeln positionieren häufig auf String-Feldern (`unit[1] != 'E'`, Länder-/Währungscode-Prüfungen). Das Voucher-State ist angreiferkontrolliert. Zwei verifizierte Divergenzen: (a) Der Interpreter indiziert per BYTE-SLICE und liefert bei OOB **und** bei in einen Multibyte-Sequenz fallendem Index `Value::Null` statt Fehler; der Pre-Check rechnet mit CHAR-Indizes und gibt für Byte-in-range/Char-out-of-range ein synthetisches `"\u{0000}"` zurück. Bei negierten Prädikaten (`Voucher.unit[1] != 'X'`) genügt es, das Feld mit einem Multibyte-Präfix zu versehen: Byte 1 ist dann Continuation-Byte → Interpreter-`Null != 'X'` → `true` — die signierte Positionsregel wird vacuously bypassed, obwohl der zweite CHARACTER sehr wohl 'X' ist. (b) Der Pre-Check akzeptiert Indizes bis Byte-Länge und erzeugt NUL-Zeichen, die es im Feld gar nicht gibt — jede Gleichheits-Regel gegen `'\u{0000}'` wird damit zur Lotterie zwischen den Evaluatoren.
- Broken Invariant: Deterministische, evaluator-unabhängige Semantik (#1) und Fail-Closed für fehlende/undefinierte Zugriffe (#2, Geist von HMC-SEC-03-01/M03-001): Der M03-001-Fix schloss NULL-Coalescing nur für Map/List-Bracket-Access; der STRING-Arm wurde nie an die tatsächliche Byte-Slice+Null-Coalescing-Semantik des Interpreters angeglichen.
- Fail-First-Test-Skizze:
  ```rust
  // State: {"unit": "\u{C4}EX"} — 'Ä' (2 Bytes) + "EX"; CHAR[1] == 'E', BYTE[1] == Continuation.
  let state = serde_json::json!({"unit": "\u{00C4}EX"});
  // Negierte Positionsregel des signierten Standards:
  let verdict = DynamicPolicyEngine::evaluate_rule("Voucher.unit[1] != 'E'", &state, None);
  // SOLL (Fail-closed/Determinismus): Err(...) — String-Indexing außerhalb
  // ASCII/exakt-modellierter Semantik wird abgelehnt (oder char-genau geprüft => Ok(false)).
  // IST (unpatched): Ok(true) — Interpreter slice't BYTE 1 (Continuation) ->
  // str.get() -> None -> Value::Null; Null != 'E' => true. Bypass.
  // Begleit-Control: "Voucher.unit[0] == '\u{00C4}'" muss Ok(true) bleiben (ASCII-[0]-Pfad intakt).
  ```
  Fix-Richtung: Im Pre-Check-String-Arm Byte-Slice-Semantik exakt nachbilden UND jeden `None`-Fall (OOB **und** non-char-boundary) zu `Err(EvaluationError)` machen statt Null/NUL zu fabrizieren — fail-closed wie der Map/List-Arm; alternativ non-ASCII-Indexierung generell ablehnen.
- Dedupe-Check: M03-001 (bracket NULL-coalescing) behandelte fehlende Map-Keys/OOB-Listenindizes; der String-Arm mit seiner Byte/Char-Schere und `unwrap_or('\0')` wird in keinem Report, nicht in STATUS.md und nicht in W2 erwähnt (W2 nennt nur size()-Bytes-vs-Chars als Beispiel-Divergenz — andere Funktion, anderer Pfad). Neu.

---

## Betrachtet und verworfen (keine Kandidaten)

- **Arithmetik-Operatoren (`_+_ _-_ _*_ _/_ _%_`) im Catch-all:** cel-interpreter 0.10.0 wirft typisierte Errors (`Overflow`, `DivisionByZero` objects.rs/lib.rs:99-104) → fail-closed; Float-NaN-Fälle landen wegen Ordering-Guard (M03-003) im `Err`. Kein Befund.
- **Leeres `t_type` umgeht Whitelist** (`rules.rs:11` `!tx.t_type.is_empty()`): Chain-Conservation (chain.rs:395) greift typunabhängig, Produktionspfade setzen `t_type` immer; Restrisiko rein hygienisch, nicht beweisbar exploitable → verworfen (LIKELY-FALSE-POSITIVE).
- **`check_decimals`-UInt> i64::MAX-Plätze:** beide Evaluatoren range-checken zuerst → false/fail-closed. Kein Befund.
- **O(n²)-`loop_env`-Clone:** durch M03-005-Budget (1000 Iterationen) gedeckelt; bereits als W2(d) known-open dokumentiert — kein neuer Erkenntniswert.
- **Import-Konfliktvergleich per Raw-String** (`standard_container_handler.rs:182`): semantisch identische TOMLs werden abgelehnt → Availability-Ärgernis, fail-closed. Kein Befund.
