# Security-Hypothesen — Modul 04: Transaktionslogik & State-Integrity (Agent A-04)

> Scope: `src/services/bundle_processor.rs`, `secure_container_manager.rs`, `integrity_manager.rs`,
> `decimal_utils.rs`, `models/voucher.rs`, `models/secure_container.rs` + Downstream-Lifecycle
> (`src/wallet/transaction_handler.rs`, `src/services/voucher_manager/transaction.rs`,
> `src/services/voucher_validation/chain.rs`).
>
> Bereits abgedeckt (NICHT erneut vorgeschlagen): SA04-01 (Amount-Summen-Overflow im Receive-Pfad),
> SA04-02 (Split-Overflow in Chain-Validation), SA04-03 (Ghost-Archive bei abgebrochenem Multi-Transfer).
>
> Recherche-Notiz zu Panic-Hazards: `CompressedEdwardsY::from_slice` liefert in curve25519-dalek
> 4.1.3 ein `Result` (kein Index-Panic); alle Aufrufer mappen den Fehler. `crypto_symmetric`
> prüft Nonce/Tag-Längen vor `Nonce::from_slice`/`Tag::from_slice`. `decode_base64`, `bs58::decode`,
> `Signature::from_slice` sind durchgängig Result-basiert. Manuell konnte daher KEIN konkreter,
> erreichbarer Panic in den Dekodern nachgewiesen werden — Hypothese H-04-08 fordert deshalb einen
> systematischen Fuzz-Invariantentest (kandidiert für FALSE POSITIVE).

---

## H-04-01 — Partial-Commit-Desync beim Empfang von Multi-Voucher-Bundles
- **Status Phase B:** CONFIRMED+FIXED — 2-Voucher-Bundle mit unbekannter Standard-UUID im zweiten Mitglied hinterließ 1 Phantom-Voucher im Store (Test `sa04_04_...` FAIL auf unpatched); Triage `[CONFIRMED VULNERABILITY]`; Fix: Snapshot-and-Rollback-Wrapper um `process_encrypted_transaction_bundle` (Temp-Wallet-Pattern wie Sendepfad) in transaction_handler.rs; Finding HMSEC-SA04-04.
- **Vermutung:** `process_encrypted_transaction_bundle` committet Voucher inkrementell pro
  Schleifeniteration: Für jedes Bundle-Mitglied laufen Standard-Lookup, Strict-Ingestion des
  Privacy-Guards und Validierung, und DANACH wird `add_voucher_instance(...)` aufgerufen. Schlägt
  ein LATERES Mitglied fehl (unbekannte Standard-UUID → `Generic`-Err bei Zeile ~215; Guard-
  Entschlüsselungsfehler bei ~241; `validate_voucher_against_standard` bei ~222), gibt die Funktion
  `Err` zurück, aber die bereits verarbeiteten Voucher bleiben dauerhaft im `voucher_store`. Gleichzeitig
  werden `bundle_meta_store.history` (Insert erst ~478), `TransferReceived`-Events (~458) und
  `scan_and_rebuild_fingerprints()` (~492) nie ausgeführt. Ergebnis: Der Store enthält Phantom-Voucher
  ohne Bundle-History-Eintrag — der Layer-1-Replay-Schutz (bundle_id) ist für diese Ingestion nicht
  registriert, Events fehlen gegenüber dem Besitzstand und der Caller hält die Operation für vollständig
  fehlgeschlagen. Das ist genau die „Teilschreib-Desync"-Klasse jenseits von SA04-03 (welches nur die
  Sender-/Archive-Richtung prüft).
- **Betroffene Invariante:** State-Integrity/Atomizität: Ein mit `Err` abgebrochener Empfang darf
  KEINE Spuren in `voucher_store` hinterlassen (All-or-Nothing wie `execute_multi_transfer_and_bundle`
  mit Temp-Wallet-Commit).
- **Zielcode:** src/wallet/transaction_handler.rs :: process_encrypted_transaction_bundle (~361 `add_voucher_instance` im Loop; Fehlerquellen ~215/~241/~222)
- **Geplanter Fail-First-Test:** Gültiges 2-Voucher-Bundle bauen, wobei Voucher B eine unbekannte
  Standard-UUID trägt; dann:
  `let before = wallet.voucher_store.vouchers.len(); let res = wallet.process_encrypted_transaction_bundle(...); assert!(res.is_err()); assert_eq!(wallet.voucher_store.vouchers.len(), before, "partial commit detected");`
  Auf unpatched Code enthält der Store Voucher A → Assertion schlägt fehl.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Schwerlich: Die Funktion
  dokumentiert keinen Best-Effort-Empfang, und der Layer-1-Replay-Schutz setzt zwingend voraus, dass
  Store-Besitz und Bundle-History konsistent sind. Ein bewusstes „accept prefix on error" wäre im
  Widerspruch zur Transaktionsarchitektur des Sendepfads (Temp-Wallet). Falls Triage ergibt, dass
  Teilannahme gewollt ist, müsste mindestens der History-Insert atomar mitgezogen werden.
- **Priorität:** CRITICAL

---

## H-04-02 — Post-Commit-Archivierung: Wallet-State committet VOR Archive-Writes (inverse SA04-03-Lücke)
- **Vorbemerkung:** SA04-03 deckt „abgebrochene Operation schreibt Ghost-Einträge ins Archiv" (pre-commit
  Archivierung). Hier liegt der umgekehrte Defekt: Nach dem Remediation-Commit archiviert
  `execute_multi_transfer_and_bundle` zwar erst NACH `*self = temp_wallet` (~976), aber der Archiv-Loop
  (~983–999) propagiert Fehler per `?`. Fällt `archive_backend.archive_voucher` mitten im Loop aus
  (Festplatte voll, Permission-Fehler am 2. von N Vouchern), ist der Wallet-State bereits unwiderruflich
  committet, die Operation meldet dem Caller jedoch `Err` („fehlgeschlagen") und das Forensic-Archiv
  enthält nur einen TEIL der übertragenen Zustände. Wallet ↔ Archiv sind permanent desynchron;
  Double-Spend-Pfadenanalyse (Union über Archivpfade) arbeitet fortan mit Löchern.
- **Betroffene Invariante:** Konsistenz zwischen committed Wallet-State, VoucherStore und Forensic-Archive
  („jede je gesehene State ist archiviert"); Err-Semantik darf nicht lügen (State hat sich trotzdem geändert).
- **Zielcode:** src/wallet/transaction_handler.rs :: execute_multi_transfer_and_bundle (~976 Commit, ~983–999 Archive-Loop mit `?`)
- **Geplanter Fail-First-Test:** Spy-Archiv, das beim k-ten `archive_voucher` (k ≥ 2 Quellen) `Err(ArchiveError::...)` zurückgibt; 2-Quellen-Transfer ausführen:
  `let res = wallet.execute_multi_transfer_and_bundle(..., Some(&failing_archive)); if res.is_err() { /* entweder Commit rückgängig ODER Err darf nicht propagieren */ }`
  Secure Invariant: Nach Rückkehr mit `Err` MUSS der Wallet-State unverändert sein (oder alternativ das
  Ergebnis muss `Ok` mit Degraded-Archiv-Flag sein — beides ist heute falsch). Aktuell: State committed,
  `Err` zurückgegeben → Test schlägt fehl und beweist den Desync.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Die Kommentare (HMC-SEC-04-03)
  behaupten explizit Atomizität via Post-Commit-Archivierung — der Teilschreib-Fall ist offensichtlich
  nicht bedacht, also eher Design-Lücke als Design-Intent. Mögliche Remediation ohne Rollback:
  Journal-and-replay oder Best-Effort-Dokumentation + Retry-Queue; Triage entscheidet.
- **Priorität:** HIGH

---

## H-04-03 — Split/Change-Anchor-Overlap: Chain-Validator akzeptiert identische Anker
- **Status Phase B:** CONFIRMED+FIXED — self-consistente init(100)→split(60/40)-Kette mit `receiver_ephemeral_pub_hash == change_ephemeral_pub_hash` lieferte `Ok(())` (Test `sa04_05_...` FAIL auf unpatched); Triage `[CONFIRMED VULNERABILITY]`; Fix: Anchor-Separationsprüfung im Split-Zweig von `verify_transactions` (chain.rs); Finding HMSEC-SA04-05.
- **Vermutung:** `verify_transactions` (chain.rs) prüft P2PKH-Anker-Matching, Conservation, Precision und
  Zeitordnung — aber NIRGENDWO, dass bei einem `t_type == "split"` die beiden Ausgabe-Anker
  `receiver_ephemeral_pub_hash` und `change_ephemeral_pub_hash` verschieden sind. Ein crafteter Split mit
  `receiver_ephemeral_pub_hash == change_ephemeral_pub_hash == H(X)` ist self-consistent signierbar und
  passiert die komplette Validation. Damit kontrolliert EIN Schlüssel X beide Branches: Der Issuer kennt X
  (er hat den Change-Seed deterministisch abgeleitet bzw. den Recipient-Seed gewählt) und kann den
  Empfänger-Zweig vor dem ehrlichen Empfänger spenden → Empfänger wird als Double-Spender framiert;
  zudem brechen identische Anker die Unlinkability zwischen Transfer- und Change-Fingerprint
  (Trap-Korrelation). Auch degenerate leere Strings als Anker werden nicht abgelehnt.
- **Betroffene Invariante:** Split-Anchor Separation: Key_Receiver ≠ Key_Change (dokumentierte
  Kern-Invariante des Audits 04); kein Output-Pair darf unter einer einzigen Schlüsselkontrolle vereinbar sein.
- **Zielcode:** src/services/voucher_validation/chain.rs :: verify_transactions (~117–479, fehlende
  Anchor-Gleichheitsprüfung im Split-Zweig ~441–472); Referenz Erzeugung: src/services/voucher_manager/transaction.rs :: create_transaction (~157–186, dort korrekt getrennt: random recipient seed vs. HKDF change seed)
- **Geplanter Fail-First-Test:** Self-consistente Kette init(100) → split(amount=60, remaining=40) mit
  `receiver_ephemeral_pub_hash == change_ephemeral_pub_hash` craften (alle Signaturen/Hashes wie in
  `craft_voucher_with_overflowing_split` sauber berechnen):
  `assert!(verify_transactions(&voucher, &standard).is_err(), "anchor overlap must be rejected");`
  Auf unpatched Code liefert die Funktion `Ok(())` → Test schlägt fehl.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Ein ehrlicher Use-Case für
  gleiche Anker existiert nicht: Der Change gehört dem Sender, der Transfer-Zweig dem Empfänger —
  Identität beider Schlüssel würde bedeuten, dass Sender und Empfänger derselbe Schlüsselinhaber sind
  (Self-Transfer über Split ist via `sender_id == recipient_id`-Verbot für öffentliche Modis ohnehin
  unerwünscht; Stealth-Modi erlauben es semantisch nicht). Wahrscheinlich schlicht nie implementiert.
- **Priorität:** HIGH

---

## H-04-04 — Mutation-Gap: End-to-End-Acceptance ohne wirksame Signaturprüfung (verify_container_signature / verify_bundle_signature)
- **Status Phase B:** CONFIRMED-PENDING→erledigt als MUTANT-KILL (Coverage-Fix, kein Src-Fix nötig): Test `sa04_06_...` führt (a) gefälschte `sender_signature` + recomputed bundle_id in signaturlosem Privacy-Container und (b) authentischen Alice-Payload im Fremd-Envelope (Mallory-signiert) durch den öffentlichen Pfad `open_and_verify_bundle` → beide mit typisierten Errors (`InvalidBundleSignature`/`InvalidContainerSignature`) abgelehnt; PASS auf clean code = beide survive-nden Mutanten getötet; Finding HMSEC-SA04-06.
- **Vermutung:** Laut `temp/uncovered_code.md` (Zeilen ~104/117 der älteren Revision) überleben
  Security-Bypass-Mutanten von `verify_container_signature` und `verify_bundle_signature` (Body → `Ok(())`)
  die gesamte Testsuite. Die vorhandenen Unit-Tests rufen die Funktionen direkt auf, aber KEIN Test
  führt ein manipuliertes Bundle durch den öffentlichen Pfad `open_and_verify_bundle`. Kritischer
  Detail: Da `bundle_id` laut HMC-SEC-06-01 die Felder `bundle_id`/`sender_signature` EXKLUDIERT, bleibt
  die bundle_id-Bindung intakt, wenn man AUSSCHLIESSLICH `sender_signature` durch Zufallsbytes ersetzt —
  die innere Signaturprüfung ist dann die EINZIGE Verteidigungslinie gegen signature-stripping/-swap.
  Ebenso reicht das Leeren von `container.signature` (Privacy-Mode erlaubt leere Envelope-Signatur),
  sodass ohne `verify_bundle_signature` jeder, der einen gültigen `(container.i, bundle)`-Schnappschuss
  besitzt, Inhalte beliebig rekombinieren könnte, wenn die Mutanten Realität wären. Ohne Kill-Tests ist
  unklar, ob Refactorings diese Guards still beschädigen können.
- **Betroffene Invariante:** Authentizität/Integrität: Kein Bundle ohne gültige Ed25519-Signatur des
  deklarierten `sender_id` wird akzeptiert (CWE-347).
- **Zielcode:** src/services/bundle_processor.rs :: open_and_verify_bundle / verify_container_signature / verify_bundle_signature (~161–201)
- **Geplanter Fail-First-Test (Mutanten-Kill):**
  (a) Volles legitimes Bundle+Container erzeugen, DANN `bundle.sender_signature` = bs58(Zufall-64B)
  setzen, neu versiegeln (container.i korrekt neu berechnen, Envelope-Signatur leer lassen):
  `assert!(matches!(open_and_verify_bundle(&identity, &bytes), Err(VoucherCoreError::Validation(ValidationError::InvalidBundleSignature))));`
  (b) Gegenprobe: Container mit manipuliertem `signature`-Feld gegen fremden Sender → muss mit
  `InvalidContainerSignature` abgelehnt werden.
  Beide Tests killen die survive-nden Mutanten (mit gelöschtem Guard flippen sie zu `Ok` → assert failt).
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Nein — hier geht es nicht um Logikänderung,
  sondern um fehlende Regression-Coverage für dokumentierte Guards; Verhalten ist bereits korrekt.
  Erwartetes Phase-B-Ergebnis: Test PASS auf clean code (= Mutanten-Kill, kein Fix nötig).
- **Priorität:** CRITICAL (Coverage eines Security-Bypass-Mutants)

---

## H-04-05 — Mutation-Gap: Status-Gate-Negation in _execute_single_transfer (Spend aus Quarantäne/Archiv)
- **Vermutung:** Der Negation-Bypass-Mutant an `if !matches!(instance.status, VoucherStatus::Active)`
  (uncovered_code.md ~471, heute ~715) überlebt: Es gibt keinen Test, der gezielt versucht, einen
  NICHT-aktiven Voucher (Quarantined/Archived) zu spenden und `VoucherCoreError::VoucherNotActive`
  erwartet. Das Gate ist die letzte Sperre gegen Zombie-Spending: Ein in Quarantäne befindlicher
  Konfliktverlierer darf niemals als Transferquelle dienen — auch nicht indirekt über
  `execute_multi_transfer_and_bundle`, dessen Instanz-Lookup (~899) nur Existenz, nicht Status prüft.
- **Betroffene Invariante:** Nur `VoucherStatus::Active`-Instanzen sind spendebar; Quarantäne ist
  wertmäßig eingefroren bis zur Konfliktauflösung.
- **Zielcode:** src/wallet/transaction_handler.rs :: _execute_single_transfer (~710–717 Status-Gate)
- **Geplanter Fail-First-Test:** Wallet mit Voucher A; A in `Quarantined{..}` versetzen (über öffentlichen
  Konflikt-Pfad bzw. bestehende test_utils-Fixtures; falls nicht erreichbar, Store-Setup analog
  `add_voucher_to_wallet` mit Status-Override); dann:
  `let res = wallet.execute_multi_transfer_and_bundle(&id_a, "1"); assert!(matches!(res, Err(VoucherCoreError::VoucherNotActive(_)))); assert!(wallet.voucher_store.vouchers.contains_key(&id_a));`
  Mit negiertem Gate (Mutant) würde der Spend durchlaufen → assert failt.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Nein; Quarantine-Freezing ist Kern des
  Fraud-Detection-Designs (AGENTS.md). Coverage-Fix, kein Logikfix erwartet.
- **Priorität:** HIGH

---

## H-04-06 — Mutation-Gap: Equality-Check sender_permanent_did vs. bundle.sender_id (Forensische Attribution fälschbar)
- **Vermutung:** Der Equality-Check `payload.sender_permanent_did != bundle.sender_id`
  (uncovered_code.md ~306, heute ~266) überlebt als Mutant. Ohne diesen Check könnte ein Angreifer A
  ein kryptografisch valides Bundle mit EIGENER Bundlesignatur versenden, dessen Privacy-Guard aber als
  `sender_permanent_did` eine DRITTPERSON C deklariert. Da `extract_sender_from_transaction` (~1110)
  für die lokale Counterparty-Attribution bevorzugt die DID aus dem entschlüsselten Guard nimmt, würde
  der Empfänger C in seinem Event-Log/TransferSummary als Absender aufgezeichnet → Offline-Forensik und
  Dispute-Workflow werden gezielt vergiftet (Attribution Spoofing/Framing-by-design-Schnittstelle).
- **Betroffene Invariante:** Gebundene Attribution: Die im Guard deklarierte permanente Sender-DID muss
  kryptografisch mit dem Bundlesigner übereinstimmen; keine Fremd-Attribution ohne dessen Signaturschlüssel.
- **Zielcode:** src/wallet/transaction_handler.rs :: process_encrypted_transaction_bundle (~266–271 MismatchedPrivacySenderId-Guard); Attribution: extract_sender_from_transaction (~1110–1137)
- **Geplanter Fail-First-Test:** Gültigen Bundle-Container von Angreifer-Schlüssel bauen, Privacy-Guard
  jedoch mit `sender_permanent_did = <DID eines Unbeteiligten>` verschlüsseln:
  `assert!(matches!(res, Err(VoucherCoreError::Validation(ValidationError::MismatchedPrivacySenderId{..}))));`
  und zusätzlich: `assert!(!event_log_mentions(unbeteiligter_did));`
  Mit Mutant (`==`) würde das Bundle angenommen und C attribuiert → assert failt.
- **Triage-Vorabcheck:** `[INTENTIONAL DESIGN REQUIREMENT]`? Nein — der Check existiert bereits und ist
  dokumentiert als SECURITY CHECK; es fehlt ausschließlich der Kill-Test (Regression-Coverage).
- **Priorität:** MEDIUM

---

## H-04-07 — decimal_utils::format_for_storage rundet still statt Precision-Verlust zu verwerfen (Conservation-Randfall)
- **Status Phase B:** FALSE-POSITIVE (für Ausnutzung) — alle Produktionsrouten geschützt: create_transaction ruft `validate_precision` VOR beiden format_for_storage-Calls (transaction.rs:67→90/197); Issuance-Route (creation.rs:243 ohne Präzisionscheck) ist fail-closed, da verify_transaction_basics init-amount == nominal_value erzwingt. Control-/Regression-Guard-Test `sa04_07_...` (grün): Exactness-Invariante im gültigen Domänenbereich + End-to-End-Split-Conservation-Tripwire; Defense-in-Depth-Empfehlung (fail-on-rounding) im Report dokumentiert; Finding HMSEC-SA04-07.
- **Vermutung:** `format_for_storage` nutzt `format!("{:.1$}", amount, places)` und RUNDET damit
  stillschweigend auf die Standard-Präzision — inklusive möglicher AUFRUNDUNG (z. B. Rest 0.006 bei
  places=2 → "0.01"): Σ Outputs könnte Σ Inputs um Rundungsdust übersteigen. Aktuelle Analyse sagt:
  Der Vektor ist mehrschichtig blockiert, WEIL sowohl Sende- (`validate_precision` in
  create_transaction) als auch Empfangsseite (chain.rs ~130–147 für amount UND sender_remaining_amount)
  scale ≤ places erzwingen und die Subtraktion `spendable_balance - amount_to_send` daher nie mehr
  Präzision als places produzieren kann. ABER: Die Funktion selbst hat keinen Schutz (kein Debug-Assert,
  kein Fehler-Pfad), sodass jede künftige Import-/Aggregations-Route mit höherskaligen Beträgen
  (z. B. Summierung mehrerer Outputs in `get_spendable_balance` mit gemischten Skalen, künftige
  Fee-Logik, externe Imports) stille Inflation/Erosion einführt. Hypothese: Es existiert HEUTE eine
  erreichbare Route, bei der ein gerundetes Split-Rest die Conservation verletzt — oder mindestens
  fehlt der invarianten-seitige Beweis, dass nicht.
- **Betroffene Invariante:** Conservation of Value: Σ Inputs = Σ Outputs (+Fees) exakt; kein stiller
  Wertverlust/-zuwachs durch Formatierung.
- **Zielcode:** src/services/decimal_utils.rs :: format_for_storage (~46–48); Verbraucher: src/services/voucher_manager/transaction.rs :: create_transaction (~87–94 Split-Rest)
- **Geplanter Fail-First-Test:** Proptest/invariantentest: Für zufällige (balance, amount)-Paare mit
  scale ≤ places gilt nach Split `Decimal::from_str(formatted_amount) + Decimal::from_str(formatted_remaining) == balance.normalize()`.
  Zusätzlich Direkttest des Grenzfalls: `let rem = dec!(10.005); format_for_storage(&rem, 2)` — Soll:
  entweder exakt oder Err; Ist: stilles Runden ("10.00"/"10.01"). Falls Phase B zeigt, dass alle
  produktiven Routen scale ≤ places garantieren, Ergebnis = FALSE POSITIVE für Ausnutzung, aber
  Behandlungsempfehlung: format_for_storage hart machen (fail-on-rounding) als Defense-in-Depth.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Stilles Runden ist schwerlich
  intendiert (das Projekt dokumentiert sonst jeden Determinismus-Grundsatz); eher historisch
  unbedacht, weil aktuell unkritisch. Klassifikation als Defense-in-Depth-Gap plausibel.
- **Priorität:** MEDIUM

---

## H-04-08 — Panic-Freiheit der Bundle-/Container-Dekoder unter fuzz-artigen Malformed-Inputs (systematischer Invariantenscan)
- **Vermutung:** Trotz manueller Prüfung (siehe Recherche-Notiz oben: dalek-from_slice ist Result-basiert,
  crypto_symmetric length-guarded) kann nicht ausgeschlossen werden, dass eine Kombination malformed
  Felder (kaputte base64url in protected/iv/tag/encrypted_key, epk mit falscher Länge, leeres recipients
  Array, tief geschachteltes/unbalanciertes JSON in `unprotected`/protected-header, Unicode/Control-Chars
  in did:key-Strings, extrem lange Strings) einen Panic-Pfad erreicht (Indexing, Slice-OOR, arithmetischer
  Overflow in Hash/Längenlogik, serde-Rekursionstiefe). Gefordert ist ein systematischer
  catch_unwind-Invariantentest über eine Malformed-Input-Matrix gegen `open_and_verify_bundle` und
  `open_secure_container` (beide sind die untrusted Entry-Points VOR jedem Signatur-/Entschlüsselungserfolg).
- **Betroffene Invariante:** Panic-Freedom on Untrusted Inputs: Der Core panict NIEMALS auf Netzwerkinput
  (CWE-248; FFI/WASM-Absturzrisiko).
- **Zielcode:** src/services/bundle_processor.rs :: open_and_verify_bundle (~105–169); src/services/secure_container_manager.rs :: open_secure_container (~248–346)
- **Geplanter Fail-First-Test:** Matrix-Generator (mutierter legitimer Container: Feld-für-Feld ersetzen
  durch [], "", 1 Byte, 31/33 Bytes, 1 MB, nicht-kanonisches base64, JSON-Typ-Wechsel epk→Zahl,
  recipients=[{header:{kid:1}},...], et=None trotz TransactionBundle etc.) und pro Eingabe:
  `let outcome = catch_unwind(AssertUnwindSafe(|| open_and_verify_bundle(&identity, &malformed))); assert!(outcome.is_ok(), "panic on malformed input variant {:?}", label);`
  Jeder gefundene Panic = FAIL auf unpatched code; wenn alle Varianten graceful Err liefern →
  dokumentierter FALSE POSITIVE (Invarianztest bleibt als Regression-Guard bestehen).
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Nein — Panic-Freiheit ist
  explizite Systeminvariante des Audit-Auftrags; höchstens Einzelvarianten könnten als
  „unreachable by design" wegtriagiert werden.
- **Priorität:** LOW (Erwartung: weitgehend gehärtet; Ziel ist Beweis + Regression-Guard)

---

## Querverweise (Koordinator-Entscheid nötig)
- `src/services/crypto_utils.rs :: validate_user_id` (Negation-Bypass, ~817), `get_short_hash_from_user_id`
  (~134/136), `build_hkdf_info` (~309), `decrypt_recipient_payload` Bounds (~338): laut Koordinations-Doc §2
  Modul 02 zugeordnet → hier nur Querverweis, keine eigenen Hypothesen.
- `trap_manager::verify_trap`-Panic-Kandidaten (blinded_id/R-Längen): verifiziert UNSCHÄDLICH in
  curve25519-dalek 4.1.3 (Result-API); Modul 01/02-Scope, kein Modul-04-Finding.

---

# Wave 3 (Stand: HEAD b006cfb)

> Adversarial Re-Audit nach Commit `b006cfb` (HMC_TX_AUTH_V3 / Shared-Signature Trap).
> Phase A — nur Codeanalyse, keine Tests/Builds. Nummerierung fortlaufend ab WH3-04-401.
>
> **Untersucht und sauber befunden (keine Hypothese nötig):**
> - Conservation: `checked_add` an chain.rs:197 und chain.rs:440 intakt; Output-Matching nur
>   gegen EINZELNE Vor-Outputs (`normalize()`-Equality, chain.rs:221) — Summierung mehrerer
>   Outputs strukturell ausgeschlossen; V3 hat die Betragslogik nicht berührt.
> - Split-Anchor-Separation (SA04-05-Fix) unverändert vorhanden (chain.rs:405–425); der
>   V3-Umbau fasst die Anchor-Erzeugung in `create_transaction` nicht an.
> - SA04-04-Snapshot-Rollback-Wrapper intakt (transaction_handler.rs:114–136) und umschließt
>   auch den neuen SST-Witness-Pfad; Receive-Pfad ruft via `validate_voucher_against_standard`
>   (voucher_validation/mod.rs:58) die komplette Chain-Validation INKLUSIVE
>   ds_tag↔Input-Bindung (chain.rs:338–345) VOR dem Witness-Check.
> - Neue SST-Parser (`parse_point_bs58`, `parse_canonical_scalar`, trap_manager.rs:156–179)
>   sind durchgängig Result-basiert; `.expect("len checked")` in
>   `verify_fingerprint_signature` (conflict_manager.rs:149/155/166/167) durch vorangestellte
>   Längenchecks abgesichert; `reconstruct_identity` guardt τ-Gleichheit, c=0, Identitäts-
>   punkt und nutzt dalek-sicheres `invert()`.
> - **Status-Hinweis zu H-04-02:** Der Archiv-Loop wurde in/bis `b006cfb` auf BEST-EFFORT
>   umgestellt (transaction_handler.rs:1040–1080, AUDIT-00-WILDCARD-002-Kommentar; Fehler
>   werden geloggt statt `?`). Die ursprüngliche H-04-02-Fehlerklasse („Err lügt über
>   committed State") ist damit auf Senderseite entschärft; Koordinator möge den Status in
>   H-04-02 entsprechend pflegen.

---

## WH3-04-401 — Guard-Äquivokation unsichtbar: t_id-Preimage schließt privacy_guard aus → unentdeckbare Doppel-Aushändigung
- **Status Phase B (Wave 3 FIX):** CONFIRMED-PENDING (Protocol Break) — Test `sa04_08_...` zunächst repariert (Setup: Full-Spend re-keyt die lokale Instanz-ID; Harvest jetzt über unveränderliche `voucher_id` statt altem Local-Key). Danach FAILT er NUR noch an der Vulnerability-Assertion: byte-identische Fingerprints unter zwei echten AEAD-Guards (Assertion b) — Lücke bewiesen. Triage: Option A (Detektor-Fix ohne Wire-Break) kryptographisch unmöglich — die Varianten unterscheiden sich AUSSCHLIESSLICH im Guard-Blob, der in KEINEN authentifizierten Commitment fließt; jeder unauthentifizierte Detektor-Signal ist vom Angreifer selbst (er IST der Signaturgeber beider Varianten) strip-/forgierbar; Gruppierung fordert zudem `unique_t_ids > 1`, was bei identischem t_id axiomatisch scheitert. Entscheidung: Option B → `#[ignore = "..."]` mit ausführlicher Begründung; Remediation-Design (HMC_TX_AUTH_V4: guard_hash in den L2-Digest, epoch-markierte Dual-Verification) im Report `04_integrity_report.md` Wave-3-Sektion. Finding HMSEC-SA04-08.
- **Vermutung:** Seit V3 fließen `trap_data` UND `privacy_guard` NICHT mehr in das t_id-Preimage
  (chain.rs:599–605; Anhang nach t_id-Berechnung in voucher_manager/transaction.rs). Der
  HMC_TX_AUTH_V3-Digest (chain.rs:664–694, l2_gateway.rs:280–299) bindet ebenfalls NICHT den
  Guard; `encrypt_transaction_timestamp` leitet seinen XOR-Key nur aus (prev_hash, t_id) ab
  (conflict_manager.rs:712–730) und ist guard-unabhängig. D.h.: Ein Absender kann EINEN Spend
  erzeugen und DIESELBE Transaktion (identisches t_id, identische layer2_signature, identische
  Shards) mit ZWEI verschiedenen, jeweils AEAD-gültigen Guards versehen und an zwei Opfer
  aushändigen (Stealth/Flexible: recipient_id = ANONYMOUS in beiden Varianten → t_id wirklich
  identisch). Beide Varianten passieren `verify_transactions` unabhängig voneinander (`Ok`),
  weil der Guard kryptografisch an GAR NICHTS gebunden ist — die Kind-Verkettung
  (prev_hash = H(canonical JSON inkl. Guard, chain.rs:459)) unterscheidet sie erst im
  Nachhinein. Folgen: (a) Die Fingerprint-Erzeugung ignoriert den Guard
  (conflict_manager.rs:25–116) → beide Varianten liefern BYTE-IDENTISCHE Fingerprints →
  HashSet-Dedup + `unique_t_ids.len() > 1`-Bedingung (conflict_manager.rs:282–304) sehen
  KEINEN Konflikt; (b) selbst ohne Dedup würde `extract_sst_identity` die Äquivokation
  verwerfen, da identische Shards+τ als „replay, not a fork" degeneriert zurückgewiesen
  werden (trap_manager.rs:395–406, 468–472); (c) spenden beide Opfer später, haben ihre
  Forks DIFFERENZIERTE ds_tags (= H(prev_hash‖E), prev_hash enthält den jeweiligen Guard,
  transaction_handler.rs:807/820–831) → KEINE Kollision, KEINE Attribution, NIE. Netto:
  Ein böswilliger Aussteller/Verkäufer verkauft einen Gutschein doppelt, und das System
  besitzt NULL kryptografische Fraud-Evidenz — unter V2 (Guard+Trap im Preimage) hatten die
  Varianten verschiedene t_ids und galten als sauberes Double-Spend-Fork-Paar. Das ist eine
  V3-Regression gegen die Kern-Invariante „Double-Spending ist kryptographisch beweisbar“.
  (Wellen-2-Fix SA04-04/Snapshot-Rollback und SA06-02 Bundle-Signatur helfen nicht: Der
  Signaturgeber IST hier der Angreifer und signiert beide Varianten legal.)
- **Betroffene Invariante:** Conservation of Ownership / Fraud-Detectability: Ein Input darf
  nicht in zwei strukturell validen, aber evidenzlos divergierenden Aushändigungen münden;
  Σ Besitzansprüche ≤ Σ Inputs muss beweisbar bleiben.
- **Zielcode:** `src/services/voucher_validation/chain.rs:599–605` (Preimage-Exklusion),
  `chain.rs:641–694` (L2-Digest ohne Guard), `src/services/trap_manager.rs:401–406`
  (Identical-Shard-Rejection), `src/services/conflict_manager.rs:282–304` (Gruppierung nur
  über ds_tag + unique_t_ids>1, Hash-Dedup identischer Fingerprints), `conflict_manager.rs:703–734`
  (guard-unabhängiger Timestamp-Key), `src/models/voucher.rs` (TrapData/RecipientPayload V3-Felder).
- **Geplanter Fail-First-Test:** Stealth-Kette init(100)→transfer T erzeugen; Variante B =
  Klon mit `T.privacy_guard` ersetzt durch einen für zweiten Test-Empfänger gültig
  re-verschlüsselten RecipientPayload (gleiche Helper wie create_transaction). Dann:
  1) `assert!(verify_transactions(&va).is_ok() && verify_transactions(&vb).is_ok());`
     (beide individuell valide, identisches t_id — dokumentiert die Bindungslücke);
  2) `assert_eq!(create_fingerprint_for_transaction(&ta,…)?, create_fingerprint_for_transaction(&tb,…)?);`
  3) SOLL-Assertion: `check_for_double_spend` mit own={fp_A}, foreign[D]={fp_B} MUSS einen
     Konflikt/Equivocation-Evidence liefern (oder verify_transactions muss Variante B bei
     bekannter A ablehnen). Auf unpatched Code ist `result.verifiable_conflicts` leer bzw.
     beide `Ok` → Assertion schlägt fehl und beweist die Unsichtbarkeit.
- **Triage-Vorabcheck:** Die Exklusion ist im Commit dokumentiert („guard is AEAD-protected")
  — aber dokumentierte Absicht heilt nicht, dass damit ein Kern-Paradigma
  (Fraud Detection, Not Prevention → Beweisbarkeit) für den wichtigsten Angriffsakteur
  (den Aussteller selbst) ausgehebelt wird. Kein legitimer Use-Case benötigt zwei
  verschiedene Guards auf identischem t_id. Remediation-Optionen für Phase B/Triage:
  Guard-Hash ins t_id-Preimage ODER in den L2-Digest aufnehmen, oder Duplicate-t_id mit
  divergierender kanonischer JSON explizit als Konfliktklassen behandeln.
- **Priorität:** CRITICAL

---

## WH3-04-402 — Public-Mode-R5-Lücke: Garbage-/Nicht-SST-Shards passieren Creation & Validation → dauerhafte DS-Detection-Evasion
- **Status Phase B (Wave 3 FIX):** CONFIRMED+FIXED — Test `sa04_09_...` FAIL auf unpatched (beide Garbage-Ketten `Ok(())`); Fix: neue `pub(crate) trap_manager::validate_shard_structure(trap_r, trap_s)` (Base58 + 32-Byte-Gates; STRICT CANONICAL compressed-Edwards für R — wichtig: `[0xFF;32]` ist unter dalek dekomprimierbar, y ≡ 18 mod p! Daher zusätzlich Kanonizitäts-Gate masked-y < p analog `parse_canonical_scalar`; Decompress-Check; kanonischer Scalar für s), gerufen aus dem `trap_data`-Block von `verify_transactions` (chain.rs) für alle NON-init-Tx. Init/Issuance unverändert. Synergie: `"none"/"none"`- und `""/""`-Placeholder-Shards scheitern an den Längen-/Dekodier-Gates → SA06-11 (SOLL-A) und audit_02_09 (SOLL-A) dadurch bedient. Regressions: identity_trap_audit 8/8, core_logic::security::trap_verification 6/6 grün. Finding HMSEC-SA04-09.
- **Vermutung:** Der R5-Handover-Schutz (Witness-Check, transaction_handler.rs:355–413) liegt
  komplett INNERHALB des `if let Some(guard_base64) = &last_tx.privacy_guard`-Blocks
  (transaction_handler.rs:320). Im Public-Mode gibt es legimitately KEINEN Guard
  (recipient_id = DID im Klartext) → der Empfänger prüft KEINE Witness, und auch die
  Chain-Validierung prüft Shards nur auf DID-Marker-Zeichen und ds_tag-Bindung
  (chain.rs:310–353) — NIEMALS, ob `trap_r` ein dekomprimierbarer Curve-Punkt oder `trap_s`
  ein kanonischer Skalar ist. Da die layer2_signature vom Inhaber des Ephemeral-Keys
  erzeugt wird, kann ein böswilliger Sender BELIEBIGE Byte-Strings als Shards signieren und
  in Umlauf bringen (Raw-Bundle-Crafting umgeht `generate_sst_trap`). Solche Shards sind
  keine affinen Bilder eines SST-Zusammenhangs: Jede spätere Kollision dieses Inputs
  scheitert in `parse_shard`/`reconstruct_identity` (trap_manager.rs:366–437) → Extraktion
  unmöglich → der Coin ist permanent gegen Double-Spend-Attribution immun, obwohl alle
  Signaturen/Validationen grün sind. Im Stealth-Mode verhindert genau dieser Angriff der
  Handover-Witness-Check (R5); Public-Mode-Zahler haben kein Äquivalent. Damit ist die
  Kern-Invariante „Double-Spending muss kryptographisch PROVIERBAR sein" für alle
  Public-Mode-Sends selektiv abschaltbar.
- **Betroffene Invariante:** Fraud-Detectability (DS-Tag/Shard-Mathematik muss für jeden
  Spend intakt bleiben); Panic-/Parsing-Robustheit ist gegeben, aber strukturelle
  Shard-Sanität fehlt vollständig auf Validator-Ebene.
- **Zielcode:** `src/wallet/transaction_handler.rs:319–421` (Witness-Check nur bei
  Guard-Präsenz), `src/services/voucher_validation/chain.rs:310–353` (fehlende Punkt-/Skalar-
  Strukturprüfung), Gegenprobe Stealth: transaction_handler.rs:360–413; Shard-Erzeugungs-
  Kontrakt: trap_manager.rs:227–273.
- **Geplanter Fail-First-Test:** Valide Public-Mode-Kette erzeugen, dann Tip-Transaktion:
  `trap_data = TrapData { ds_tag: <korrekt rekombinierter Tag>, trap_r: bs58([0xFF;32]) (kein
  Curve-Punkt), trap_s: bs58([0xFFu8;32]) (nicht-kanonischer Skalar) }`, layer2_signature vom
  Test (als Input-Key-Inhaber) korrekt über den manipulierten Shard-String neu berechnen.
  SOLL: `verify_transactions(...)` MUSS mit strukturellem Shard-Fehler abweisen (Generation-
  Kontrakt garantiert dekomprimierbaren R_i + kanonischen s_i). Ist auf unpatched: `Ok(())`
  → Test schlägt fehl. Optional Teil 2 (End-to-End): solcher Coin wird doppelt ausgegeben →
  `extract_sst_identity` liefert Err → keine Attribution → Beweis der Evasion.
- **Triage-Vorabcheck:** Könnte `[INTENTIONAL DESIGN REQUIREMENT]` sein? Der Verzicht auf
  On-Chain-Punkt-/Skalarparsen könnte Performance-motiviert sein; allerdings erzwingt
  `verify_fingerprint_signature` am Gossip-Ingress denselben Striktheitsgrad indirekt, und
  der R5-Kommentar beansprucht fail-closed-Verhalten generell. Mindestlösung (strukturelle
  Canonical-Checks im Validator) kostet zwei Decode-Aufrufe pro Tx und bricht nichts;
  Vollbild (Witness auch im Public-Mode bzw. Verpflichtung zu Guard) wäre Triage-Thema.
- **Priorität:** HIGH

---

## WH3-04-403 — Fingerprint-Ingress ohne Input-Bindung: fremde Self-Signed-FPs unter Opfer-ds_tag vergiften Konflikt-Radar dauerhaft
- **Status Phase B (Wave 3 FIX):** CONFIRMED+FIXED — Test `sa04_10_...` FAIL auf unpatched (2 Fremd-Keys persistiert unter D_H + Junk-Proof). Fix in `conflict_handler.rs::process_received_fingerprints`: VOR der Admission wird der LOKALE Input-Kontext gebaut (ds_tag → Menge legitimer `sender_ephemeral_pub` aus allen gehaltenen Chains, own active/history, local_history); kollidierende Fremd-FPs werden nur zugelassen, wenn ihr Key einem lokal revealed Input-Key entspricht (Storage-Zeit-Analogon zu `reproduces_local_tag`). Tags OHNE lokalen Kontext bleiben unberührt → normaler Gossip über unbekannte Inputs funktioniert weiter (F11-Gate unangetastet; ehrliches Forwarding trägt stets den echten Spender-Key = lokaler Chain-Key). Test grün: keine Fremd-Entries unter D_H, proof_store leer, list_conflicts leer, Opfer bleibt Active. Finding HMSEC-SA04-10.
- **Querverweis:** Kernthema „False Dispute Injection" gehört Modul 01 (A-01); hier als
  Wave-3-relevante Lücke dokumentiert, da der V3-Ingress-Gate (b006cfb) die Grenze neu
  zieht. Koordinator entscheide die Eigentümerschaft.
- **Vermutung:** Der Ingress-Filter (conflict_handler.rs:995–1002) lässt jeden Forwarded
  Fingerprint zu, der (a) kein Init-FP ist und (b) eine gültige layer2_signature über den
  V3-Digest trägt — signiert ALLERDINGS vom EPHEMERAL KEY IM FINGERPRINT SELBST. Ein
  Angreifer erzeugt freihaus Keypairs und kann daher beliebig viele „selbst-authentische"
  Fingerprints mit GLEICHER ds_tag (z. B. dem echten Input-Tag D_H eines Opfers, das aus
  Gossip/Bundles öffentlich ablesbar ist) und beliebigen t_ids einschleusen. Es fehlt die
  Bindungsprüfung `ds_tag == H(prev_hash ‖ sender_ephemeral_pub)` — sie existiert erst in
  `resolve_conflict_offline::reproduces_local_tag` (conflict_handler.rs:1175–1211), also erst
  IM Quarantäne-Rennen, nicht bei der SPEICHERUNG. Folge: X1/X2 landen dauerhaft in
  `known_fingerprints.foreign_fingerprints[D_H]`; jede zukünftige ehrliche Spende des Opfers
  unter D_H gruppiert in `check_for_double_spend` auf ≥3 unique t_ids → dauerhaft
  `verifiable_conflicts` + Soft-Proof-Erzeugung (conflict_handler.rs:554–605, 780–806) +
  Proof-Store-Wachstum bei jedem Empfang (transaction_handler.rs:566–601, 691–701).
  Quarantäne selbst wird durch reproduces_local_tag zuverlässig blockiert (Opfer-Branch
  gewinnt immer), daher KEIN direkter Value-Verlust — aber permanenter False-Alarm-Kanal
  Richtung App-Layer, Proof-Müll und unbezahlbares Rauschen im Forensik-Workflow; zudem
  widerspricht das der dokumentierten Attacker-Class-Grenze („nur ehemalige Key-Inhaber",
  conflict_handler.rs:1103–1117), denn hier reicht JEDER Externe.
- **Betroffene Invariante:** Integrität des Konflikt-Detection-Kanals: Kollisionsevidenz muss
  an realen Input-Kontext gebunden sein; Speicher/Alarmkanäle dürfen nicht unbegrenzt von
  Nicht-Inhabern beschrieben werden können.
- **Zielcode:** `src/wallet/conflict_handler.rs:995–1070` (Ingress-Filter + persistente
  Speicherung ohne Tag-Bindung/Cap), `src/services/conflict_manager.rs:282–304` (Gruppierung
  ausschließlich per ds_tag, keine sender_ephemeral_pub-Gleichheit — anders als die
  Extraktion conflict_handler.rs:712–749), Hardening-Referenz: conflict_handler.rs:1175–1211.
- **Geplanter Fail-First-Test:** Opfer-Wallet mit aktivem Voucher (Input-Tag D_H) bauen;
  Bundle eines Angreifers mit forwarded_fingerprints [X1(E_A,D_H,t1), X2(E_A,D_H,t2)] (eigene
  Keys, korrekt self-signiert) via `process_encrypted_transaction_bundle` injizieren. SOLL:
  Ingression MUSS FPs ohne nachvollziehbare Input-Bindung verwerfen oder mind. beim nächsten
  Scan keinen Konflikt melden:
  `assert!(wallet.known_fingerprints.foreign_fingerprints.get(D_H).unwrap_or(&vec![]).iter().all(|fp| fp.sender_ephemeral_pub == E_H));`
  und danach normale eigene Spende → `check_result.verifiable_conflicts` MUSS leer sein.
  Auf unpatched Code sind X1/X2 gespeichert und der Konflikt wird gemeldet → FAIL.
- **Triage-Vorabcheck:** Der Doc-Block (conflict_handler.rs:1099–1117) akzeptiert
  „ehemalige Key-Inhaber" als Restrisiko ([INTENTIONAL] für DIESE Klasse) — aber gerade
  NICHT beliebige Externe, und die Implementierung der Eingrenzung erfolgt erst im Race,
  nicht im Radar. Klassifikation vermutlich `[CONFIRMED VULNERABILITY]` mit reduzierter
  Severity (Availability/Forensics, kein Direktwertverlust); Alternativ-Remediation:
  Tag-Bindungscheck bereits im Ingress-Filter (Analogon zu reproduces_local_tag gegen
  lokale Ketten) + Größen-Cap je ds_tag-Gruppe.
- **Priorität:** MEDIUM

---

## WH3-04-404 — Unbegrenzte Base58/JSON-Allokationen in den neuen SST-/Fingerprint-Decodern (OOM-Abort statt graceful Err)
- **Status Phase B:** WEGGELASSEN (Test) — WRITE done für die Dokumentation, **kein Test**. Begründung: Das eigentliche Risiko ist Allokations-Amplifikation bis zum Prozess-Abort (OOM), der NICHT `catch_unwind`-fangbar und in Unit-Tests nicht sicher reproduzierbar ist (reale OOM-Bedingungen im CI-Prozess sind unzuverlässig und gefährden die Testinfrastruktur; ein Custom-Global-Allocator mit harten Limits würde das gesamte Testbinary betreffen und ist flaky-anfällig). Ein praktisch sicherer Test (z. B. 100–200 KB Shard-String durch `verify_fingerprint_signature`/`parse_shard`) liefert auf unpatched Code bereits graceful `false`/`Err` — er wäre ein PASS ohne Fail-First-Aussagekraft und bewiese nur Panik-Freiheit (bereits durch Modul-02 abgedeckt), nicht die fehlende Längenschranke. Der Befund selbst bleibt bestehen: keine Length-Gates vor `bs58::decode` an trap_manager.rs:169–179/309–322/366–374, conflict_manager.rs:135–146/714–724, transaction_handler.rs:375–397; secure_container.rs:189 räumt die Limitation selbst ein. Empfehlung an Triage: Remediation als zentralen `decode_fixed_b58::<N>()`-Helper (Vorab-Längencheck) umsetzen; ein Regressionstest ist erst MIT Fix sinnvoll schreibbar (dann: dedizierter Error-Variant bei Überschreitung des Caps). Priorität LOW unverändert.
- **Vermutung:** Alle neuen V3-Decodier-Stellen rufen `bs58::decode(..).into_vec()` OHNE
  vorherige Längenschranke auf — u. a. `parse_point_bs58`/`parse_canonical_scalar`
  (trap_manager.rs:169–179, 309–322, 366–374), `verify_fingerprint_signature`
  (conflict_manager.rs:135–146), `encrypt/decrypt_transaction_timestamp`
  (conflict_manager.rs:714–724, 751–761), Witness-Ingestion (transaction_handler.rs:375–397),
  `reproduces_local_tag` (conflict_handler.rs:1180–1187). Base58-Dekodierung alloziert
  ~ln(58)/ln(256)≈0,73× der Eingabelänge als Vec, bevor eine evtl. Längen-/Formatablehnung
  erfolgt; `SecureContainer`/Bundle-Größen sind nirgends gecappt
  (secure_container_manager.rs / bundle_processor.rs enthalten keine Limits; models/secure_container.rs:189
  dokumentiert die Lücke nur als „known limitation" für Header-Strukturen). Ein Netzwerk-
  Akteur kann daher über Guard-, Shard-, prev_hash- oder Fingerprint-Felder
  Allokations-Amplifikation bis zum Prozess-Abbruch (OOM-Abort — NICHT catch_unwind-fangbar,
  tödlich im FFI/WASM-Kontext) treiben. Die eigentliche Panic-Freiheit (CWE-248) bleibt
  formal bestehen; die Ressourcen-Variante derselben Systeminvariante ist jedoch unerwiesen.
- **Betroffene Invariante:** Robustheit auf untrusted Input: Ablehnung MALFORMED/Riesiger
  Felder muss vor teurer Verarbeitung erfolgen (fail-fast), kein Abbruchweg über
  Allokationsversagen.
- **Zielcode:** `src/services/trap_manager.rs:169–179/309–322/366–374`,
  `src/services/conflict_manager.rs:135–146/714–724`,
  `src/wallet/transaction_handler.rs:375–397`, `src/models/secure_container.rs:189` (Known
  Limitation), Limitsuche negativ in `secure_container_manager.rs`/`bundle_processor.rs`.
- **Geplanter Fail-First-Test:** Invariantentest mit hartem Längengate: SOLL-Verhalten ist,
  dass Shard-/Point-/Hash-Felder >64 Zeichen (bzw. konfigurierbare Caps) mit einem
  dedizierten Fehler (z. B. `Crypto("field too long")`) abgelehnt werden BEVOR dekodiert
  wird. Test speist z. B. `TransactionFingerprint.trap_r` mit 10 MB gültigem Base58 in
  `verify_fingerprint_signature`/`parse_shard` und asserted (a) Rückkehr mit
  Length-Gate-Fehler und (b) Peak-Allocation unter Schranke (custom allocator/Zählwrapper,
  Phase B entscheidet Mechanik). Auf unpatched Code existiert kein Length-Gate → entweder
  anderes Error-Variant (Decode-Längenfehler erst nach MB-Allokation) oder Abort → FAIL.
  Erwartungsnotiz: hohes FALSE-POSITIVE-Risiko im engeren Sinne (Ergebnis heute schon
  `Err`), Wert liegt im Nachweis der Allokationsklasse + Regression-Gate.
- **Triage-Vorabcheck:** Kein Design-Intent erkennbar (models/secure_container.rs:189 räumt
  die Lücke selbst als „known limitation" ein). Remediation: zentrale
  `decode_fixed_b58::<N>()`-Helper mit Vorab-Längencheck; API-kompatibel.
- **Priorität:** LOW
