# Defensiver Security-Audit Wave 5 — Stealth/Shards/Konflikte/Fingerprints/Bundles

**Datum:** 2026-08-29  
**Auditor:** Muse Spark (OpenCode) — Senior Rust  
**Scope (rigoros, codezeilen-genau):** `src/services/voucher_validation/chain.rs`, `src/services/trap_manager.rs`, `src/services/conflict_manager.rs`, `src/wallet/conflicts.rs`, `src/services/bundle_processor.rs`, `src/wallet/transactions.rs`  
**Methodik:** Manuelle Sichten + Ausführung `cargo test` (full) + reproduzierbare Defensive Tests unter `tests/security_audit_defensive_wave5.rs`

## Executive Summary

Der Code-Stand HEAD ist **hoch gehärtet**: V3-SST (Shared-Signature-Trap), `HMC_TX_AUTH_V3`-Digest, kanonische Skalar-/Punkt-Gates, `is_init_fingerprint`-Korrektur (`"none"/"none"` nur), Ingress-Signature-Gate, Bucket-Cap 150, plausible Zeitfenster, `reproduces_local_tag`, atomare Bundle-Rollbacks. Es verbleiben **3 relevante Findings** (1 Medium, 2 Low) sowie 2 **Hardening-Optimierungen** (Dos/Normierung). Alle Fixes sind in diesem Audit umgesetzt, 7 neue defensive Tests decken die Lücken ab, `cargo test` ist grün.

## Findings-Übersicht

| ID | Priorität | Dateien/Zeilen | Problem | Empfehlung/Fix (Status) |
|---|---|---|---|---|
| **W5-01** | **Medium** | `src/services/conflict_manager.rs:904-911` (`import_foreign_fingerprints`)<br>`src/wallet/conflicts.rs:1387` (`process_received_fingerprints`) | **Equivocation-Evidenz wird bei Gossip-Dedup verworfen.** Dedup auf `t_id`-Gleichheit allein droppt zweite Fingerprints mit **gleicher `t_id` aber divergenten signatur-gebundenen Feldern** (`trap_r/s`, `encrypted_timestamp`, `layer2_signature`, `privacy_guard_hash`). `check_for_double_spend` besitzt zwar `has_equivocation` (`conflict_manager.rs:429-453`) für *gleiche `t_id` + divergente Evidenz* (HMSEC-SA04-08), erreicht diesen Ast aber nie, wenn der Ingress die zweite Hälfte bereits als "Duplikat" verwirft. Angreifer kann per Gossip eine equivocation (z. B. zweiter Guard unter gleicher `t_id`) im selben Bucket unterschlagen; Kläger sehen nie einen Konflikt. Cross-Source-Equivocation (own vs. foreign) blieb sichtbar — rein-foreign equivocation nicht. | **Fix implementiert:** Dedup auf **exakter Evidenz-Gleichheit** (alle signatur-gebundenen Felder) + Erhalt divergenter `t_id`-Kollisionen. `deletable_at` ausgenommen (lokal zugewiesene Retention). Gleicher Fix in `wallet/conflicts.rs`. *Tests:* `wave5_foreign_equivocation_same_tid_divergent_shards_both_stored_and_detected` beweist Ingress + Detektion; Re-Import exakt identischer Fingerprint bleibt deduped. |
| **W5-02** | Low | `src/services/trap_manager.rs:194-213` (`validate_shard_structure`)<br>`src/services/voucher_validation/chain.rs:335-383` | **Keine Längen-Schranke vor `bs58::decode` / fehlende `ds_tag`-Formatprüfung.** `trap_r/s` (und `ds_tag`) wurden ohne Vorab-Längen-Gate dekodiert. Ein 10 KiB-String alloziert ~7 KiB temporär; bei hunderten Forks pro Bucket (Adversarial Bucket-Stuffing) CPU/Alloc-Amplifikation im synchronen Wallet-Pfad. `ds_tag` wurde nur per String-Vergleich geprüft, nicht strukturell (Base58 32 Byte). | **Fix implementiert:** Längen-Gate `>64` Base58-Zeichen (32 Byte ≈44 Zeichen) vor Decode in `trap_manager.rs:validate_shard_structure` und `chain.rs` für `ds_tag` + explizite `ds_tag`-Base58/32-Byte-Validierung vor `validate_shard_structure`. *Test:* `wave5_shard_structure_rejects_oversized_strings`. |
| **W5-03** | Low | `src/services/conflict_manager.rs:887-895` etc. | **Bucket-Cap bereits korrekt, aber ohne reproduzierbaren Boundary-Test.** `MAX_FOREIGN_BUCKET_CAP=150` existiert, aber die 151-Grenze war bisher nur indirekt getestet. | **Härtung:** Boundary-Test `wave5_foreign_bucket_cap_150_is_enforced` (151 unter gleichem `ds_tag`, nur 150 importiert). |
| **W5-04** | Info/Hardening | `src/wallet/transactions.rs:118-140` (`process_encrypted_transaction_bundle`)<br>`src/wallet/conflicts.rs:1180` | **Bundle-Atomarität korrekt, jedoch ohne expliziten In-Memory-Rollback-Regressionstest für Mehr-Voucher-Bundles.** Rollback via `clone()`-Snapshot ist korrekt implementiert (HMSEC-SA04-04), die In-Memory-`pending_events` werden mitsnapshotted. Fehlte aber ein Test mit 2 Vouchern im selben Bundle, bei dem der zweite an `validate_voucher_against_standard` (unbekannte Standard-UUID) scheitert — der klassische "erstes Voucher bereits eingehängt, zweites failt"-Fall. | **Test ergänzt:** `wave5_bundle_receive_atomicity_on_unknown_standard` — leeres Standards-Map → Err, danach `voucher_store.len()` und `pending_events.len()` unverändert. |
| **W5-05** | Info | `src/services/conflict_manager.rs:287-290` (`is_init_fingerprint`) | **Korrekt (`"none"/"none"` nur), aber Randfälle (`""`, `"invalid"`, gemischt) ohne dedizierten Unit-Test.** | **Test ergänzt:** `wave5_is_init_fingerprint_edge_cases` (4 Assertions). |
| **W5-06** | Info | `src/services/voucher_validation/chain.rs:539-549` | **Init-trap-Guard bereits korrekt** (`is_trivial`-Prüfung) — keine Lücke, aber als positiver Befund bestätigt. Test `wave5_chain_validation_rejects_nontrivial_trap_on_init` hält die Invariante fest. |

## Detail-Befunde

### W5-01 — Equivocation-Dedup (Medium)

**Schwere Begründung:** `has_equivocation` sollte *identische `t_id` + divergente signatur-gebundene Felder* als beweisbare Guard-/Shard-Equivocation (HMSEC-SA04-08) werten. Wenn beide Fingerprints aus **derselben** foreign-Quelle stammen und denselben `t_id` teilen, verwarf der alte Code den zweiten — die Detektion war systematisch blind für rein-foreign equivocation. Cross-Source (own vs. foreign) war nicht betroffen, da unterschiedliche Maps gemerged werden.

**Exploit-Szenario (reproduzierbar):**
1. Angreifer kennt seinen Input-Schlüssel `E`, wählt `t_id_X`.
2. Er signiert zwei Fingerprints unter gleichem `ds_tag=D`, gleichem `t_id_X`, aber mit zwei verschiedenen `trap_r/s` (oder zwei verschiedenen `privacy_guard_hash`) — beide mit validem `verify_fingerprint_signature` unter `E`.
3. Er gossippt beide an Opfer via `import_foreign_fingerprints` / `process_received_fingerprints` im selben Bucket.
4. Alt: `entry.iter().any(|e| e.t_id==fp.t_id)` → zweiter `push` unterbleibt → Bucket Len 1 → `has_equivocation` nie true.
5. Neu: exakte Evidenz-Gleichheit (`t_id` + 5 signatur-gebundene Felder) prüft Duplikat; divergent ⇒ beide gespeichert → `check_for_double_spend` meldet Konflikt.

**Fix-Details:**

```rust
// src/services/conflict_manager.rs ~904
let is_exact_duplicate = entry.iter().any(|e|
    e.t_id==fp.t_id && e.trap_r==fp.trap_r && e.trap_s==fp.trap_s
    && e.encrypted_timestamp==fp.encrypted_timestamp
    && e.layer2_signature==fp.layer2_signature
    && e.privacy_guard_hash==fp.privacy_guard_hash
);
if is_exact_duplicate { rejected; }
entry.push(fp); // equivocation (same t_id divergent) bleibt erhalten
```

Symmetrisch in `src/wallet/conflicts.rs:1377`. `deletable_at` bewusst ausgenommen (lokale 180-Tage-Retention streut pro Import).

### W5-02 — Längen-Gates (Low)

**Begründung:** Ohne Gate dekodiert `bs58::decode` beliebige Längen; 10 KiB Strings → 7 KiB Vec je Shard, je Transaktion 2 Shards, je Bucket bis 150 Mitglieder → multi-MB temporär im Hot Path `verify_transactions`/`import_foreign_fingerprints`/`resolve_conflict_offline`. Keine Panic, aber **Amplifikation** und fehlende Normierung.

**Fix:** `if trap_r.len()>64 || trap_s.len()>64 ⇒ Err("exceeds maximum Base58 length (64)")` in `validate_shard_structure`; analog `ds_tag.len()>64` + Base58-decode + `len==32` in `chain.rs`. Honest Pfade liefern ~44 Zeichen → unbehindert.

### W5-03 — Bucket-Cap-Boundary (Low)

Kein Bug, nur Absicherung: 151 distinct `t_id` unter gleichem `ds_tag`, alle einzeln korrekt signiert, via `import_foreign_fingerprints` → `new_count==150`, `bucket.len()==150`.

### W5-04 — Bundle-Atomarität (Info)

`Wallet::process_encrypted_transaction_bundle` (`wallet/transactions.rs:125-139`) nutzt `let snapshot=self.clone(); match inner { Ok⇒Ok, Err⇒*self=snapshot}` — korrekt inkl. `pending_events`. Die forensische Archivierung läuft **erst nach Commit** best-effort (wildcard_02-Fix). Der neue Test erzwingt den bisher unbewiesenen Pfad: 2-Voucher-Bundle, Standards-Map leer → zweiter Voucher scheitert an `validate_voucher_against_standard` nach bereits eingehängtem erstem Voucher → Rollback beweist `voucher_store` + `pending_events` unverändert.

### W5-05/06 — `is_init_fingerprint` & Init-Trap (Info/Positiv)

`is_init_fingerprint` ist seit Wave 4 korrekt: `fp.trap_r=="none" && fp.trap_s=="none"` — leere Strings, `"invalid"`, gemischt ⇒ nicht-genesis (spend-typed). `create_fingerprint_for_transaction` mappt Spends mit leerem/placeholder-Shard auf `VOID_SPEND_SHARD_MARKER="invalid"` → nie als Genesis fehlklassifiziert (HMSEC-SA06-11). `chain.rs:539-549` rejected nicht-triviale Init-traps — beides im Test abgesichert.

## Validierung

* `cargo test` — vollständig grün (inkl. aller Wave-4-Audits, 7 neue Wave-5-Tests, Doc-Tests). Laufzeit ~18 s für `security_audit_wave4_traps` enthalten.
* Neu: `tests/security_audit_defensive_wave5.rs` — 7 Tests, alle ok (siehe CI-Log).

## Empfehlungen (defensiv, minimal)

1. `W5-01`-Fix beibehalten; keine weitere Verbreiterung des Dedup-Keys (nur exakt signatur-gebundene Felder).
2. `W5-02`-Gates beibehalten; falls künftig größere Wire-Formate geplant sind, Schwelle zentralisieren (z. B. `const MAX_SHARD_B58_LEN=64`).
3. `W5-04`-Invariante in Architektur-Tests verankern (Bundle mit N≥2 Vouchern, Fehler im N-ten Member).
4. Keine Änderung: `is_init_fingerprint`-Regel (`"none"/"none"` nur) ist kryptografisch minimal und vollständig.

## Anhang — Geänderte Dateien

* `src/services/conflict_manager.rs:902-923` — equivocation-erhaltendes Dedup, `is_exact_duplicate`.
* `src/wallet/conflicts.rs:1377-1391` — gleicher equivocation-erhaltender Fix.
* `src/services/trap_manager.rs:194-213` — Längen-Gate `>64` vor Base58-Decode.
* `src/services/voucher_validation/chain.rs:350-379` — `ds_tag` Base58/32-Byte-Gate vor `validate_shard_structure`.
* `tests/security_audit_defensive_wave5.rs` — 7 reproduzierbare Defensive-Tests (siehe § Validierung).
