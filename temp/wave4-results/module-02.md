# WAVE 4 — Module 02 Results (Phase B: Fail-First TDD Proof)

> Auditor: Wave-4 Phase-B Test-Autor · Datum: 2026-08-26 · Branch: `live`
> Scope: NUR WH4-02-302 und WH4-02-301+WH4-06-704-kombiniert gemäß Koordinator.
> WH4-02-303/304/305 sind dispositioniert und wurden NICHT getestet (keine Tests geschrieben).
> Dateien erstellt: `tests/security_audit_wave4_crypto.rs` + dieser Report. Null Änderungen an src/, bestehenden Dateien oder git-State.

## Results Table

| ID | Result | Testname | Ausschnitt | Fix-Notiz |
|---|---|---|---|---|
| AUDIT-W4-CRY-302 (WH4-02-302, MEDIUM) | **PROVEN** (rot auf ungepatchtem Code, bleibt rot auf aktuellem Baum) | `audit_w4_cry_302_create_secure_container_with_empty_password_must_be_rejected` (tests/security_audit_wave4_crypto.rs:141) | `panicked at tests/security_audit_wave4_crypto.rs:151:5: SECURITY VIOLATION AUDIT-W4-CRY-302: create_secure_container accepted ContainerConfig::Password("") and sealed the payload under PBKDF2-HMAC-SHA512("", salt) — a key every offline scanner can derive in seconds given the public envelope format` | Guard im Password-Zweig von `create_secure_container` (src/services/secure_container_manager.rs:177–198): leeres Passwort vor jeder Verschlüsselung mit typisiertem Fehler ablehnen (z. B. neuer Variant `ContainerManagerError::WeakSecret`), Parität zu HMSEC-SA05-10. Optional Defense-in-Depth: gleicher Guard in `encrypt_symmetric_password` (src/services/crypto_symmetric.rs:206–234), da dort dieselbe Senke für andere Aufrufer offen bleibt. Positiv-Kontrolle (`Password("pin1234")`, Seal+Reopen-Roundtrip) ist im Test eingebaut und muss nach dem Fix grün bleiben. Produktionsaufrufer zur Prüfung: `app_service/standard_container_handler.rs:387`. |
| AUDIT-W4-CRY-301 (+WH4-06-704, MEDIUM) | **PROVEN** (rot auf ungepatchtem Code) + **Hardening-Beweis erbracht** (grün nach Concurrent-Fix) | `audit_w4_cry_301_forged_low_order_epk_container_must_not_decrypt_for_victim` (tests/security_audit_wave4_crypto.rs:186) | Run A (ungepatcht): `panicked at tests/security_audit_wave4_crypto.rs:275:13: SECURITY VIOLATION AUDIT-W4-CRY-301: open_secure_container accepted a container forged under a NON-CONTRIBUTORY (low-order) epk … attacker-chosen payload decrypted as: "{\"forged\":\"ATTACKER-CHOSEN-PAYLOAD\"}"` · Run B (gepatcht): PASS mit Reason-Pinning (`not in the list of recipients`) | Vollständiger Fail-First-Zyklus empirisch belegt: (1) Roter Beweis gegen den Baum VOR dem Fix — minimales SecureContainer-Crafting mit `epk=base64([0u8;32])`, öffentlich berechenbarem KEK=`HKDF-SHA256(b"secure-container-kek",[0u8;32])`, gewrapptem Angreifer-CEK `[42u8;32]`, AEAD-Payload an Protected Header gebunden, konsistentem `i` + gültiger Angreifer-Signatur → `open_secure_container` lieferte den Angreifer-Payload. (2) Ein concurrent akteur hat während Phase B (mtime 2026-08-26 12:39:26) die `was_contributory()`-Guards gelandet (secure_container_manager.rs:106/:130/:326); nach Re-Sync läuft der Test grün — der Decrypt-Pfad-Guard feuert korrekt nach erfolgreichem Header-/Key-Parsing (Error-Reason wird gepinnt, damit der Beweis nicht durch inkidentelle Parse-Fehler entwertet). Der Test bleibt als Regression-Shield permanent in der Suite. Restliches Hardening-Debt aus der Hypothese (nicht fix-kritisch): a) `derive_kek` (:389–395) bindet weder epk noch Empfänger-ID ins HKDF-info (Kontrast: `build_hkdf_info`) — Kontextbindung nachziehen; b) KEK/Shared Secrets im Open-Pfad nicht zeroized (`payload_key` bereits ja); c) Semantikentscheidung dokumentieren: Skip-to-next statt fail-closed ist nur solange harmlos, wie kein zweiter gültiger Empfängereintrag existiert. |

## Empirical Run Log

- **Run A (Pre-Fix-Snapshot):** 2 tests run: 0 passed, 2 failed → beide Findings rot = Beweis. Snapshot enthielt das rohe `recipient_x25519_sk.diffie_hellman(&esk_pub)` ohne Contributory-Check am Decrypt-Pfad (secure_container_manager.rs:315).
- **Run B (aktueller Baum nach Concurrent-Landing der Guards, mtime 12:39:26):** 2 tests run: 1 passed, 1 failed → CRY-301 grün (Fix wirksam, Regression-Shield aktiv), CRY-302 weiterhin rot (ungefixt).

## Execution Environment Note (exact obstacle + resolution)

Der mandatierte Befehl kompiliert in-repo NICHT aus einem vorgelagerten, unabhängigen Grund (identisch zum Modul-06-Befund):

```
error[E0063]: missing field `privacy_guard` in initializer of `L2LockRequest`
   --> src/bin/l2_client_simulator/main.rs:1231:20
```

Cargo baut bei Integrationstests alle Package-Binaries (`CARGO_BIN_EXE_*`), daher blockiert das veraltete Demo-Binary jeden Testlauf. Der Simulator hinkt hinter `L2LockRequest.privacy_guard` her (API-Drift aktueller Security-Fixes, unberührt von dieser Phase).

Verfahren (Präzedenz: temp/wave4-results/module-06.md):
1. In-repo-Compile-Validierung des eigenen Tests: `CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo check --test security_audit_wave4_crypto` → OK, warnungsfrei.
2. Ausführung des mandatierten Befehls exakt wie vorgeschrieben in `/tmp/opencode/hmc-w4-run` — byte-identischer Repo-Copy (sha256-Manifest-Diff über src/tests/bindings/voucher_standards: leer), einziges Delta: `autobins = false` im [package]-Block dieser Kopie (Binaries deaktiviert). Das Repo selbst blieb vollständig unmodifiziert:

```
CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_crypto
```

## Dispositionierte Hypothesen (NICHT getestet, per Koordinator)

- WH4-02-303 (signatures.rs:80 Grammatik-Firewall): dispositioniert — kein Test.
- WH4-02-304 (verify_seal_on_login zirkulärer Trust-Anker): dispositioniert — kein Test.
- WH4-02-305 (hash_to_curve Subgroup-Annahme ungepinnt): dispositioniert — kein Test.
