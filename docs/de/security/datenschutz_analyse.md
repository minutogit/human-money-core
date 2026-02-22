# Datenschutz-Analyse und Privacy-Modi

Dieses Dokument beschreibt die systematische Analyse der Datenschutz-Modi ("Privacy Modes") in `human-money-core`. Da Privatsphäre ein Kernversprechen des Systems ist, müssen die Regeln für die verschiedenen Modi rigoros definiert und validiert werden.

## Übersicht der Modi

Das System unterstützt drei Modi für Transaktionen:

1.  **Public**: Vollständig transparente Zahlungen (z.B. Spenden, öffentliche Kassen). Sender und Empfänger sind identifiziert.
2.  **Private**: Private Zahlungen. Der Sender ist für Außenstehende nicht erkennbar (keine `sender_id`), die Verbindung ist kryptographisch verschleiert.
3.  **Flexible**: Mischform, bei der bestimmte Identitätsmerkmale weggelassen werden können.

## Zustands-Matrix (State Transition Analysis)

Um logische Lücken zu vermeiden, definieren wir eine Wahrheitstabelle für die Validierungslogik. Diese Tabelle diktiert, welche Kombinationen von Feldern in welchem Modus erlaubt (`MUSS`, `DARF NICHT` = VERBOTEN, `Optional`) sind.

| Feld / Modus | Public | Private | Flexible |
| :--- | :--- | :--- | :--- |
| `sender_id` (Absender-ID) | **MUSS** vorhanden sein | **VERBOTEN** (Muss `None` sein) | Optional |
| `sender_sig` (Identitäts-Signatur) | **MUSS** (implizit via Signatur-Check) | **VERBOTEN** | Wenn ID fehlt: **VERBOTEN** |
| `trap_data` (Double-Spend Schutz) | Optional | **MUSS** (Konzeptionell)* | Optional |
| `recipient_id` (Empfänger) | Format: `did:...` | Format: Hash / Nicht-DID | Format: Egal |
| `ds_tag` (Kontext-Bindung) | **MUSS** korrekt berechnet sein | **MUSS** korrekt berechnet sein | **MUSS** korrekt berechnet sein |

*> Anmerkung: Aktuell ist `trap_data` im Code technisch optional, sollte aber für Private-Sicherheit erzwungen werden, um Double-Spends ohne Identität zu verhindern.*

### Kritische Invarianten

Unabhängig vom Modus gelten folgende Invarianten, die *niemals* verletzt werden dürfen:

1.  **Context Binding**: Wenn `trap_data` vorhanden ist, **MUSS** der `ds_tag` kryptographisch an die aktuelle Transaktion (via `prev_hash` + `ephemeral_pub`) gebunden sein. Dies verhindert Replay-Attacken, bei denen Trap-Daten aus einer anderen Transaktion kopiert werden.
2.  **Identity Consistency**: Wenn keine `sender_id` da ist, darf auch keine Signatur da sein, die auf eine ID verweist.

## Risiko-Analyse: TrapData im Private Mode

Ein identifizierter kritischer Pfad ist die Interaktion von *TrapData* (dem Mechanismus zur Verhinderung von Double-Spending ohne Identitäts-Enthüllung) und dem *Private Mode*.

### Das Problem (The Gap)
In früheren Versionen oder naiven Implementierungen besteht die Gefahr, dass Validierungslogik übersprungen wird, wenn Daten fehlen.

*   **Szenario:** Ein Angreifer sendet eine Private-Transaktion (`sender_id = None`) mit manipulierten Trap-Daten.
*   **Gefahr:** Wenn die Prüfung `verify_trap` nur ausgeführt wird `if let Some(id) = sender_id`, wird sie im Private Mode übersprungen. Der Angreifer könnte invalide Trap-Daten senden, das System akzeptiert sie, und der Double-Spend-Schutz greift nicht.

### Die Lösung (Hardening)
1.  **Globales Context Binding:** Der `ds_tag` Check (Zeile ~761 in `voucher_validation.rs`) wird *immer* ausgeführt, wenn Trap-Daten da sind, unabhängig von der `sender_id`.
2.  **Strikte Matrix:** Tests müssen sicherstellen, dass die oben definierte Matrix vollständig abgedeckt ist (siehe `TEST_STRATEGY.md`).

## Offene Punkte & Verbesserungen

- [ ] **Enforcement:** Sollte `trap_data` im Private Mode explizit zur Pflicht gemacht werden? Aktuell erlaubt der Code Private ohne Trap (reiner Transfer ohne DS-Schutz?).
- [ ] **ZKP Verifizierung ohne ID:** Prüfen, wie der Zero-Knowledge-Proof (ZKP) im Trap verifiziert werden kann, wenn kein Public Key (`sender_id`) bekannt ist. (Eventuell gegen `ephemeral_pub`?).
