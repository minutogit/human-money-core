---
creation date: 2026-02-21 14:15
modification date: 2026-02-21
tags:
  - human-money-core
  - layer-2
  - sync
  - protocol
---
# 05. Layer-2 Synchronisation

**Kontext:** Teil 5 der Human Money Core Spezifikation.

## Architekturspezifikation: Hocheffizientes Layer-2 Synchronisationsprotokoll

Dieses Dokument beschreibt das Kommunikationsprotokoll zwischen dem `human_money_core` Client (Wallet) und dem Layer-2-Netzwerk (L2-Gateway). Es spezifiziert, wie Zustandsabgleiche (State Reconciliation) und die Verifizierung von Transaktionen durchgeführt werden, um maximale Skalierbarkeit und Sicherheit zu gewährleisten.

## 1. Kontext und Problemstellung

### Das System-Design
Das Human Money (HuMoCo) Ökosystem basiert auf dezentralen, elektronischen Gutscheinen. Jeder Gutschein trägt seine eigene Transaktionshistorie in sich. Das System nutzt ein UTXO-Modell (Unspent Transaction Output). Wenn ein Gutschein geteilt wird (Split), verzweigt sich die Historie. Daraus entsteht ein gerichteter azyklischer Graph (DAG), ähnlich einem Baum, der in einer `genesis_id` wurzelt.

### Das Layer-2 (L2) Netzwerk
Um "Double Spends" (das mehrfache Ausgeben desselben Gutscheinwerts) zu verhindern, existiert ein Layer-2-Netzwerk. Dieses fungiert als globale, kryptografische Pinnwand. Es speichert keine ökonomischen Daten (keine Beträge, keine Namen), sondern vermerkt lediglich, ob ein bestimmter kryptografischer Anker (der `ds_tag` / Double-Spend-Tag) bereits verbraucht wurde und mit welcher Transaktion (`t_id`) dies geschah.

### Identifikatoren: Voucher ID vs. L2 Voucher ID
Ein kritischer Aspekt für die Performance ist die Adressierung eines Gutscheins auf dem Layer 2:
*   **Voucher ID (L1):** Die vom Client genutzte, oft Base58-kodierte ID zur Identifikation des Gutscheins in der Wallet.
*   **L2 Voucher ID (L2):** Eine für das Layer-2-Netzwerk optimierte ID (in der Regel ein Hex-kodierter SHA-256 Hash der Genesis-Daten). Sie dient als primärer Index für den Bloom-Filter und die Gruppierung von Locks im L2-State.
    *   *Beispiel:* `bd3a81285da197b6189a2df41614cb29c52439c6a51604662f8f613ecbe7485d`

### Das Kernproblem: Informationsasymmetrie & State Reconciliation
*   **Der Client (Smart Client):** Ein Nutzer, der einen Gutschein erhält, kennt systembedingt nur seinen eigenen, spezifischen Pfad von der Genesis-Transaktion bis zu seinem aktuellen Blatt. Er kennt nicht die Äste anderer Nutzer.
*   **Der Server (L2 Node):** Der Server kennt idealerweise den globalen Zustand (den gesamten Baum) aller bisher gemeldeten Transaktionen dieses Gutscheins.
*   **Die Herausforderung:** Wenn der Client nach einer Offline-Phase online geht oder einen fremden Gutschein verifizieren will, müssen Client und Server ihren Zustand abgleichen. Der Server muss effizient den letzten gemeinsamen Knoten (Last Common Ancestor) finden, um dem Client mitzuteilen, welche Transaktionen ihm noch fehlen.

## 2. Die Lösung: Die "Dumb Server, Smart Client" Architektur

Nach der Evaluierung komplexer algorithmischer Verfahren wurde für HuMoCo ein asymmetrisches Design gewählt.

**Die Leitprämisse:** Der Server muss so "dumm" und schnell wie möglich sein. Seine Operationen müssen im Idealfall eine Komplexität von $O(1)$ haben (z.B. simple Datenbank-Lookups). Der Client übernimmt die logische Arbeit und bereitet Anfragen so vor, dass der Server sie ohne Suchaufwand beantworten kann.

Das Protokoll nutzt vier Kerntechnologien, um dies zu erreichen:

### A. Der RAM-basierte Bloom-Filter (Der Türsteher)
Der L2-Server hält alle ihm bekannten L2 Voucher IDs in einem extrem kompakten In-Memory Bloom-Filter. Bevor der Server für eine Anfrage überhaupt die Festplatte oder Datenbank berührt, fragt er den Bloom-Filter. Antwortet dieser mit "Nein", wird die Anfrage sofort in Nanosekunden abgewiesen. Dies schützt die Datenbank effektiv vor Brute-Force-Angriffen mit zufälligen Hashes.

### B. Logarithmische Locators (Die smarten Brotkrumen)
Wenn der Client seinen Zustand abfragt, sendet er nicht seinen gesamten Pfad mit, sondern eine exponentiell ausgedünnte Liste von Vorgänger-Hashes (Brotkrumen), rückwärts zählend von seinem aktuellen Blatt.
*   *Beispiel (Tiefe 100):* Der Client sendet die Hashes der Tiefen `[100, 99, 98, 96, 92, 84, 68, 36, Genesis]`.
*   Die Dichte ist dort am höchsten, wo eine Abweichung am wahrscheinlichsten ist (an der Spitze). Der Server muss maximal diese handvoll Hashes in seiner Datenbank abfragen ($O(1)$), um den Einstiegspunkt für eine Synchronisation zu finden.

### C. 10-Zeichen Base58 Prefixing (Pragmatische Kompression)
Um Bandbreite zu sparen und die Komplexität auf Server-Seite (Index-Suche) zu minimieren, nutzt das Protokoll Präfixe der Base58-kodierten Hashes.
*   **Logik:** Der Client nimmt den Base58-String eines `ds_tag` und kürzt diesen auf die ersten 10 Zeichen.
*   **Sicherheit:** 10 Zeichen in Base58 bieten ca. 58,5 Bits Entropie. Da die Suche immer auf einen spezifischen Gutschein (L2 Voucher ID) eingeschränkt ist, ist die Wahrscheinlichkeit einer Kollision vernachlässigbar klein.
*   **Effizienz:** Der Server kann diese Präfixe direkt für String-basierte Index-Scans (z. B. `LIKE 'Prefix%'`) nutzen, ohne Binärumwandlungen vornehmen zu müssen. Nur der eigentliche Ziel-Hash (Challenge) bleibt als vollständiger Base58-String erhalten.

### D. Trustless Verification durch kryptografische Bindung
Ein bösartiger Server könnte versuchen, einen Client zu täuschen, indem er behauptet, für einen `ds_tag` sei eine andere `t_id` eingetragen, um so fälschlicherweise einen Double-Spend-Alarm auszulösen.

Um dies auszuschließen, nutzt HuMoCo eine strikte kryptografische Bindung (Signature Hardening):
*   **Proof of Truth:** Wenn der Server meldet, dass ein Tag vergeben ist, muss er den vollständigen `L2LockEntry` (inklusive der `layer2_signature`) mitsenden.
*   **Payload-Bindung:** Die Signatur des Nutzers (`layer2_signature`) sichert nicht nur die `t_id`, sondern bindet diese untrennbar an die `layer2_voucher_id` und den `challenge_ds_tag`.
*   **Hashing-Logik:** Der Client serialisiert die Felder strikt in der folgenden Reihenfolge (kodiert als rohe Bytes, gehashed mit SHA-256):
    1. `challenge_ds_tag` (als Bytes)
    2. `layer2_voucher_id` (als Bytes)
    3. `transaction_hash / t_id` (32 Bytes Array)
    4. `sender_ephemeral_pub` (32 Bytes Array)
    5. `receiver_ephemeral_pub_hash` (Optional, 32 Bytes Array)
    6. `change_ephemeral_pub_hash` (Optional, 32 Bytes Array)
    7. `deletable_at` (Optional, als Bytes)
*   Da der Server die Signatur des Nutzers über diesen spezifischen Payload unmöglich fälschen kann, dient der zurückgelieferte Eintrag als unumstößlicher Beweis.
*   **Schutz vor Mix-up:** Ein Server kann keinen gültigen Beweis eines anderen Gutscheins oder eines anderen Tags "umbiegen", da die IDs fest im signierten Hash verankert sind.

### E. Authentizität des L2-Servers (Server Signatures)
Um zu verhindern, dass ein böswilliger Akteur gefälschte Verifizierungen sendet, nutzt das Protokoll eine zusätzliche Authentifizierungsebene:
*   **L2ResponseEnvelope:** Jede Antwort des Servers (`L2Verdict`) wird in einen Briefumschlag (Envelope) verpackt, der eine Ed25519-Signatur des Servers trägt. Dies gilt auch für Fehler oder Synchronisationspunkte.
*   **Vertrauensanker:** Das Wallet verfügt über den konfigurierten `l2_server_pubkey`.
*   **Verifizierung:** Bevor ein Client das Urteil verarbeitet, bildet er den SHA-256 Hash der serialisierten `verdict` JSON-Daten. Anschließend validiert er die Server-Signatur (`server_signature`) des Envelopes mit diesem Hash. Nur bei erfolgreicher Authentizität wird das Urteil akzeptiert.

## 3. Datenstrukturen und API-Payloads

Die Kommunikation zwischen Wallet und L2-Node findet standardmäßig mittels JSON-kodierten Nachrichten (oft transportiert über QUIC oder HTTP/2) statt. Kryptografische Keys und Hashes (Ed25519, SHA-256) werden im L2 Netzwerk, sofern in JSON eingebettet, konsequent in **Base58**-String-Repräsentation (oder seltener als hexadezimaler String für die `layer2_voucher_id`) gesendet, um Interoperabilität zu gewährleisten.

### L2LockRequest (Zustand anmelden)
Dieser Payload wird vom Client gesendet, um eine neue Transaktion (oder Genesis) auf der L2-Node zu registrieren ("locken").

```json
{
  "auth": {
    "ephemeral_pubkey": "FR2Q... (Base58, 32 Bytes)",
    "auth_signature": null
  },
  "layer2_voucher_id": "bd3a81285da197b...", // Hex-kodiert
  "ds_tag": "9aXv2Mqn8b... (Base58)", // null bei Genesis-Locks
  "transaction_hash": "3J98... (Base58, 32 Bytes)",
  "is_genesis": false,
  "sender_ephemeral_pub": "5Qx1... (Base58, 32 Bytes)",
  "receiver_ephemeral_pub_hash": "7mY2... (Base58, 32 Bytes)", // optional
  "change_ephemeral_pub_hash": null, // optional
  "layer2_signature": "At92... (Base58, 64 Bytes)",
  "deletable_at": null // optional
}
```

### L2StatusQuery (Zustand abfragen)
Mit dieser Payload fragt das Wallet den Status eines spezifischen Tags ab. Optional schickt es Locator-Brotkrumen für effiziente Missing-Locks-Suchen.

```json
{
  "auth": {
    "ephemeral_pubkey": "FR2Q...",
    "auth_signature": null
  },
  "layer2_voucher_id": "bd3a81285da197b...",
  "challenge_ds_tag": "abC8xY...", // Der zu prüfende Tag in voller Base58 Länge
  "locator_prefixes": [
    "3J98t1Wp9a", // Base58 (erste 10 chars)
    "9aXv2Mqn8b",
    "GenesisPre"
  ]
}
```

### L2ResponseEnvelope & L2Verdict (Antwort des Servers)
Dies ist die generische Hülle (`Envelope`), die für **jede** Serverantwort genutzt wird. Das `verdict` unterscheidet den genauen Status.

```json
{
  "verdict": {
    "type": "Verified",
    "lock_entry": {
      "layer2_voucher_id": "bd3a81285da1...",
      "t_id": "3J98... (Base58)",
      "sender_ephemeral_pub": "5Qx1... (Base58)",
      "receiver_ephemeral_pub_hash": "7mY2...",
      "change_ephemeral_pub_hash": null,
      "layer2_signature": "At92...",
      "deletable_at": null
    }
  },
  "server_signature": "ZZ88... (Base58, 64 Bytes)"
}
```

Mögliche `type`-Werte für `verdict`:
- `Verified`: Bestätigung eines erfolgreichen oder bereits gesetzten Locks. Gibt stets den vollständigen `lock_entry` zurück.
- `MissingLocks`: Server fordert Synchronisation ab dem genannten `sync_point`.
- `UnknownVoucher`: Gutschein ist der L2-Node komplett unbekannt.
- `Rejected`: Fehlerhafte Anfrage (z.B. Signaturprüfung fehlgeschlagen).

Ein ausführliches, lauffähiges Code-Beispiel einer Mock L2-Node findet sich unter [`examples/l2_mock_node.rs`](../../../../examples/l2_mock_node.rs).

## 4. Die Workflows (Szenarien)

Das Zusammenspiel dieser Komponenten zeigt sich in vier maßgeblichen Workflow-Szenarien.

### Szenario 1: Der "Happy Path" (Prüfung eines gültigen Gutscheins)
*   **Kontext:** Ein Nutzer empfängt einen Gutschein (Tiefe 10) und möchte vor der Annahme prüfen, ob dieser manipulationsfrei und als "nicht ausgegeben" auf L2 gelockt ist.
*   **Client sendet `L2StatusQuery`:**
    *   `l2_voucher_id`: Der Hex-String (z.B. `bd3a81...`)
    *   `challenge_ds_tag`: Der vollständige Base58-String des Tags von Tiefe 10.
    *   `locator_prefixes`: `["3J98t1Wp9a", "9aXv2Mqn8b", ...]` (Jeweils die ersten 10 Zeichen der Vorgänger-Hashes).
*   **Server arbeitet ($O(1)$):**
    1.  Prüft den Bloom-Filter für die `l2_voucher_id`. Ergebnis: Treffer.
    2.  Sucht in der Key-Value DB nach dem `challenge_ds_tag`. Ergebnis: Nicht gefunden (im Sinne von "noch nicht ausgegeben/neu"). *(Anmerkung: Wenn als "nicht ausgegeben" zu verifizieren: Tag der eingehenden Tx sollte noch kein Lock haben, oder die Applikationslogik lockt ihn in dem Moment.) Im Originalbeispiel sucht er den Tag. Wenn der Tag der vorherigen Tx gesucht wird und dort unsere Tx lockt, ist es "Verified".* Im Betrugsfall wird er mit einer **anderen** Tx gefunden. Wenn vom Server gemeldet wird, der aktuelle eigene wird verriegelt, antwortet er entsprechend.
    *(Korrektur laut Vorgabe - wenn der Gutschein schon gesichert wurde)*: Sucht in der Key-Value DB nach dem `challenge_ds_tag`. Ergebnis: Gefunden.
*   **Server antwortet:** `L2ResponseEnvelope` (Beinhaltet das signierte `L2Verdict::Verified { lock_entry }` oder initial ein `L2Verdict::Ok`).
*   **Client verifiziert:**
    1.  **Server-Authentizität:** Er prüft die Signatur des Envelopes gegen den `l2_server_pubkey`.
    2.  **Nutzer-Beweis:** Er prüft die Signatur des `lock_entry` mathematisch gegen den rekonsituierten Payload (Härtung).
    3.  **T_ID Check:** Er vergleicht die `t_id` aus dem Eintrag mit seiner lokalen `t_id`. Stimmen sie überein, ist die Zahlung garantiert sicher, da der Client nun den Beweis hat, dass seine Transaktion als der offizielle und einzig gültige Lock im L2-Netzwerk verankert ist.

### Szenario 2: Die Offline-Synchronisation (Client ist dem Server voraus)
*   **Kontext:** Der Nutzer hat den Gutschein offline mehrfach weitergegeben. Der Client hat nun den Stand Tiefe 10, aber das L2-Netzwerk kennt bisher nur den Stand bis Tiefe 7.
*   **Client sendet `L2StatusQuery`:** Wie im Happy Path beschrieben.
*   **Server arbeitet:**
    1.  Bloom-Filter: Treffer.
    2.  Sucht den Ziel-Hash (Tiefe 10) in der DB. Ergebnis: Nicht gefunden.
    3.  Der Server iteriert durch die `locator_prefixes`: Kennt Tiefe 9? Nein. Kennt Tiefe 8? Nein. Kennt Tiefe 6? Ja!
*   **Server antwortet:** `L2ResponseEnvelope` mit `L2Verdict::MissingLocks { sync_point: "3J98t1Wp9a" }`.
*   **Client arbeitet (Batch-Erstellung):**
    *   Der Client weiß nun genau: "Der Server kennt den Pfad bis Tiefe 6. Ich muss ihm nur die Transaktionen 7, 8, 9 und 10 schicken." Er formt einen `L2BatchLockRequest` mit den Payload-Daten dieser vier Transaktionen.
*   **Server verarbeitet Batch:** Der Server führt die UTXO-Checks und Krypto-Signaturprüfungen für die Transaktionen 7 bis 10 sequenziell durch und speichert sie in der DB. Er antwortet mit `Success`.

### Szenario 3: Erkennung eines Double-Spends (Der Betrugsfall)
*   **Kontext:** Ein Betrüger hat die Transaktion an Tiefe 4 zweifach ausgegeben (Tiefe 5A an Opfer 1, Tiefe 5B an Opfer 2). Der Betrüger hat Tiefe 5B bereits online im L2 gelockt. Unser Client (Opfer 1) fragt nun Tiefe 5A ab.
*   **Client (Opfer 1) sendet `L2StatusQuery`:**
    *   `challenge_ds_tag`: Der Tag aus Tiefe 5A.
*   **Server arbeitet:**
    *   Sucht den `challenge_ds_tag` in der DB. Ergebnis: Gefunden! (Der Tag ist bereits mit Transaktion 5B belegt).
*   **Server antwortet:** `L2ResponseEnvelope` mit `L2Verdict::Verified { lock_entry }`.
*   **Client verifiziert & blockiert:**
    1.  Der Client validiert die `layer2_signature` aus dem gesendeten `lock_entry`. Da sie gültig ist, ist bewiesen, dass der Server nicht lügt.
    2.  Der Client vergleicht die vom Server erhaltene `t_id` (5B) mit seiner lokalen `t_id` (5A).
    3.  Mismatch! Der Client hat soeben den unumstößlichen, kryptografischen Beweis erhalten, dass dieser Gutschein vom Vorgänger mehrfach ausgegeben wurde.
    4.  Das Wallet lehnt die Transaktion ab und setzt den Gutschein in Quarantäne.

### Szenario 4: Erstmaliges Eintragen (Genesis-Registrierung)
*   **Kontext:** Ein komplett neu und offline erstellter Gutschein soll das erste Mal auf L2 verankert werden.
*   **Client sendet `L2StatusQuery`:**
    *   `l2_voucher_id`: Der Hex-String.
    *   `challenge_ds_tag`: Tiefe 1.
    *   `locator_prefixes`: `["GenesisPre"]`.
*   **Server arbeitet:**
    *   Prüft den Bloom-Filter für die `l2_voucher_id`. Ergebnis: Kein Treffer.
*   **Server antwortet:** `L2ResponseEnvelope` mit `L2Verdict::UnknownVoucher`
*   **Client arbeitet (Initialer Upload):** Der Client weiß, dass der Gutschein global unbekannt ist und lädt die Kette ab Genesis hoch. Der Server trägt die `l2_voucher_id` nach dem ersten validen Genesis-Lock in den Bloom-Filter ein.
*   **Client arbeitet (Initialer Upload):**
    *   Der Client prüft die Signatur des Envelopes gegen den `l2_server_pubkey`.
    *   Der Client weiß, dass der Gutschein global unbekannt ist und lädt die Kette ab Genesis hoch. Der Server trägt die `l2_voucher_id` nach dem ersten validen Genesis-Lock in den Bloom-Filter ein.

## 4. Zusammenfassung der Architektur-Vorteile

Durch dieses Design erreicht `human_money_core` eine perfekte Symbiose aus Dezentralität und Performanz:
*   **Maximale Serversicherheit:** Der L2-Server ist immun gegen Spam-Angriffe, da er unbekannten "Müll" via Bloom-Filter abweist.
*   **O(1) Skalierbarkeit:** Der Server benötigt unabhängig von der Baumtiefe nur eine Handvoll Index-Abfragen.
*   **Vollständige Krypto-Gewissheit:** Die Rückgabe von vollständig signierten Lock-Einträgen in Kombination mit der Server-Signatur des Envelopes entzieht sowohl L2-Nodes als auch Angreifern jegliche Möglichkeit, Daten zu manipulieren oder Double-Spends vorzutäuschen.
*   **Entwicklerfreundlichkeit:** Durch die Nutzung von 10-Zeichen Base58-Präfixen bleibt das Protokoll für Menschen lesbar, einfach zu debuggen und hochperformant in der Datenbank-Suche. Die Trennung in eine hex-basierte `L2 Voucher ID` sorgt für optimale Datenbank-Indizierung.
