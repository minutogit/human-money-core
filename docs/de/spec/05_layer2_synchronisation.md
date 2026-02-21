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

### D. Trustless Verification durch vollständige Lock-Einträge
Ein bösartiger Server könnte versuchen, einen Client zu täuschen, indem er behauptet, für einen `ds_tag` sei eine andere `t_id` eingetragen, um so fälschlicherweise einen Double-Spend-Alarm auszulösen.
*   Um das auszuschließen, reicht es nicht aus, dass der Server nur die `t_id` zurückgibt. Wenn der Server meldet, dass ein Tag vergeben ist, muss er den gesamten Lock-Eintrag (inklusive der `layer2_signature`) als Antwort mitsenden. 
*   Da der L2-Server die Signatur des Nutzers mathematisch unmöglich fälschen kann, dient die vom Server zurückgelieferte Signatur als unumstößlicher Beweis, dass der Server nicht lügt.

### E. Authentizität des L2-Servers (Server Signatures)
Um zu verhindern, dass ein böswilliger Akteur (oder ein Man-in-the-Middle) gefälschte Verifizierungen oder Double-Spend-Warnungen sendet, nutzt das HuMoCo-Protokoll eine zusätzliche Authentifizierungsebene:
*   **L2ResponseEnvelope:** Jede Antwort des Servers (das `L2Verdict`) wird in einen Briefumschlag (Envelope) verpackt, der eine kryptografische Signatur des Servers trägt.
*   **Vertrauensanker:** Der Client (Wallet) verfügt über einen lokal konfigurierten öffentlichen Schlüssel des vertrauenswürdigen L2-Servers (`l2_server_pubkey`). 
*   **Verifizierung:** Bevor ein Client das Urteil (`L2Verdict`) verarbeitet, validiert er die Signatur des Envelopes. Nur wenn die Authentizität des Servers gewährleistet ist, wird das Urteil akzeptiert.

## 3. Die Workflows (Szenarien)

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
*   **Server antwortet:** `L2ResponseEnvelope` (Beinhaltet das signierte `L2Verdict::Verified { lock_entry }`).
*   **Client verifiziert:**
    1.  **Server-Authentizität:** Er prüft die Signatur des Envelopes gegen den `l2_server_pubkey`.
    2.  **Nutzer-Beweis:** Er prüft die Signatur des `lock_entry` (Nutzer-Signatur). Ist sie gültig, sagt der Server die Wahrheit.
    3.  **T_ID Check:** Danach vergleicht er die `t_id` aus dem Eintrag mit der `t_id` seiner lokalen Gutschein-Datei. Stimmen sie überein, ist die Zahlung garantiert sicher.

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
