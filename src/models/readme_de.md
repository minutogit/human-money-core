# Dokumentation: Transaktionsstruktur und Double-Spending-Erkennung

## 1\. Motivation und Designziele

Die Transaktionsstruktur in `human_money_core` wurde entwickelt, um zwei Hauptziele zu erreichen:

- **Interne Integrität:** Die Historie innerhalb einer einzelnen Gutschein-Datei muss fälschungssicher und kryptographisch nachvollziehbar sein.

- **Globale Validierung:** Es muss möglich sein, eine externe (Layer 2) Infrastruktur zur Erkennung von Double-Spending aufzubauen. Dabei sollen die Anonymität der Nutzer und die Details der Gutscheine gewahrt bleiben, aber dennoch eine zeitliche Einordnung von Konflikten möglich sein.

Das Ergebnis ist eine mehrschichtige Sicherheitsarchitektur, die auf einer expliziten kryptographischen Verkettung und einem innovativen, datenschutzfreundlichen Signatur- und Fingerprint-Schema beruht.

-----

## 2\. On-Voucher-Integrität: Die `prev_hash`-Kette

Jede Transaktion ist über das Feld `prev_hash` untrennbar mit ihrem Vorgänger verbunden.

- **Init-Transaktion:** Die allererste Transaktion (`t_type: "init"`) ist ein Sonderfall. Ihr `prev_hash` ist der Hash der finalen `voucher_id` des Gutscheins. Dies verankert die gesamte Transaktionskette fest mit der Identität des Gutscheins.

- **Folgetransaktionen:** Bei jeder weiteren Transaktion ist der `prev_hash` der Hash des gesamten, kanonisch serialisierten Vorgänger-Transaktionsobjekts.

Diese Verkettung stellt sicher, dass die Reihenfolge der Transaktionen nicht unbemerkt verändert und keine Transaktion aus der Mitte entfernt werden kann, ohne die Kette zu brechen.

-----

## 3\. Anatomie einer Transaktion

### Transaction ID (`t_id`)

Jede Transaktion besitzt eine eindeutige `t_id`. Diese wird berechnet, indem das Transaktionsobjekt selbst (mit temporär leeren `t_id`- und `sender_signature`-Feldern) kanonisch serialisiert und gehasht wird. Dies gibt jeder Transaktion eine von ihrem Inhalt abhängige, fälschungssichere Identität.

### Transaction Signature (`sender_signature`)

Die Signatur wurde bewusst vereinfacht, um Redundanz zu vermeiden und die Effizienz zu steigern. Der Zeitstempel `t_time` ist **nicht mehr Teil der Signatur**. Stattdessen wird ein minimales JSON-Objekt signiert:

```json
{
  "prev_hash": "...",
  "sender_id": "...",
  "t_id": "..."
}
```

**Warum ist das sicher?** Da `t_time` bereits Teil der Daten ist, die zur Erzeugung der `t_id` gehasht werden, ist der Zeitstempel durch die Aufnahme der `t_id` in die Signatur **implizit fälschungssicher** mit der Transaktion verbunden. Eine erneute Aufnahme in die Signatur wäre überflüssig.

-----

## 4\. Layer 2: Anonymisierte Double-Spending-Erkennung

Die `human_money_core`-Bibliothek ist so optimiert, dass eine übergeordnete Anwendung eine globale Datenbank zur Betrugserkennung nutzen kann, ohne sensible Daten preiszugeben.

### Das Konzept des "Anonymen Fingerabdrucks"

Um einen Double-Spend global zu erkennen, muss ein Server wissen, ob ein Sender versucht, von demselben Zustand (`prev_hash`) zweimal auszugeben. Um dabei die Anonymität zu wahren, wird ein anonymer "Fingerabdruck" erzeugt.

- **Fingerabdruck-ID:** `prvhash_senderid_hash` = `hash(prev_hash + sender_id)`.
- **Server-Upload:** Ein Client lädt ein **`TransactionFingerprint`**-Objekt an den Server hoch. Es enthält:
  - `prvhash_senderid_hash`: Die anonyme ID des Sendevorgangs.
  - `t_id`: Die ID der spezifischen Transaktion.
  - `sender_signature`: Der kryptographische Beweis.
  - `encrypted_timestamp`: Ein verschlüsselter Zeitstempel.

Der Server kennt weder den `prev_hash` noch die `sender_id` und kann diese auch nicht aus dem Hash zurückrechnen. Er kann also nicht sehen, wer handelt oder von welchem Gutschein die Transaktion stammt.

### Die Innovation: Der verschlüsselte Zeitstempel

Der Schlüssel zur neuen, verbesserten Methode ist der **verschlüsselte Zeitstempel**. Er löst das Dilemma, eine zeitliche Einordnung für Konflikte zu ermöglichen, ohne das Datum an den Server preiszugeben.

- **Verschlüsselung:** Der Zeitstempel (in Nanosekunden) wird mit einem symmetrischen Schlüssel via XOR verschlüsselt:
  `encrypted_nanos = original_nanos ^ schlüssel`

- **Schlüsselableitung:** Der Schlüssel wird deterministisch aus Daten abgeleitet, die nur die Konfliktparteien kennen:
  `schlüssel = hash(prev_hash + t_id)` (bzw. die ersten 128 Bit davon).

- **Datenschutz:** Der Server kann den Zeitstempel **nicht entschlüsseln**, da er weder `prev_hash` noch `t_id` kennt. Für den Server ist es nur eine Zufallszahl.

- **Beweisführung:** Ein Opfer, das einen `ProofOfDoubleSpend` mit zwei widersprüchlichen Transaktionen erhält, besitzt alle nötigen Informationen (`prev_hash`, `t_id_A`, `t_id_B`), um **beide Schlüssel zu rekonstruieren**, die Zeitstempel zu entschlüsseln und sie zu vergleichen.

### Erkennung und Beweisführung (Neues Schema)

Ein Double-Spend hat stattgefunden, wenn der Server einen Fingerprint für einen `prvhash_senderid_hash` erhält, für den bereits ein Eintrag mit einer anderen `t_id` existiert.

- **Alarm:** Der Server schlägt Alarm und sendet den bereits existierenden Fingerprint als Beweis zurück.
- **Lokale Verifizierung:** Der Client des Opfers hat nun zwei widersprüchliche Transaktionen. Er kann:
  1.  Beide Signaturen unabhängig voneinander verifizieren (wie im alten Schema).
  2.  **Neu:** Beide verschlüsselten Zeitstempel entschlüsseln und vergleichen.

Dieser Mechanismus ermöglicht eine dezentrale, fundierte Entscheidung im Konfliktfall, selbst ohne Server-Urteil.

-----

## 5\. Peer-to-Peer-Verbreitung (Gossip-Protokoll)

Neben der zentralisierten Erkennung über einen Layer-2-Server ermöglicht die Architektur eine dezentrale, rein Peer-to-Peer-basierte Verbreitung von Fingerprints. Dies geschieht durch ein "Gossip-Protokoll", bei dem Teilnehmer sich gegenseitig über Transaktionen informieren, die sie beobachtet haben.

Jedes Mal, wenn ein Wallet ein Transaktionsbündel an einen Empfänger sendet, legt es eine Sammlung von bis zu 150 Fingerprints bei, die es für relevant hält. Dieser Prozess ist intelligent gestaltet, um maximale Effizienz zu erreichen.

### Die Intelligente Auswahl (Heuristik)

Die `select_fingerprints_for_bundle`-Methode wählt nicht zufällig aus, welche Fingerprints sie weiterleitet. Sie folgt einer klaren Heuristik, um die nützlichsten Informationen zu verbreiten:

- **Priorisierung nach Relevanz (`depth`):** Jeder Fingerprint hat eine "Tiefe" (`depth`), die angibt, wie viele Stationen (Hops) er bereits durchlaufen hat. Die Auswahl-Logik bevorzugt immer Fingerprints mit der niedrigsten `depth` (beginnend bei 0). Das sorgt dafür, dass neue, "frische" Informationen sich am schnellsten im Netzwerk verbreiten.

- **Vermeidung von Redundanz (`known_by_peers`):** Das Wallet merkt sich für jeden Fingerprint, welchen Peers es diesen bereits gesendet hat. Vor dem Senden prüft es, ob der aktuelle Empfänger den Fingerprint schon kennt. Wenn ja, wird er übersprungen. Dies verhindert unnötigen Datenverkehr und Endlosschleifen.

- **"Gieriges" Füllen des Kontingents:** Das Protokoll versucht immer, das Kontingent von 150 Fingerprints zu füllen. Wenn nicht genügend Fingerprints mit niedriger `depth` verfügbar sind, werden auch solche mit höherer `depth` ausgewählt. Dies maximiert den Informationsaustausch bei jeder Transaktion.

### Die Verarbeitung (Min-Merge-Regel)

Wenn ein Wallet ein Bündel mit Fingerprints empfängt, verarbeitet es diese nach einer einfachen, aber effektiven Regel:

1.  Die `depth` jedes empfangenen Fingerprints wird um 1 erhöht (für den "Hop" vom Sender).
2.  Das Wallet vergleicht diese neue, empfangene `depth` mit dem `depth`-Wert, den es eventuell bereits für denselben Fingerprint lokal gespeichert hat.
3.  Es wird immer der **niedrigere (bessere) Wert beibehalten**.

Diese "Min-Merge-Regel" stellt sicher, dass sich im Netzwerk immer die Information über den kürzesten Pfad zur ursprünglichen Transaktion durchsetzt.

### Effizienz und Funktionsweise

Das Protokoll ist aus mehreren Gründen effizient:

- Es erzeugt keinen zusätzlichen Netzwerkverkehr, da die Fingerprints an reguläre Transaktionen "angehängt" (piggybacked) werden.
- Es vermeidet durch die `known_by_peers`-Logik die redundante Verbreitung von Informationen.

Durch diesen Mechanismus entsteht ein "Informations-Immunsystem": Kritische Informationen, insbesondere über Double-Spending-Versuche, verbreiten sich als natürlicher Nebeneffekt der normalen Systemnutzung schnell und organisch im gesamten Netzwerk.

-----

## 6\. Konfliktlösung: Die Geteilte Strategie (Offline vs. Layer 2)

Die Reaktion des Wallets auf einen `ProofOfDoubleSpend` wurde verbessert und hängt davon ab, ob ein autoritatives Urteil eines L2-Servers vorliegt.

### Szenario A: Reine Offline-Erkennung (Heuristik: "Der Frühere gewinnt")

Dies ist der neue Standardfall, wenn ein Wallet einen Konflikt lokal feststellt (z.B. durch Austausch von Fingerprints mit einem Peer), ohne ein Server-Urteil zu haben.

- **Warum diese Strategie?** Dank des verschlüsselten Zeitstempels ist eine "Maximale Vorsicht" (alles einfrieren) nicht mehr nötig. Der Client kann eine informierte, deterministische Entscheidung treffen.

- **Aktion des Wallets:**

  1.  Das Wallet entschlüsselt die Zeitstempel beider widersprüchlicher Transaktionen.
  2.  Der Gutschein-Zweig mit der Transaktion, die den **früheren Zeitstempel** hat, wird als wahrscheinlich legitim angesehen und bleibt `Active`.
  3.  Der Gutschein-Zweig mit der Transaktion, die den **späteren Zeitstempel** hat, wird auf `VoucherStatus::Quarantined` gesetzt.

Diese Heuristik bietet eine pragmatische Lösung, die den Gutschein nutzbar hält und gleichzeitig vor der offensichtlich betrügerischen (späteren) Transaktion schützt.

### Szenario B: Layer-2-gestützte Lösung (Autoritatives Urteil)

Dieser Fall tritt ein, wenn das Wallet einen `ProofOfDoubleSpend` verarbeitet, der ein signiertes `Layer2Verdict` enthält. **Das Urteil des Servers hat immer Vorrang vor der lokalen Zeitstempel-Heuristik.**

- **Warum diese Strategie?** Das Urteil des Servers stellt eine "höhere Wahrheit" dar. Da der Server die Fingerprints in einer global geordneten Reihenfolge empfängt ("First-Come, First-Served"), kann er autoritativ festlegen, welche Transaktion zuerst da war.

- **Aktion des Wallets:**

  1.  Das Wallet verifiziert die Signatur des `Layer2Verdict`.
  2.  Der Gutschein-Zweig, der die laut Urteil **gültige** Transaktion enthält, wird `Active` gesetzt (oder aus der Quarantäne reaktiviert).
  3.  Der Gutschein-Zweig, der die **ungültige** Transaktion enthält, wird auf `VoucherStatus::Quarantined` gesetzt.
  4.  **Zusätzlich** wird für den ungültigen Zweig eine **Sperr-Transaktion** (`t_type: "block"`) vorbereitet, um diesen Zweig permanent und "on-chain" als Endpunkt zu markieren.

### Fazit

Das System kombiniert eine robuste, interne Kettenlogik mit einem fortschrittlichen, datenschutzfreundlichen Fingerprint-Mechanismus. Es operiert standardmäßig in einem sicheren Offline-Modus mit einer intelligenten Heuristik und kann nahtlos auf einen Modus der autoritativen Sicherheit umschalten, sobald höherwertige Informationen eines Layer-2-Dienstes verfügbar sind.