# Konfliktmanagement-Strategie

Dieses Dokument beschreibt die Strategie des Systems zur Handhabung von Double-Spend-Konflikten. Die Strategie kombiniert automatisierte, kryptographisch gesicherte Prozesse innerhalb der Wallet-Software mit klaren, nutzergeführten sozialen Lösungswegen.

Das Kernprinzip des Systems ist nicht die Unmöglichkeit von Betrug (was in einem dezentralen Offline-System nicht zu garantieren ist), sondern die garantierte Erkennung und unwiderlegbare Nachweisbarkeit jedes Betrugsversuchs.

## 1. Technische Erkennung und automatische Lösung (Offline-First)

Die technische Handhabung eines Konflikts findet vollständig innerhalb der human_money_core-Bibliothek statt, sobald ein Nutzer ein neues Transaktions-Bundle empfängt.

### 1.1. Der Prozess im Wallet

Konflikterkennung: Nach dem Empfang eines neuen Gutscheins scannt das Wallet seinen gesamten Bestand an Transaktionen. Es erzeugt für jede Transaktion einen anonymisierten Fingerabdruck. Ein Konflikt wird erkannt, wenn zwei oder mehr Transaktionen vom selben Ursprung (prev_hash und sender_id) abstammen, aber unterschiedliche Ziele haben.

Automatische Offline-Lösung: "Earliest Wins"-Heuristik
Da das Wallet offline agiert und keine externe Wahrheit kennt, wendet es eine strikte, deterministische Regel an:

Es entschlüsselt die kryptographisch gesicherten Zeitstempel der widersprüchlichen Transaktionen.

Die Transaktion mit dem früheren Zeitstempel wird als gültig eingestuft. Die zugehörige Gutschein-Instanz im Wallet erhält den Status Active.

Die Transaktion mit dem späteren Zeitstempel wird als Betrugsversuch gewertet. Die zugehörige Instanz wird unter Quarantäne gestellt (Quarantined) und ist somit wertlos und unbrauchbar.

Beweissicherung: Gleichzeitig generiert das Wallet einen kryptographisch signierten Betrugsbeweis (ProofOfDoubleSpend). Dieses Dokument enthält die IDs des Täters und des Entdeckers sowie die beiden widersprüchlichen Transaktionen. Es ist der fälschungssichere Beleg des Vorfalls.

### 1.2. Ergebnis für den Nutzer

Am Ende dieses automatischen Prozesses hat der Nutzer, dessen Wallet den Konflikt entdeckt hat:

Eine klare Trennung in einen gültigen und einen ungültigen Gutschein.

Einen exportierbaren, unwiderlegbaren Beweis des Betrugsversuchs.

## 2. Praktische Konfliktlösung durch den Nutzer

Nachdem die Technik ihre Arbeit getan hat, beginnt der soziale Prozess. Die App muss den Nutzer befähigen, den Konflikt zu lösen. Der Entdecker des Betrugs ist dabei der "Auditor", der die Aufklärung anstößt. Der wirtschaftlich Geschädigte ist die Person in der Kette, die für den nun wertlosen Gutschein eine Leistung erbracht hat.

Eine App sollte dem Nutzer basierend auf dem ProofOfDoubleSpend die Beteiligten (Täter, Haftungskette) transparent aufzeigen und ihm die Wahl zwischen zwei Lösungswegen lassen:

### Weg A: Die lückenlose Haftungskette (Der transparente, "gerechte" Weg)

Dieser Weg zielt auf maximale Transparenz und die Stärkung des sozialen Drucks ab.

Rückverfolgung: Der Entdecker des Betrugs konfrontiert die Person, von der er den (nun ungültigen) Gutschein direkt erhalten hat.

Beweisweitergabe: Er übergibt den ProofOfDoubleSpend als Beleg und fordert eine gültige Entschädigung.

Kettenreaktion: Jede Person in der Kette muss sich nun an ihren jeweiligen Vorgänger wenden, bis der ursprüngliche Betrüger erreicht ist.

Vorteil: Der Betrug wird entlang der gesamten Kette offengelegt. Dies maximiert den Reputationsschaden für den Täter und stärkt das Bewusstsein für Sicherheit im Netzwerk. Alle Beteiligten werden informiert.

### Weg B: Die direkte Regulierung (Der effiziente, "private" Weg)

Dieser Weg zielt auf eine schnelle und unkomplizierte Schadensregulierung ab.

Direktkonfrontation: Der wirtschaftlich Geschädigte (der am Ende den wertlosen Gutschein hält) nutzt die offender_id aus dem Beweis, um den ursprünglichen Täter direkt zu kontaktieren.

Schadensregulierung: Er fordert eine direkte Entschädigung vom Täter.

Fallabschluss: Wenn der Täter den Schaden begleicht, kann das Opfer eine Beilegungserklärung (ResolutionEndorsement) digital signieren und dem Täter als Quittung übergeben.

Vorteil: Die Lösung ist schnell und diskret. Unbeteiligte Zwischenstationen der Kette werden nicht behelligt. Der wirtschaftliche Schaden wird effizient behoben.

## 3. Die Rolle des Layer-2-Systems

Ein zukünftiges Layer-2-System (ein oder mehrere Server) dient als höchste Eskalationsinstanz und primäres Präventionswerkzeug.

### 3.1. Präventive Funktion (Online-Schutz)

Die Hauptaufgabe des Layer-2-Systems ist die Verhinderung von Double-Spends für Nutzer, die online sind.

Nutzer reichen die Fingerprints ihrer Transaktionen unmittelbar nach Ausführung beim Server ein.

Der Server agiert als Zeitstempel-Behörde ("notary"). Er akzeptiert nur den ersten Fingerprint für einen bestimmten Transaktions-Ursprung.

Jeder Versuch, einen widersprüchlichen Fingerprint einzureichen, wird sofort abgelehnt. Der Betrugsversuch wird damit im Keim erstickt und gelangt gar nicht erst in Umlauf.

### 3.2. Judikative Funktion (Autoritative Schlichtung)

Für Konflikte, die offline entstanden sind und später entdeckt werden, dient der Layer-2-Server als Schlichtungsstelle.

Ein Nutzer kann einen ProofOfDoubleSpend beim Server einreichen.

Der Server validiert den Beweis und fällt ein autoritatives Urteil (Layer2Verdict). Dieses Urteil legt verbindlich fest, welche Transaktion gültig ist.

Vorrang: Das signierte Urteil des Servers hat immer Vorrang vor der lokalen "Earliest Wins"-Heuristik eines Wallets. Es schafft eine einheitliche, netzwerkweite Wahrheit.

Sanktion: Das Urteil führt zu einem sofortigen, öffentlichen und automatisierten Reputationsverlust für den Täter, was ihn effektiv aus dem vertrauensbasierten Netzwerk ausschließt.