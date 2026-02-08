# Zustandsmanagement von Gutschein-Instanzen

Dieses Dokument beschreibt den Lebenszyklus von Gutschein-Instanzen innerhalb des Wallets, insbesondere die Logik für Statusänderungen und die Handhabung von Double-Spend-Konflikten.

## Der Lebenszyklus und die Status

Jeder Gutschein im Wallet wird als VoucherInstance verwaltet und hat einen der folgenden Status (VoucherStatus):

### Active

Der Gutschein ist gültig und kann für Transaktionen verwendet werden. Dies ist der Standardzustand für neue oder empfangene Gutscheine mit Guthaben.

### Incomplete

Der Gutschein ist strukturell korrekt, erfüllt aber noch nicht alle Regeln seines Standards (z. B. fehlende Bürgen-Signaturen). Er kann nicht für Transaktionen verwendet werden, bis die fehlenden Bedingungen erfüllt sind.

### Archived

Der Gutschein wurde vom Wallet-Besitzer vollständig aufgebraucht oder transferiert. Er hat aus Sicht des Besitzers kein Guthaben mehr und wird nur für historische und forensische Zwecke aufbewahrt.

### Quarantined

Der Gutschein wurde aufgrund eines Konflikts (z. B. nachgewiesener Double-Spend) oder eines fatalen Validierungsfehlers gesperrt. Er kann nicht mehr verwendet werden.

## Logik bei Transfers

Das Wallet unterscheidet strikt zwischen Teil- und Vollauszahlungen, um den Archived-Status sinnvoll zu nutzen und den Speicher nicht unnötig zu belasten.

### Teiltransfer (Split)

Wenn nur ein Teilbetrag eines Gutscheins gesendet wird (z. B. 30 von 100), passiert Folgendes:

Die alte Instanz (mit 100) wird aus dem aktiven Speicher des Senders entfernt.

Eine komplett neue Instanz für den Restbetrag (70) wird mit dem Status Active erstellt.

**Begründung:**

**Logische Korrektheit:** Ein Gutschein mit Restguthaben ist nicht "archiviert", sondern weiterhin ein gültiges Zahlungsmittel. Ihn zu archivieren wäre falsch und verwirrend.

**Effizienz:** Würde bei jedem Split eine Kopie archiviert, entstünde eine große Menge an redundanten historischen Zuständen, was unnötig Speicherplatz verbrauchen würde.

### Vollständiger Transfer

Wenn der gesamte Betrag eines Gutscheins gesendet wird:

Die alte Instanz wird aus dem aktiven Speicher entfernt.

Eine neue Instanz, die diesen finalen Transfer repräsentiert, wird mit dem Status Archived hinzugefügt.

**Begründung:**

**Klare Historie:** Dieser Prozess markiert einen Gutschein unmissverständlich als "verbraucht". Er steht für Abfragen des Gesamtguthabens nicht mehr zur Verfügung, bleibt aber für die Nachverfolgung von Transaktionsketten erhalten.

## Double-Spend-Erkennung und -Behandlung

Das System nutzt eine zweistufige Strategie: proaktive Verhinderung im eigenen Wallet und reaktive Erkennung bei eingehenden Transaktionen.

### 1. Proaktive Verhinderung

Wenn ein Nutzer versucht, einen Gutschein auszugeben, wird die entsprechende VoucherInstance nach erfolgreicher Transaktion sofort aus dem aktiven Speicher entfernt (und je nach Transfer-Art durch eine Active-Restbetrag-Instanz oder eine Archived-Instanz ersetzt). Ein direkter zweiter Versuch, dieselbe alte Instanz auszugeben, schlägt mit einem VoucherNotFound-Fehler fehl. Dies verhindert versehentliches oder einfaches Double-Spending im eigenen Wallet.

### 2. Reaktive Erkennung und Konfliktlösung

Die eigentliche Prüfung findet statt, wenn ein Wallet ein Bundle von einem anderen Nutzer empfängt (process_encrypted_transaction_bundle).

**Fingerprint-Scan:** Nach dem Hinzufügen des neuen Gutscheins zum Speicher wird ein Scan aller Transaktionen im Wallet durchgeführt. Für jede Transaktion wird ein anonymer Fingerabdruck (ds_tag) erzeugt.

**Konflikterkennung:** Das System prüft, ob für einen Fingerabdruck mehrere Transaktionen mit unterschiedlichen IDs (t_id) existieren. Ist dies der Fall, liegt ein Double-Spend-Konflikt vor.

### Konfliktlösung (Bevorzugt): Urteil durch Layer 2

In der Praxis hat das Urteil eines externen, autoritativen Systems (Layer 2) immer Vorrang. Obwohl dieses System aktuell noch nicht implementiert ist, ist die Wallet-Logik bereits darauf vorbereitet, ein signiertes Urteil (Layer2Verdict) zu empfangen und zu verarbeiten. Dieses Urteil legt verbindlich fest, welche Transaktion gültig ist und welche unter Quarantäne gestellt wird.

### Konfliktlösung (Offline-Fallback): Die "Earliest Wins"-Heuristik

Nur wenn kein Urteil von einem Layer-2-System vorliegt, greift das Wallet auf eine lokale, deterministische Regel zurück:

Das Wallet entschlüsselt die Zeitstempel der beiden widersprüchlichen Transaktionen. Der Zeitstempel ist kryptographisch an die Transaktion gebunden und kann nicht unbemerkt manipuliert werden.

Die Gutschein-Instanz mit der Transaktion, die den früheren Zeitstempel hat, wird als gültig angesehen und behält den Status Active.

Die Instanz mit dem späteren Zeitstempel wird als Betrugsversuch gewertet und auf Quarantined gesetzt.