.dev/design_decisions.md

**Abbildung des Geschlechts im `Creator` Struct:**
    * **Entscheidung:** Das `gender`-Feld im `Creator`-Struct wird als `Int definiert. eschlecht des Erstellers ISO 5218 (1 = male", 2 = female", 0 = not known, 9 = Not applicable)
    * **Begründung:** Diese Wahl ist pragmatisch und universell einsetzbar, ohne sich auf spezifische kulturelle oder rechtliche Definitionen von Geschlecht zu beschränken, die vorwiegend in westlichen Ländern verbreitet sind. Sie bietet eine einfache und ausreichende Abbildung für die Zwecke der Core-Bibliothek (z.B. für Bürgen-Anforderungen des Minuto-Standards) und überlässt komplexere oder sensiblere Abbildungen den höheren Anwendungsschichten, die `voucher_core` nutzen.
---
** Für Gutschein Standard wird toml verwendet **
    * damit lassen sich kommentare nutzen damit der standart auch besser lesbar wird. Bei Json keine Kommentare möglich.
---
## Notwendigkeit und Berechnung der `local_voucher_instance_id`
### Warum wird eine `local_voucher_instance_id` benötigt?
Eine `local_voucher_instance_id` ist zwingend erforderlich, um **Gutschein-Instanzen eindeutig zu verwalten**, nachdem eine **`split`-Transaktion** stattgefunden hat.
- **Problem:** Eine `split`-Transaktion erzeugt aus einem Ursprungsgutschein mehrere neue, separat spendable Guthaben (z.B. einen Teil für einen Empfänger und den Restbetrag für den Sender). Alle diese Instanzen teilen sich jedoch weiterhin dieselbe globale `voucher_id`.
- **Lösung:** Da die `voucher_id` allein nicht mehr eindeutig ist, dient die `local_voucher_instance_id` als **stabiler und einzigartiger Primärschlüssel** für jede dieser Instanzen innerhalb der lokalen Wallet-Verwaltung (z.B. in einer `HashMap` oder Datenbank).

# todo Berechnung hat sich vereinfach und muss nicht so komplex sein. (Berschreibung anpassen)
### Warum ist die Berechnung scheinbar komplex?
Die Berechnung ist nicht willkürlich komplex, sondern präzise darauf ausgelegt, einen kritischen Anwendungsfall robust zu handhaben: die **lokale Double-Spending-Erkennung**.
Die Komplexität entsteht, weil die Logik zwischen zwei Zuständen eines Gutscheins im Profil des Nutzers unterscheiden muss:
1.  **Aktiver (spendabler) Gutschein:** Der Nutzer besitzt ein Guthaben `> 0`. Die ID muss diesen aktuellsten, besessenen Zustand widerspiegeln.
2.  **Archivierter (ausgegebener) Gutschein:** Der Nutzer hat das gesamte Guthaben ausgegeben (Guthaben `= 0`). Der Gutschein wird aber als "leere Hülle" für die Transaktionshistorie aufbewahrt. Seine ID muss auf dem **letzten Zustand eingefroren werden, in dem er aktiv war**.
Um dies zu erreichen, kann die Berechnung nicht einfach die letzte Transaktion des Gutscheins nehmen. Stattdessen muss sie die Transaktionshistorie **rückwärts durchsuchen**, um den letzten Zeitpunkt zu finden, an dem der Profilinhaber tatsächlich ein Guthaben besaß. Dieser gezielte Suchvorgang macht die Berechnung scheinbar komplex, ist aber die Grundlage für eine konsistente und sichere Zustandsverwaltung.


# Architekturentscheidung: Identitäts- und Schlüsselmanagement in voucher_core
Zur Verwaltung von Benutzerkonten auf mehreren Geräten (z.B. PC und Handy) wurde eine Architektur für Separated Account Identity (SAI) gewählt. Sie kombiniert die Anforderung eines einheitlichen "Web of Trust" mit der Notwendigkeit einer strikt getrennten Kontoführung, um Double Spending durch Zustands-Inkonsistenzen zu verhindern.

## Das entschiedene Separated Account Identity (SAI) Modell
Konzept: Ein Nutzer besitzt eine einzige kryptographische Identität, die durch einen einzigen Public Key (z.B. did:key:z...xyzA) repräsentiert wird. Diese Identität wird direkt aus dem Mnemonic (und optionaler Passphrase) abgeleitet, ohne Einbeziehung eines Präfixes.

Getrennte Konten: Obwohl die kryptographische Identität (der Public Key) gleich ist, definiert der Nutzer separate Konten für verschiedene Kontexte (z.B. "pc", "mobil"), indem er unterschiedliche Präfixe verwendet.

Eindeutige Adressen: Jedes Konto hat eine eindeutige, vollständige User-ID, die aus dem Präfix, einer Prüfsumme und dem einheitlichen Public Key besteht.

Konto 1 (PC): pc-aB3@did:key:z...xyzA

Konto 2 (Mobil): mobil-C4d@did:key:z...xyzA

## Kernprinzipien der Implementierung
Einheitliche Identität für das Web of Trust: Für das externe Reputationssystem (Web of Trust) ist nur der Public Key (did:key:z...xyzA) relevant. Alle Aktionen, unabhängig vom Präfix, werden kryptographisch dieser einen Identität zugeordnet.

Strikte Kontentrennung zur Verhinderung von Double Spending: Die Wallet-Logik muss die vollständige User-ID (z.B. pc-aB3@did:key:z...xyzA) zur Validierung des Besitzes verwenden.

Beim Empfang (receive_bundle): Ein Gutschein, der an mobil-C4d@... adressiert ist, muss von einer Wallet, die als pc-aB3@... agiert, abgewiesen werden. Ein automatisches "Mitladen" ist ausgeschlossen, da dies zu kritischen Double-Spend-Szenarien führen würde, wenn beide Geräte (z.B. offline) denselben eingehenden Gutschein annehmen.

Prüfsummen-Validierung: Die in der User-ID enthaltene Checksumme (z.B. aB3) stellt sicher, dass Gutscheine durch Tippfehler nicht an ungültige oder falsche Präfix-Varianten gesendet werden können.

Ermöglichung von internen Transfers: Dieses Modell erzwingt ein klares mentales Modell: Guthaben auf pc-aB3@... ist getrennt von Guthaben auf mobil-C4d@.... Um Guthaben zwischen seinen eigenen Geräten zu bewegen, muss der Nutzer eine explizite Transaktion (einen Transfer an sich selbst) durchführen. Dies ist ein gewollter und notwendiger Schritt, um die Zustände sauber und konsistent zu halten.

## Zusammenfassung der Architektur
Diese Separated Account Identity (SAI) Lösung ist optimal auf die Anforderungen des Systems zugeschnitten:

Sicherheit: Sie verhindert die gefährlichste Fehlerklasse – die unbeabsichtigte Doppel-Annahme desselben Gutscheins auf verschiedenen Geräten – durch eine strikte, adressbasierte Kontentrennung.

Vertrauen: Sie wahrt die Integrität des Web of Trust, indem alle Konten eines Nutzers auf dieselbe, verifizierbare kryptographische Identität (did:key) zurückgeführt werden.