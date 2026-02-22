# Systemarchitektur: Human Money Core

Dieses Dokument bietet einen **technischen Überblick** über das `human_money_core` System. Es beschreibt die grundlegenden Konzepte, Komponenten und Datenflüsse, ohne sich in kryptographischen Details zu verlieren (dafür siehe spezifische Spezifikationen).

## 1. Kernkonzepte

Das System basiert auf drei fundamentalen Prinzipien, die es von klassischen Blockchains unterscheiden:

1.  **Vollständig Dezentral (Kein Ledger):** Es gibt keine globale Datenbank. Der "Status" des Geldes ist ausschließlich in den Dateien (Gutscheinen) selbst gespeichert.
2.  **Offline-First:** Transaktionen können ohne Internetverbindung stattfinden. Die Sicherheit wird primär durch soziale Sicherheitsmechanismen (Web of Trust) gewährleistet; ohne eine entsprechende Vertrauenswürdigkeit im Netzwerk sind Offline-Transaktionen technisch sicher, aber sozial kaum durchführbar.
3.  **Lokale Vertrauensbereiche:** Jeder Gutschein entspringt einem sozialen Vertrauenskontext (z.B. einem Menschen, einem Dorf, einem Verein), ist aber technisch standardisiert.
4.  **Layered Security:** Das System unterscheidet zwischen einer **Offline-Ebene (Layer 1)**, die auf sozialen Identitäten und Vertrauen basiert, und einer **Online-Ebene (Server/Layer 2)**, die technischen Komfort und Echtzeit-Sicherheit bietet.

## 2. Die Hauptkomponenten

### 2.1 Der Gutschein (Voucher)
Der Gutschein ist nicht nur ein "Token", sondern eine **selbst-enthaltende Datenbank** mit einer flexiblen Wertverteilung.
*   **Struktur:** Er enthält seine komplette Transaktionshistorie (Audit Trail).
*   **Inhalt:** Ersteller-Profil, Wert, Signaturen (Bürgen) und die Kette der Besitzer.
*   **Teilbarkeit (Splitting):** Ein Gutschein kann in Teilbeträge aufgespalten werden. Dabei entstehen neue Transaktionspfade innerhalb desselben Gutschein-Containers, wobei der jeweils ungenutzte Restbetrag beim Sender verbleibt.
*   **Sicherheit:** Jede Zustandsänderung ist durch kryptographische Signaturen (Ed25519), Hash-Ketten und die P2PKH-Logik gesichert.

### 2.2 Das Wallet
Das Wallet ist die Verwaltungssoftware für den Nutzer und fungiert als persönlicher "Safe" und Schlüsselmanager. Es ist **zustandslos** in dem Sinne, dass es den Status eines Gutscheins jederzeit aus der kryptographischen Kette rekonstruieren kann, speichert aber lokale Metadaten zur Effizienz.

*   **Aufgabe:** 
    *   **Schlüsselverwaltung:** Sichere Speicherung der privaten Schlüssel (Identity & Ephemeral Keys).
    *   **Transaktions-Orchestrierung:** Erzeugen von Transfer-Paketen (Bundles), inklusive Privacy Guard Verschlüsselung und Proof-Generierung.
    *   **Konflikt-Überwachung:** Das Wallet führt eine lokale Datenbank ("Fingerprint Store") mit Transaktions-Merkmalen. Es gleicht eingehende Gutscheine gegen **eigene historische Transaktionen** und (optional) gegen eine vom Server synchronisierte Liste bekannter Fingerprints ab, um Double-Spends zu erkennen.

*   **Zustandsmanagement (Lifecycle):** Das Wallet kapselt jeden Gutschein in eine `VoucherInstance`, die den lokalen Status verwaltet:
    *   `Incomplete`: Der Gutschein ist technisch intakt, erfüllt aber noch nicht alle "Gesetze" des Standards (z.B. fehlen noch Bürgen-Unterschriften). Das Wallet zeigt hierfür eine detaillierte "To-Do-Liste" an.
    *   `Active`: Der Gutschein ist valide, vollständig signiert und das Wallet besitzt den aktuellen privaten Schlüssel. Er ist bereit zur Ausgabe.
    *   `Archived`: Der Gutschein wurde ausgegeben (Transfer) oder aufgeteilt. Er wird als historischer Beleg aufbewahrt.
    *   `Quarantined`: Der Gutschein wurde aufgrund einer Verletzung der Regeln (z.B. ungültige Signatur, erkannter Double-Spend) isoliert.

    #### Logik bei Transfers
    Das Wallet unterscheidet strikt zwischen Teil- und Vollauszahlungen, um den Speicher effizient zu nutzen:

    1.  **Teiltransfer (Split):**
        *   Die alte Instanz (Quelle) wird gelöscht.
        *   Eine **neue `Active`-Instanz** wird für den verbleibenden Restbetrag erstellt.
        *   *Begründung:* Ein Gutschein mit Restguthaben ist weiterhin ein gültiges Zahlungsmittel. Ihn zu archivieren wäre semantisch falsch.

    2.  **Vollständiger Transfer:**
        *   Die alte Instanz wird gelöscht.
        *   Eine **neue `Archived`-Instanz** wird erstellt, die diesen finalen Transfer repräsentiert.
        *   *Begründung:* Dies markiert den Gutschein unmissverständlich als "verbraucht". Er steht für das Gesamtguthaben nicht mehr zur Verfügung, bleibt aber für den Audit-Trail (und die Double-Spend-Erkennung) erhalten.

### 2.3 Layer 2 Server (Chain of Authority)
Obwohl `human_money_core` offline-first ist, dient der **Layer 2 Server** als autoritative Instanz zur Absicherung von Transaktionen gegen Double-Spending. Da lokale Dateien beliebig oft kopiert werden können, benötigt das Netzwerk eine Instanz, die die **Eindeutigkeit der Historie** bestätigt. Das System nutzt eine asymmetrische **"Dumb Server, Smart Client"-Architektur** für maximale Skalierbarkeit und Sicherheit.

*   **Proof of Lock & Trustless Verification:** Der Server führt eine lückenlose Liste aller konsumierten Transaktions-Anker (`ds_tag`). Meldet der Server einen Anker als verbraucht, muss er den gesamten Lock-Eintrag inklusive vom Nutzer erstellter L2-Signatur mitsenden. Dies macht den Beweis unumstößlich ("trustless") und schließt lügende L2-Server aus.
*   **First-Seen-Rule:** Da es keine absolute "Gleichzeitigkeit" gibt, gilt die Transaktion, die zuerst beim Server registriert ("gelockt") wird, als die gültige Fortführung der Kette.
*   **Erkennung statt Blockade:** Ein Server kann Offline-Transaktionen nicht verhindern. Er liefert aber kryptographische Beweise, die der lokale Client überprüft. Bei einem erkannten Double-Spend blockiert der Client selbst die Transaktion.
*   **Hypereffizient (O(1)):** Der Server operiert größtenteils im Arbeitsspeicher (Bloom-Filter zur Vorabprüfung von L2 Voucher IDs). Der Abgleich fehlender Transaktionen erfolgt blitzschnell über "logarithmische Locators" (10-Zeichen Präfixe der Hashes), die vom Smart Client vorbereitet werden.
*   **Technische Anonymität:** Der Server sieht dabei nur kryptographische Anker. Er kennt weden Beträge, Token-Metadaten noch die echten Sender oder Empfänger.

### 2.4 Standards & Governance (Das "Gesetz")
Standards werden über signierte TOML-Dateien definiert, die als **dezentrales "Gesetzbuch"** für eine Währung fungieren.
*   **Sozial:** Jeder kann einen Standard ("Gesetz") schreiben und signieren. Ob dieser Wert hat, entscheidet allein die Akzeptanz der Gemeinschaft (Vertrauen in den Herausgeber). Dies ermöglicht lokalen Gruppen, ihre eigenen Regeln festzulegen, ohne Code ändern zu müssen.
*   **Technisch:** Die Datei konfiguriert starre Regeln für die Software:
    *   **Währungs-Logik:** Ist es "Geld" (addierbar/teilbar) oder ein "Ticket"? Wie viele Nachkommastellen?
    *   **Governance-Regeln:** Definition von Signaturanforderungen (z.B. "Mindestens 3 Bürgen, davon einer aus der Gruppe 'Vorstand'"). Diese Regeln werden vom Core-System automatisiert gegen die Profildaten der Unterzeichner validiert.
    *   **Privatsphäre-Level:** Der Standard erzwingt den Modus: `Public` (Sender muss stets sichtbar sein), `Private` (Sender muss anonym sein) oder `Flexible`.
    *   **Sicherheits-Anker:** Definierte Pflicht-Signaturen (z.B. "Nur gültig mit Unterschrift des Kassenwarts").
    *   **Immutability:** Jeder Gutschein speichert den Hash seines Standards. Ändert sich auch nur ein Zeichen im "Gesetz", gilt dies als neuer Standard. Eine nachträgliche Regeländerung für existierende Gutscheine ist somit kryptographisch unmöglich.

## 3. Datenfluss und Prozesse

### 3.1 Erstellung (Minting)
Ein Nutzer (Emittent) erstellt einen Gutschein. Dieser ist initial durch sein eigenes Schlüsselpaar signiert.

### 3.2 Weitergabe (Transfer)
1.  **Adressierung:** Der Sender benötigt den öffentlichen Schlüssel (DID:KEY) des Empfängers.
2.  **P2PKH (Pay-to-Public-Key-Hash):** Ähnlich wie bei Bitcoin wird Geld an den *Hash* eines Schlüssels (den "Anker") gesendet.
    *   **Anchor:** In der vorhergehenden Transaktion wurde ein Hash hinterlegt.
    *   **Pre-Image:** Um den Gutschein weiterzugeben, muss der Sender den zum Hash passenden öffentlichen Schlüssel (Pre-Image) enthüllen und damit die Transaktion signieren. Dies beweist den rechtmäßigen Besitz, ohne dass die Identität (`did:key`) zwingend offengelegt werden muss.
3.  **Privacy Guard:** Der Sender verschlüsselt Metadaten (wie seine eigene permanente DID und den Seed für den nächsten Wechsel-Key) für den Empfänger mittels X25519 (Diffie-Hellman). Dies gewährleistet "Forward Secrecy" und einen sicheren Informationsfluss zwischen den Parteien.
4.  **Anonymität vs. Vertrauen:** Im Gutschein selbst können sich Nutzer durch **Private Keys** anonymisieren. Dadurch ist in der Historie nicht direkt ersichtlich, wer den Gutschein besessen hat. Da die Identität jedoch als soziale Abschreckung gegen Betrug dient, kommen bei Private Keys mathematische Fallen zum Einsatz: Diese offenbaren die Identität des Senders **nur im Falle eines Betrugs** (Double Spend).
5.  **Inhalt:** Auf dem Gutschein selbst gehen Transaktionen entweder an öffentliche `did:keys` (Transparent) oder an verschleierte Schlüssel (Private), je nach gewählter Privatsphäre.

### 3.3 Konfliktlösung und Sicherheit
Das System bietet je nach Modus und Ebene unterschiedliche Schutzmechanismen:

*   **Online (Layer 2):** Die "Chain of Authority". Der Server bestätigt durch **Locks**, welche Transaktion die gültige Nachfolgerin ist. Ein Double-Spend wird nicht "verhindert" (die falsche Datei existiert ja), aber er wird **sofort erkannt** und vom Empfänger-Client abgelehnt, da der Server den Konflikt (Anker bereits belegt) beweisen kann.
*   **Anonyme Fingerprints:** Um Double-Spends auch ohne Preisgabe der Historie zu erkennen, tauschen Wallets und Server **Fingerprints** aus.
    *   Ein Fingerprint enthält den Double-Spend-Tag (Hash aus Kontext und Key), ein gerundetes Ablaufdatum (zur Ununterscheidbarkeit) und einen via XOR verschlüsselten Zeitstempel (nur für Inhaber der Transaktion entschlüsselbar).
*   **Offline (Layer 1 - Öffentlich):** Bei Transaktionen an `did:keys` ist die Historie für jeden Besitzer des Gutscheins sichtbar. Ein Double-Spend würde **verzögert** auffallen (sobald die Pfade wieder zusammenlaufen) und sozial geahndet (Reputationsverlust), da die Identität klar ist.
*   **Offline (Layer 1 - Private):** Da hier keine Identitäten sichtbar sind, greift die **mathematische Falle**. Wer denselben Private-Zustand zweimal ausgibt, enthüllt rechnerisch seinen privaten Schlüssel.

## 4. Die zwei Ebenen (Layers)

| Ebene | Fokus | Mechanismus | Zweck |
| :--- | :--- | :--- | :--- |
| **Layer 1 (Offline)** | Soziales Vertrauen | `did:key`, Web of Trust | Dezentralität, lokale Souveränität. Double-Spending wird sozial bestraft (da sichtbar oder enthüllt). |
| **Layer 2 (Online)** | Technischer Komfort | Server, Hashes | Double-Spend **Prävention** (unmöglich gemacht). Bietet Bequemlichkeit ähnlich wie EC-Karten. |

## 5. Spezifikations-Hierarchie

Dieses Projekt folgt einer "Vom Groben zum Feinen" Dokumentationsstruktur:

1.  **Level 1: Systemarchitektur (Dieses Dokument)**
    *   Verständnis der Zusammenhänge und Module.

2.  **Level 2: Detaillierte Spezifikationen**
    *   [1. Sicherheitsmodell](spec/01_sicherheits_modell.md): Philosophie, Bedrohungsmodell und Offline-Strategie.
    *   [2. Datenstrukturen](spec/02_datenstrukturen.md): Transaktions-Formate, Privacy Modes und Identifier.
    *   [3. Protokoll-Ablauf](spec/03_protokoll_ablauf.md): Der Lebenszyklus einer Transaktion (Mint, Transfer, Verkettung).
    *   [4. Kryptographie](spec/04_kryptographie_und_mathematik.md): Mathematische Details, Zero-Knowledge Proofs und Double-Spend Erkennung.
    *   [5. Layer-2 Synchronisation](spec/05_layer2_synchronisation.md): Das $O(1)$ Kommunikationsprotokoll (Dumb Server, Smart Client) & Workflows.

3.  **Level 3: Code-Dokumentation**
    *   Die Rust-Docs (`cargo doc`) beschreiben die exakte Implementierung der Interfaces.
