.dev/design_decisions.md

**Abbildung des Geschlechts im `Creator` Struct:**
    * **Entscheidung:** Das `gender`-Feld im `Creator`-Struct wird als `Int definiert. eschlecht des Erstellers ISO 5218 (1 = male", 2 = female", 0 = not known, 9 = Not applicable)
    * **Begründung:** Diese Wahl ist pragmatisch und universell einsetzbar, ohne sich auf spezifische kulturelle oder rechtliche Definitionen von Geschlecht zu beschränken, die vorwiegend in westlichen Ländern verbreitet sind. Sie bietet eine einfache und ausreichende Abbildung für die Zwecke der Core-Bibliothek (z.B. für Bürgen-Anforderungen des Minuto-Standards) und überlässt komplexere oder sensiblere Abbildungen den höheren Anwendungsschichten, die `human_money_core` nutzen.
---
** Für Gutschein Standard wird toml verwendet **
    * damit lassen sich kommentare nutzen damit der standart auch besser lesbar wird. Bei Json keine Kommentare möglich.
---
## Notwendigkeit und Berechnung der `local_voucher_instance_id`

### Warum wird eine `local_voucher_instance_id` benötigt?
Eine `local_voucher_instance_id` ist zwingend erforderlich, um **Gutschein-Instanzen eindeutig zu verwalten**, nachdem eine **`split`-Transaktion** stattgefunden hat.
- **Problem:** Eine `split`-Transaktion erzeugt aus einem Ursprungsgutschein mehrere neue, separat spendable Guthaben (z.B. einen Teil für einen Empfänger und den Restbetrag für den Sender). Alle diese Instanzen teilen sich jedoch weiterhin dieselbe globale `voucher_id`.
- **Lösung:** Da die `voucher_id` allein nicht mehr eindeutig ist, dient die `local_voucher_instance_id` als **stabiler und einzigartiger Primärschlüssel** für jede dieser Instanzen innerhalb der lokalen Wallet-Verwaltung.

### Berechnung
Die Berechnung wurde vereinfacht: Sie basiert auf einem deterministischen Hash der `voucher_id` und der Transaktions-ID (`t_id`), die das aktuelle Guthaben begründet hat. Dies stellt sicher, dass jede Instanz innerhalb eines Wallets eine eindeutige Kennung besitzt, die über Profil-Restores hinweg stabil bleibt.


# Architekturentscheidung: Identitäts- und Schlüsselmanagement (SAI)

Zur Verwaltung von Benutzerkonten auf mehreren Geräten wurde die **Separated Account Identity (SAI)** Architektur gewählt. Sie kombiniert ein einheitliches "Web of Trust" mit strikt getrennter Kontoführung.

## Das SAI Modell
- **Einheitliche Identität:** Ein Nutzer besitzt einen Public Key (`did:key`), der direkt aus dem Mnemonic abgeleitet wird.
- **Getrennte Konten:** Nutzer definieren separate Konten via Präfix (z.B. "pc", "mobil") oder nutzen **präfix-lose Root-Accounts**.
- **Context-Bound Key Derivation:** Der geheime Seed für jedes Konto wird via HKDF-SHA256 aus dem Hauptschlüssel und dem optionalen Präfix abgeleitet. Dies verhindert "Identity Hopping" und stellt sicher, dass Guthaben im definierten ökonomischen Kontext bleibt.
- **Interne Transfers:** Um Guthaben zwischen eigenen Geräten zu bewegen, ist eine explizite Transaktion nötig. Dies hält die Zustände auch offline konsistent.

---

# Wallet-Sicherheit: Rollback Guard & Integrity

## WalletSeal Rollback Guard
- **Entscheidung:** Nutzung eines kryptographischen Epochen-Systems mit hash-verketteten Siegeln.
- **Begründung:** Verhindert, dass ein Angreifer (oder ein fehlerhaftes Backup) das Wallet auf einen alten Zustand zurücksetzt, um bereits ausgegebenes Geld erneut zu verwenden. Ein `ForkLock` erkennt divergierende Wallet-Zustände.

## Storage Integrity
- **Entscheidung:** SHA3-256 Integritätsnachweise für alle Dateien, gebunden an das `WalletSeal`.
- **Begründung:** Schützt vor physischer Manipulation der Dateien auf dem Datenträger. Jede Änderung, Löschung oder Hinzufügung wird beim Laden des Wallets erkannt.

---

# Daten- und Prozessmanagement

## Wallet Event Sourcing
- **Entscheidung:** Ein persistenter, append-only Ledger (`WalletEvent`) für alle Transaktionen.
- **Begründung:** Ermöglicht eine lückenlose Audit-Historie und die Wiederherstellung von Zuständen. Durch monatliches **Chunking** (`YYYY_MM.json.enc`) bleibt die Performance auch bei tausenden Events hoch.

## Dynamic Business Rules via CEL
- **Entscheidung:** Einsatz der **Common Expression Language (CEL)** für Gutschein-Validierungsregeln.
- **Begründung:** Ermöglicht flexible Regeln in den TOML-Standards ohne Code-Änderungen im Core. CEL ist sicher (nicht Turing-vollständig), schnell und bietet mächtige Listen-Operationen.

## Anti-Signature-Reuse-Firewall
- **Entscheidung:** Validierung der Signatur-Eindeutigkeit auf Ebene des Public Keys (`[u8; 32]`), nicht des User-ID Strings.
- **Begründung:** Verhindert, dass dieselbe Identität durch verschiedene Präfixe getarnt wird, um Signaturen in unterschiedlichen Kontexten missbräuchlich wiederzuverwenden.

---

# Dezentrales Konfliktmanagement

- **Entscheidung:** Fokus auf lokale Overrides und VIP-Gossip (Very Important Proofs) statt globalem Konsens.
- **Begründung:** Globaler Konsens ist anfällig für Sybil-Angriffe und verletzt oft die Privatsphäre. Nutzer vertrauen ihren Kontakten lokal; Konflikte werden sozial oder durch Layer 2 Urteile gelöst.
- **VIP Gossip:** Betrugsbeweise werden mit negativer `depth` verbreitet, um sie von normalem Gossip abzuheben und eine schnelle Verbreitung ("Head Start") zu gewährleisten.

---

# Serialisierung & Datenstabilität

## Strikte Trennung von Domain- und View-Modell
- **Entscheidung:** Modifiziere niemals die Serialisierungslogik (z.B. serde-Attribute wie camelCase) der Kern-Datenstrukturen aus reinen UI- oder Frontend-Bequemlichkeiten.
- **Begründung:** Die Core-Bibliothek muss sprachagnostisch, idiomatisch Rust (Standard: snake_case) und vor allem kryptographisch stabil bleiben, da digitale Signaturen und Hashes exakt auf dieser Serialisierung basieren. Eine Änderung der Serialisierung (z.B. von snake_case zu camelCase) würde alle bestehenden Signaturen entwerten.
- **Umsetzung:** Datentransformationen für externe Clients (wie das JS-Frontend) müssen ausnahmslos an den äußersten Systemgrenzen (z.B. im Tauri-Wrapper oder durch dedizierte DTOs im AppService) erfolgen. Der Core bleibt bei stabilem snake_case.