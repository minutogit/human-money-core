voucher_standards/readme_de.md
# Gutschein-Standards: Erstellung, Aufbau und Validierung

Dieses Dokument beschreibt den vollständigen Prozess zur Erstellung eines Voucher-Standards, einschließlich der Struktur der `standard.toml`-Dateien, die als Vorlage und Regelwerk für alle Gutscheine innerhalb des Systems dienen. Ein gut definierter und signierter Standard ist die Grundlage für ein sicheres und vertrauenswürdiges Gutschein-Netzwerk.

## Erstellung eines Voucher-Standards

### Schritt 1: Vorbereitung
Bevor Sie einen Standard erstellen, benötigen Sie:
- Eine eindeutige `did:key`-Identität für den Herausgeber (Issuer). Diese wird aus einem Ed25519-Public-Key abgeleitet.
- Kenntnisse über die gewünschten Regeln für Gutscheine (z.B. Teilbarkeit, Gültigkeitsdauer, Signaturanforderungen).
- Ein Verständnis der TOML-Syntax für die Konfiguration.

### Schritt 2: Erstellen der `standard.toml`-Datei
Jeder Standard ist eine TOML-Datei mit vier Hauptbereichen:

1.  **`[metadata]`**: Wer ist der Herausgeber? Wie heißt der Standard?
2.  **`[template]`**: Welche Werte werden in jeden neuen Gutschein kopiert?
3.  **`[validation]`**: Welchen Regeln muss ein Gutschein entsprechen, um gültig zu sein?
4.  **`[signature]`**: Die digitale Signatur, die die Echtheit des Standards beweist (wird später hinzugefügt).

Beginnen Sie mit den ersten drei Abschnitten. Verwenden Sie die Beispiele unten als Vorlage und passen Sie sie an Ihre Anforderungen an.

### Schritt 3: Signierung des Standards
Die Signierung stellt sicher, dass der Standard authentisch ist und nicht manipuliert wurde. Der Prozess basiert auf kryptographischen Hash-Funktionen und Ed25519-Signaturen:

1. **Kanonisierung**: Der Standard (ohne Signatur-Block) wird in einen stabilen JSON-String umgewandelt.
2. **Hash-Berechnung**: Ein SHA3-256-Hash (Konsistenz-Hash) wird aus dem kanonischen JSON berechnet.
3. **Signierung**: Der Hash wird mit dem privaten Ed25519-Schlüssel des Herausgebers signiert.
4. **Hinzufügen der Signatur**: Die Base58-kodierte Signatur und die Issuer-ID werden in den `[signature]`-Block eingetragen.

Verwenden Sie das bereitgestellte Skript `sign_standards.sh` im Projektverzeichnis, um diesen Prozess zu automatisieren. Das Skript:
- Parst die TOML-Datei.
- Berechnet den Konsistenz-Hash.
- Fordert den privaten Schlüssel an (oder verwendet eine Umgebungsvariable).
- Signiert den Hash und fügt die Signatur hinzu.

**Beispiel-Befehl:**
```bash
./sign_standards.sh voucher_standards/minuto_v1/standard.toml
```

Nach der Signierung enthält die Datei den vollständigen `[signature]`-Block.

### Schritt 4: Validierung des Standards
Überprüfen Sie die Integrität des signierten Standards mit dem Skript `validate_standards.sh`:
```bash
./validate_standards.sh voucher_standards/minuto_v1/standard.toml
```

Dieses Skript:
- Parst die TOML-Datei.
- Verifiziert die Signatur gegen den berechneten Konsistenz-Hash.
- Stellt sicher, dass der Standard den erwarteten Strukturen entspricht.

Bei Erfolg ist der Standard bereit zur Verwendung. Bei Fehlern (z.B. ungültige Signatur) müssen Sie die Datei korrigieren und erneut signieren.

### Schritt 5: Integration und Verwendung
- Platzieren Sie die signierte `standard.toml` im Verzeichnis `voucher_standards/`.
- Verwenden Sie den Standard beim Erstellen neuer Gutscheine über die Wallet-Software.
- Die Validierung erfolgt automatisch beim Laden des Standards und bei jeder Gutschein-Transaktion.

**Hinweis:** Standards sind unveränderlich nach der Signierung. Änderungen erfordern eine neue Version mit aktualisierter UUID und erneuter Signierung.

-----

## `[metadata]` - Die Visitenkarte des Standards

Dieser Block enthält grundlegende, identifizierende Informationen.

```toml
[metadata]
name = "Musterstadt-Taler"
uuid = "MST-TALER-V1-2025-09" # Eine menschenlesbare, eindeutige ID
abbreviation = "MST"
issuer_name = "Wirtschaftsrat Musterstadt"
homepage_url = "https://musterstadt-taler.de"
documentation_url = "https://docs.musterstadt-taler.de"
keywords = ["regionalwährung", "gemeinschaft", "musterstadt"]
```

-----

## `[template]` - Die Kopiervorlage für Gutscheine

Dieser Block definiert alle Werte, die bei der Erstellung eines neuen Gutscheins als feste Vorgabe (`fixed`) oder als Standardwert (`default`) übernommen werden.

- **`[template.fixed]`**: Diese Werte sind für jeden Gutschein dieses Standards **zwingend und unveränderlich**.
- **`[template.default]`**: Diese Werte dienen als **Vorschlag** und können bei der Gutscheinerstellung überschrieben werden.

<!-- end list -->

```toml
[template.fixed]
# Mehrsprachige Beschreibung des Gutscheins (Liste von lokalisierten Texten)
description = [
  { lang = "de", text = "Ein Gutschein für die lokale Wirtschaft." },
  { lang = "en", text = "A voucher for the local economy." }
]

# Optionale Fußnote
footnote = "Gültig nur in teilnehmenden Geschäften."

# Primäre Einlösungsart (z.B. "cash", "goods")
primary_redemption_type = "goods"

# Gibt an, ob der Gutschein summierbar ist (für Stapelung)
balances_are_summable = true

# Gibt an, ob der Gutschein teilbar ist
allow_partial_transfers = true

# Definiert die Währungseinheit für alle Gutscheine
[template.fixed.nominal_value]
unit = "Muster-Taler"

# Informationen zur Besicherung werden fest vorgegeben
[template.fixed.collateral]
type = "Keine"
description = "Dieser Gutschein ist durch das Vertrauen der Gemeinschaft besichert."
redeem_condition = "Nicht zutreffend."

# Die Anforderungen an Bürgen werden in den Gutschein kopiert
[template.fixed.guarantor_info]
needed_count = 2
description = "Zwei Bürgen aus der Händlergemeinschaft sind erforderlich."

# Optionale Rundung der Gültigkeitsdauer (z.B. "P1M" für Monatsende)
round_up_validity_to = "P1M"

[template.default]
# Schlägt eine Gültigkeit von 5 Jahren vor, kann aber geändert werden
default_validity_duration = "P5Y"
```

-----

## `[validation]` - Das Regelwerk

Dies ist der mächtigste Block. Er definiert die Regeln, gegen die ein Gutschein bei jeder wichtigen Aktion (Erstellung, Transaktion, Empfang) validiert wird. Alle Unterabschnitte sind optional.

### `[validation.counts]` - Mengen- und Anzahlsregeln

Hier legen Sie mit `min` und `max` exakte Grenzen für die Anzahl von Elementen in den Listen (Arrays) eines Gutscheins fest.

**Mögliche Schlüssel:**

* `transactions`: Steuert die Gesamtzahl der Transaktionen in der Kette.

**Beispiel:** Ein Gutschein muss mindestens eine Transaktion haben und darf nicht mehr als 100 Transaktionen enthalten, um die Dateigröße zu kontrollieren.

```toml
[validation.counts]
transactions = { min = 1, max = 100 }
```

### `[[validation.required_signatures]]` - Spezifische Signaturanforderungen

Erzwingt das Vorhandensein von Signaturen von bestimmten Parteien. Da es sich um ein TOML-"Array von Tabellen" handelt (`[[...]]`), können Sie mehrere, voneinander unabhängige Signatur-Regeln definieren.

**Parameter pro Regel:**

* `role_description` (String): Eine menschenlesbare Beschreibung, wofür diese Signatur steht.
* `allowed_signer_ids` (Array von Strings): Eine Liste von `did:key`-IDs. Mindestens eine Signatur muss von einer dieser IDs stammen.
* `required_role` (String): Die erforderliche Rolle der Signatur (z.B. "guarantor").
* `is_mandatory` (Boolean): Wenn `true`, ist das Vorhandensein einer passenden Signatur zwingend erforderlich.

**Beispiel:** Ein "offizieller" Gutschein muss eine Freigabe-Signatur von einer der beiden autorisierten Stellen der Stadtverwaltung enthalten.

```toml
[[validation.required_signatures]]
role_description = "Freigabe durch die Stadtkasse"
allowed_signer_ids = ["did:key:z...Stadtkasse...", "did:key:z...Buergermeister..."]
required_role = "guarantor"
is_mandatory = true
```

### `[validation.content_rules]` - Inhaltsregeln für Felder

Prüft den Inhalt spezifischer Felder im Gutschein-JSON. Die **Schlüssel in diesem Block sind immer JSON-Pfade** (z.B. `"nominal_value.unit"`), die auf ein Feld im Gutschein zeigen.

**Mögliche Unterblöcke:**

* `fixed_fields`: Erzwingt, dass ein Feld einen exakten, festen Wert (String, Zahl, Boolean) haben muss.
* `allowed_values`: Stellt sicher, dass der Wert eines Feldes aus einer vorgegebenen Liste stammt.
* `regex_patterns`: Prüft, ob der Wert eines Feldes einem regulären Ausdruck (Regex) entspricht.

**Beispiel:** Gutscheine dieses Standards dürfen **niemals** teilbar sein, es sind nur Nennwerte von "25", "50" oder "100" erlaubt, und die Fußnote muss eine Projektnummer enthalten.

```toml
[validation.content_rules]
  [validation.content_rules.fixed_fields]
  "divisible" = false
  "collateral.type" = "Fiat-Währung"

  [validation.content_rules.allowed_values]
  "nominal_value.amount" = ["25", "50", "100"]

  [validation.content_rules.regex_patterns]
  "footnote" = '^PROJ-202[5-9]-[A-Z0-9]{8}$'
```

### `[validation.behavior_rules]` - Verhaltensregeln

Steuert Aktionen und systemweites Verhalten.

**Mögliche Schlüssel:**

* `allowed_t_types` (Array von Strings): Definiert die erlaubten Transaktionstypen (mögliche Werte: `"init"`, `"transfer"`, `"split"`).
* `issuance_minimum_validity_duration` (String, ISO 8601 Duration): Eine **Zirkulations-Firewall** für den Ersteller. Gibt an, welche *Restgültigkeit* ein Gutschein mindestens haben muss (z.B. `"P6M"`), damit der *ursprüngliche Ersteller* ihn noch an Dritte ausgeben (transferieren) darf. Dies soll sicherstellen, dass Gutscheine lange genug zirkulieren können.
    * **Wichtig:** Diese Regel gilt *nicht* für normale Inhaber und auch *nicht*, wenn der Ersteller den Gutschein an sich selbst (z.B. zur Einlösung auf ein anderes Konto) transferiert.
* `max_creation_validity_duration` (String, ISO 8601 Duration): Die maximal erlaubte Gültigkeitsdauer ab Erstellung (z.B. `"P10Y"` für 10 Jahre).
* `amount_decimal_places` (Integer): Erzwingt eine maximale Anzahl an Nachkommastellen für alle Beträge (z.B. `2` für Währungen, `8` für Krypto-Assets).

**Beispiel:** Es sind nur volle Übertragungen (`transfer`) erlaubt, neue Gutscheine müssen mindestens 6 Monate gültig sein, und Beträge dürfen maximal 2 Nachkommastellen haben.

```toml
[validation.behavior_rules]
allowed_t_types = ["init", "transfer"]
issuance_minimum_validity_duration = "P6M" # Ersteller darf Gutschein nur ausgeben, wenn er noch mind. 6 Monate gültig ist.
amount_decimal_places = 2
```

### `[validation.field_group_rules]` - Gruppenregeln (für Fortgeschrittene)

Definiert komplexe Regeln für die Werteverteilung von Feldern innerhalb einer Liste von Objekten. Der **Schlüssel des Blocks** ist der JSON-Pfad zum Array, das geprüft werden soll (z.B. `[validation.field_group_rules.guarantor_signatures]`).

**Parameter:**

* `field` (String): Das Feld *innerhalb* der Objekte in der Liste, das geprüft werden soll (z.B. `"gender"`).
* `value_counts` (Array von Tabellen): Eine Liste von Zählregeln. Jede Regel besteht aus:
    * `value` (String): Der zu zählende Wert.
    * `min` (Integer): Wie oft dieser Wert mindestens vorkommen muss.
    * `max` (Integer): Wie oft dieser Wert maximal vorkommen darf.

**Beispiel:** Um Diversität zu gewährleisten, muss ein Gutschein von **exakt einem Mann (`gender = "1"`) und exakt einer Frau (`gender = "2"`)** gebürgt werden. Die Werte für `gender` entsprechen dem ISO 5218-Standard für die Darstellung von menschlichem Geschlecht (z.B. "1" = männlich, "2" = weiblich, "0" = nicht bekannt, "9" = nicht anwendbar). Um einen exakten Wert zu erzwingen, wird `min` und `max` auf denselben Wert gesetzt.

```toml
[validation.field_group_rules.guarantor_signatures]
field = "gender"
value_counts = [
  { value = "1", min = 1, max = 1 }, # Der Wert "1" muss genau 1x vorkommen (männlich).
  { value = "2", min = 1, max = 1 }, # Der Wert "2" muss genau 1x vorkommen (weiblich).
]
```

-----

## `[signature]` - Das Siegel der Authentizität

Dieser Block ist **zwingend erforderlich**. Er enthält die digitale Signatur des Herausgebers. Diese Signatur stellt sicher, dass die Standard-Datei nicht manipuliert wurde und tatsächlich vom angegebenen `issuer_id` stammt. Die Wallet-Software **wird jeden Standard ablehnen**, dessen Signatur ungültig ist.

```toml
[signature]
issuer_id = "did:key:z...PublicKeyDesHerausgebers..."
signature = "Base58EncodedSignature..."
```