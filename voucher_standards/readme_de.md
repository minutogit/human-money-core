# Gutschein-Standards: Aufbau und Validierung

Dieses Dokument beschreibt die Struktur und die Möglichkeiten der `standard.toml`-Dateien, die als Vorlage und Regelwerk für alle Gutscheine innerhalb des Systems dienen. Ein gut definierter Standard ist die Grundlage für ein sicheres und vertrauenswürdiges Gutschein-Netzwerk.

Jeder Standard ist eine digital signierte TOML-Datei, die vier Hauptbereiche definiert:

1.  **`[metadata]`**: Wer ist der Herausgeber? Wie heißt der Standard?
2.  **`[template]`**: Welche Werte werden in jeden neuen Gutschein kopiert?
3.  **`[validation]`**: Welchen Regeln muss ein Gutschein entsprechen, um gültig zu sein?
4.  **`[signature]`**: Die digitale Signatur, die die Echtheit des Standards beweist.

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
# Definiert die Währungseinheit für alle Gutscheine
[template.fixed.nominal_value]
unit = "Muster-Taler"

# Gibt an, ob der Gutschein teilbar ist
is_divisible = true

# Informationen zur Besicherung werden fest vorgegeben
[template.fixed.collateral]
type = "Keine"
description = "Dieser Gutschein ist durch das Vertrauen der Gemeinschaft besichert."
redeem_condition = "Nicht zutreffend."

# Die Anforderungen an Bürgen werden in den Gutschein kopiert
[template.fixed.guarantor_info]
needed_count = 2
description = "Zwei Bürgen aus der Händlergemeinschaft sind erforderlich."

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

* `guarantor_signatures`: Steuert die Anzahl der Bürgen-Signaturen.
* `additional_signatures`: Steuert die Anzahl zusätzlicher, optionaler Signaturen.
* `transactions`: Steuert die Gesamtzahl der Transaktionen in der Kette.

**Beispiel:** Ein Gutschein muss mindestens einen Bürgen haben (`min = 1`), darf aber nicht mehr als 100 Transaktionen enthalten, um die Dateigröße zu kontrollieren.

```toml
[validation.counts]
guarantor_signatures = { min = 1, max = 3 }
transactions = { min = 1, max = 100 }
additional_signatures = { min = 0, max = 5 }
```

### `[[validation.required_signatures]]` - Spezifische Signaturanforderungen

Erzwingt das Vorhandensein von Signaturen von bestimmten Parteien. Da es sich um ein TOML-"Array von Tabellen" handelt (`[[...]]`), können Sie mehrere, voneinander unabhängige Signatur-Regeln definieren.

**Parameter pro Regel:**

* `role_description` (String): Eine menschenlesbare Beschreibung, wofür diese Signatur steht.
* `allowed_signer_ids` (Array von Strings): Eine Liste von `did:key`-IDs. Mindestens eine Signatur muss von einer dieser IDs stammen.
* `required_signature_description` (String, Optional): Falls angegeben, muss die `description` der Signatur exakt diesem Text entsprechen.
* `is_mandatory` (Boolean): Wenn `true`, ist das Vorhandensein einer passenden Signatur zwingend erforderlich.

**Beispiel:** Ein "offizieller" Gutschein muss eine Freigabe-Signatur von einer der beiden autorisierten Stellen der Stadtverwaltung enthalten.

```toml
[[validation.required_signatures]]
role_description = "Freigabe durch die Stadtkasse"
allowed_signer_ids = ["did:key:z...Stadtkasse...", "did:key:z...Buergermeister..."]
required_signature_description = "Offizielle Freigabe 2025"
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

**Beispiel:** Um Diversität zu gewährleisten, muss ein Gutschein von **exakt einem Mann (`gender = "1"`) und exakt einer Frau (`gender = "2"`)** gebürgt werden. Um einen exakten Wert zu erzwingen, wird `min` und `max` auf denselben Wert gesetzt.

```toml
[validation.field_group_rules.guarantor_signatures]
field = "gender"
value_counts = [
  { value = "1", min = 1, max = 1 }, # Der Wert "1" muss genau 1x vorkommen.
  { value = "2", min = 1, max = 1 }, # Der Wert "2" muss genau 1x vorkommen.
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