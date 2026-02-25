# 06. Spezifikation: Architektur und Validierung von Gutschein-Standards (v2.0)

## 1. Einleitung und Design-Philosophie

Dieses Dokument spezifiziert die Struktur, Semantik und kryptographische Validierung von Gutschein-Standards (repräsentiert durch die `standard.toml`) innerhalb der `human_money_core`-Bibliothek.

Ein Gutschein-Standard fungiert als die "Verfassung" oder der "Smart Contract" einer spezifischen Community-Währung (z.B. Zeitgutscheine, Minuto, Regionalgeld). Die größte Herausforderung bei dezentralen, dateibasierten Systemen ist die **Updatability (Aktualisierbarkeit)** bei gleichzeitiger **Vertrauensgarantie (Trustless Integrity)**.

Um dies zu lösen, implementiert v2.0 ein striktes **Zwei-Zonen-Modell**, das unveränderliche Konsensregeln von flexiblen Präsentationsdaten kryptographisch trennt. Kombiniert wird dies mit einem **Zwei-Stufen-Validierungssystem**:
1. **Fast-Path (Deklarativ):** Stark typisierte Variablen für blitzschnelle Checks und zur Steuerung der Benutzeroberfläche (UI-Hints).
2. **Deep-Inspection (Skripting):** Flexibles Regelwerk via Common Expression Language (CEL) für komplexe, dynamische Geschäftsbedingungen.

---

## 2. Das Zwei-Zonen-Modell und die Exklusivitäts-Regel

Die `standard.toml` ist strukturell und kryptographisch in zwei strikt voneinander getrennte Zonen unterteilt.

**Die Exklusivitäts-Regel:** Ein spezifisches Datenfeld darf zwingend nur in *einer* der beiden Zonen existieren. Ein Duplikat oder Überschreiben zwischen den Zonen führt zur sofortigen Ungültigkeit der Standard-Datei beim Parsen.

### 2.1 Die Immutable-Zone (`[immutable]`) – Der Konsens-Kern
Hier liegen alle Parameter, die die Mathematik, Sicherheit, ökonomischen Spielregeln und Identität der Währung definieren.
* **Kryptographische Bindung:** Die gesamte `[immutable]`-Zone wird kanonisiert (z.B. alphabetisch sortiert und serialisiert) und gehasht (SHA-256). Das Ergebnis ist der **Logic-Hash**.
* **Unveränderlichkeit:** Jede noch so kleine Änderung (z.B. von `allow_partial_transfers = true` auf `false`) ändert den Logic-Hash.
* **Kompatibilität:** Existierende Gutscheine, die mit einem alten Logic-Hash signiert wurden, können niemals nach den Regeln eines neuen Logic-Hashs validiert werden. Ein Bruch im Logic-Hash bedeutet einen "Hard Fork" der spezifischen Standard-Version.

### 2.2 Die Mutable-Zone (`[mutable]`) – Der flexible Präsentations-Layer
Diese Zone enthält Daten, die das Benutzererlebnis verbessern, die visuelle Repräsentation steuern oder Server-Infrastruktur-Hinweise geben.
* **Kryptographische Bindung:** Diese Zone beeinflusst den Logic-Hash *nicht*. Stattdessen wird die *gesamte* Datei (inklusive der `[immutable]`-Zone) am Ende mit der **digitalen Signatur des Herausgebers** versehen.
* **Veränderlichkeit:** Der Herausgeber (identifiziert durch seine DID, z.B. `did:key:...`) kann die `[mutable]`-Zone jederzeit aktualisieren (z.B. einen Tippfehler in der Beschreibung korrigieren oder eine neue Sprache hinzufügen), die Datei neu signieren und im Netzwerk verteilen.
* **Kompatibilität:** Da der Logic-Hash identisch bleibt, bleiben alle bisher ausgestellten Gutscheine zu 100% kompatibel und gültig, profitieren aber sofort von den aktualisierten Metadaten in den Wallets der Nutzer.

---

## 3. Identifikatoren und Anker (Die Dual-Anchor Architektur)

Um eine Währung systemübergreifend zu verfolgen und abzusichern, nutzt der Core zwei primäre Anker.

### 3.1 Die UUID (Der Ökonomische Anker)
* **Definition:** Eine standardisierte UUID v4, definiert in `[immutable.identity.uuid]`.
* **Zweck:** Dient der Wallet-Software dazu, verschiedene Gutscheine als "gleiche Währung" zu erkennen und in der UI unter demselben Reiter zu aggregieren. Die UUID überlebt auch Version-Updates (Hard Forks), solange die Community zustimmt, dass es sich ökonomisch um dasselbe Asset handelt.

### 3.2 Der Logic-Hash (Der Juristische Anker)
* **Definition:** Der SHA-256 Hash der `[immutable]` Zone.
* **Zweck:** Wird bei der Initialisierung (`init`) eines Gutscheins fest in den Header des Gutscheins geschrieben. Der Core-Validator prüft bei jeder Transaktion: *Passt der Logic-Hash im Gutschein zu dem Logic-Hash der `standard.toml`, die zur Validierung herangezogen wird?* Dies garantiert, dass niemand die Spielregeln eines *bereits existierenden* Gutscheins nachträglich ändern kann.

---

## 4. Mehrsprachigkeit und i18n-Autarkie

Gutscheine müssen offline und ohne ständige Verbindung zu einem Standard-Repository verständlich sein. Das `[mutable.i18n]` System verwendet daher das Konzept des **"Bilingual Embedding"**:

1. Der Standard definiert in der `[mutable.i18n]`-Sektion Platzhalter und Übersetzungen für alle unterstützten Sprachen (z.B. `de`, `en`, `es`, `fr`).
2. Wenn User A einen neuen Gutschein erstellt, liest die Wallet die lokale Systemsprache (z.B. `es`).
3. Die Wallet kopiert die Übersetzungen für `es` (lokal) und zwingend `en` (als globaler Fallback) direkt in die Payload des individuellen Gutscheins.
4. **Ergebnis (Autarkie):** Der Gutschein ist ab jetzt selbsterklärend und friert diese Texte ein. Selbst wenn der Standard-Herausgeber später die spanische Übersetzung in der `standard.toml` abändert, behält der bereits erstellte Gutschein seinen originalen, eingefrorenen Vertragstext.

---

## 5. Referenz der Standard-Variablen (Fast-Path)

Diese Variablen werden vom `human_money_core` direkt in performante Rust-Structs (`VoucherStandardDefinition`) geparst.

### 5.1 Die Immutable Zone (`[immutable]`)

#### 5.1.1 Identität (`[immutable.identity]`)
| Feld | Typ | Beschreibung |
|---|---|---|
| `uuid` | String | Eindeutige Kennung (v4 UUID). Zwingend erforderlich. |
| `name` | String | Der primäre Anzeigename (z.B. "Minuto"). |
| `abbreviation` | String | Das offizielle Währungskürzel (z.B. "MIN"). Max 5 Zeichen empfohlen. |

#### 5.1.2 Blueprint (Feste Startwerte für neue Gutscheine)
| Feld | Typ | Beschreibung |
|---|---|---|
| `unit` | String | Beschreibt die zählbare Einheit (z.B. "Minuten", "Kilogramm", "Punkte"). |
| `primary_redemption_type` | String | Enum. Werte: `"goods_or_services"`, `"time"`, `"physical_asset"`. Relevant für steuerliche oder juristische Klassifizierung auf App-Ebene. |
| `collateral_type` | String | Enum. Werte: `"personal_guarantee"` (Bürgen), `"fiat_backed"`, `"crypto_backed"`. |

#### 5.1.3 Features (Wallet-Verhaltenssteuerung)
| Feld | Typ | Beschreibung |
|---|---|---|
| `allow_partial_transfers` | Boolean | Wenn `true`, darf die Wallet die `split`-Funktion des Cores aufrufen (z.B. 50 von 100 Min versenden). Wenn `false`, kann der Gutschein nur als Ganzes weitergegeben werden (wie ein physischer Geldschein). |
| `balances_are_summable` | Boolean | UI-Hinweis. Wenn `true`, darf die Wallet dem Nutzer eine große Zahl (z.B. "Saldo: 500 MIN") anzeigen. Wenn `false` (z.B. bei stark heterogenen Gutscheinen), müssen diese als separate Items (wie NFTs) gelistet werden. |
| `amount_decimal_places` | Integer | Definiert die Teilbarkeit. `0` für Ganzzahlen (z.B. Minuten). `2` für Währungen (z.B. Cents). |
| `privacy_mode` | String | `"public"`, `"private"`, oder `"flexible"`. Erzwingt oder erlaubt Zero-Knowledge-Proofs für Transaktionen auf Layer 2. |

#### 5.1.4 Issuance (Regeln zur Gutschein-Entstehung)
| Feld | Typ | Beschreibung                                                                                                                                                                                                                                    |
|---|---|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `validity_duration_range` | Array[String] | ISO 8601 Zeiträume. Definiert den Rahmen, wie lange ein Gutschein maximal gültig sein darf. Bsp: `["P1Y", "P5Y"]` (1 bis 5 Jahre).                                                                                                              |
| `issuance_minimum_validity_duration` | String | **Zirkulations-Firewall:** Der Erstller darf einen  Gutschein nur dann "in Umlauf" bringen, wenn zu diesem Zeitpunkt noch mindestens dieser Zeitraum als Restgültigkeit übrig ist (Bsp: `"P1Y"`). Verhindert zu schnell ablaufender Gutscheine. |
| `additional_signatures_range` | Array[Integer] | Anzahl benötigter Mitunterzeichner bei der Erstellung. Bsp: `[2, 3]` (2 bis 3 Bürgen). `[0, 0]` für keine.                                                                                                                                      |
| `allowed_signature_roles` | Array[String] | Welche Rollen dürfen mitunterzeichnen? (Meist `"guarantor"`, optional `"auditor"` etc.).                                                                                                                                                        |


#### 5.1.6 Custom Rules (Deep-Inspection via CEL)
Hier wird die Common Expression Language (CEL) für Sonderregeln eingebettet. Der Core evaluiert diese gegen den aktuellen Status des Gutscheins.
| Feld | Typ | Beschreibung |
|---|---|---|
| `[Beliebiger_Regelname]` | Objekt | Muss `expression` (der ausführbare CEL Code) und `message` (Fehlermeldung bei Fehlschlag) enthalten. |

### 5.2 Die Mutable Zone (`[mutable]`)

#### 5.2.1 Metadata & Discovery
| Feld | Typ | Beschreibung |
|---|---|---|
| `issuer_name` | String | Wer gibt diesen Standard heraus? |
| `homepage_url` | String | (Optional) |
| `documentation_url` | String | (Optional) Link zu den rechtlichen Rahmenbedingungen. |
| `keywords` | Array[String] | (Optional) Zur Auffindbarkeit in Standard-Registries. |

#### 5.2.2 App Config (UX & Infrastruktur)
| Feld | Typ | Beschreibung |
|---|---|---|
| `default_validity_duration` | String | Welcher Wert soll im "Erstellen"-Formular der Wallet vorausgewählt sein? |
| `round_up_validity_to` | String | UI-Hinweis: Sollen Ablaufdaten z.B. immer auf das Jahresende (`"P1Y"`) gerundet werden? |
| `server_history_retention` | String | Anweisung an L2-Nodes: Wie lange nach dem Ablaufdatum eines Gutscheins (`expires_at`) müssen die kryptographischen Beweise (Transaktionshistorie) noch gespeichert werden, bevor sie sicher gelöscht (Garbage Collection) werden dürfen? Bsp: `"P6M"` (6 Monate). |

#### 5.2.3 i18n (Übersetzungs-Maps)
| Feld | Typ | Beschreibung |
|---|---|---|
| `descriptions` | Map | Haupt-Vertragstext. Unterstützt Platzhalter wie `{{amount}}`. |
| `footnotes` | Map | Klein gedrucktes / rechtliche Hinweise. |
| `collateral_descriptions` | Map | Wie wird der Gutschein gedeckt? |

---

## 6. Komplettes Praxis-Beispiel: "Minuto V2" (`standard.toml`)

Dieses Beispiel zeigt einen vollständig konfigurierten Zeitgutschein, der die Möglichkeiten des Zwei-Zonen-Modells voll ausschöpft.

```toml
# ==============================================================================
# IMMUTABLE-ZONE (Konsens-Kern)
# ACHTUNG: Jede Änderung an einem Byte in dieser Sektion verändert den Logic-Hash!
# Ein veränderter Logic-Hash bricht die Kompatibilität zu bereits ausgestellten
# Gutscheinen dieser Serie.
# ==============================================================================

[immutable.identity]
uuid = "123e4567-e89b-12d3-a456-426614174000"
name = "Minuto Regional"
abbreviation = "MIN"

[immutable.blueprint]
unit = "Minuten"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 0
privacy_mode = "flexible" # Nutzer können L2-Verschleierung pro Transaktion wählen

[immutable.issuance]
# Gutscheine dürfen maximal für 1 bis 5 Jahre ausgestellt werden
validity_duration_range = ["P1Y", "P5Y"]
# Bei Weitergabe muss der Gutschein noch mindestens 1 Jahr gültig sein
issuance_minimum_validity_duration = "P1Y"
# Es werden exakt 2 Bürgen benötigt
additional_signatures_range = [2, 2]
allowed_signature_roles = ["guarantor"]


# --- DEEP INSPECTION (Dynamische Regeln) ---
# CEL Expressions für komplexe Validierungslogik, die über Fast-Path hinausgeht.
[immutable.custom_rules.max_transfer_amount]
# Ein einzelner Transfer darf niemals 5000 Minuten (ca. 1 Monat Arbeit) überschreiten
expression = "Transaction.amount <= 5000"
message = "Ein einzelner Transfer darf 5000 Minuten nicht überschreiten."

[immutable.custom_rules.prevent_self_guarantee]
# Der Ersteller (Issuer) darf nicht gleichzeitig als Bürge (Guarantor) auftreten
expression = "!Voucher.signatures.exists(sig, sig.role == 'guarantor' && sig.pubkey == Voucher.issuer_pubkey)"
message = "Der Aussteller des Gutscheins darf nicht als eigener Bürge auftreten."


# ==============================================================================
# MUTABLE-ZONE (Metadaten & Präsentation)
# Änderungen hier verändern den Logic-Hash NICHT. Der Herausgeber kann diese
# Werte aktualisieren und die Datei neu signieren, um Wallets mit neuen 
# Übersetzungen oder besseren UX-Defaults zu versorgen.
# ==============================================================================

[mutable.metadata]
issuer_name = "Minuto Dachverband e.V."
homepage_url = "[https://minuto.org](https://minuto.org)"
documentation_url = "[https://minuto.org/manifesto-v2](https://minuto.org/manifesto-v2)"
keywords = ["zeitgutschein", "regionalgeld", "minuto"]

[mutable.app_config]
default_validity_duration = "P5Y"
round_up_validity_to = "P1Y" # Laufzeit endet immer am 31.12. des Zieljahres
server_history_retention = "P6M" # L2 Nodes dürfen Historie 6 Monate nach Ablauf löschen

# --- BILINGUAL EMBEDDING (Übersetzungen) ---
[mutable.i18n.descriptions]
de = "Ein Minuto entspricht einer Minute qualitativer Arbeitszeit. Dieser Gutschein ist einlösbar für Waren oder Dienstleistungen im Wert von {{amount}} Minuten beim Aussteller."
en = "One Minuto equals one minute of quality work. This voucher is redeemable for goods or services worth {{amount}} minutes from the issuer."
es = "Un Minuto equivale a un minuto de trabajo de calidad. Este vale es canjeable por bienes o servicios por valor de {{amount}} minutos del emisor."

[mutable.i18n.footnotes]
de = "Einlösung erfolgt nach gegenseitiger Absprache. Keine Barauszahlung."
en = "Redemption is subject to mutual agreement. No cash payout."
es = "El canje está sujeto a mutuo acuerdo. Sin pago en efectivo."

[mutable.i18n.collateral_descriptions]
de = "Dieser Gutschein ist durch die persönliche Leistungsbereitschaft des Ausstellers sowie durch die Bürgschaft von zwei unabhängigen Zeugen aus der Gemeinschaft gedeckt."
en = "This voucher is backed by the personal commitment of the issuer and the guarantee of two independent witnesses from the community."


# ==============================================================================
# DIGITALE SIGNATUR DES HERAUSGEBERS
# ==============================================================================
[signature]
# Die DID (Decentralized Identifier) des Standard-Herausgebers (Ed25519)
issuer_id = "did:key:z6Mki8QqVMb66hjtTwcceVXbZuSHTk61jqiprRvEhuotZmSA"
# Die Signatur berechnet sich über die gesamte Datei (exklusive des [signature] Blocks)
signature = "5NxcEMTVUEvCbbozZmpjinfnLdq1PqSHztKzTYQ7QT36oMGQsuVphimwPRh94AuYUJ2NxhFf6dVXdDjneLXzCZUU"