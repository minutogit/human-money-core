---
name: project-context
description: Complete API reference, data structures, cryptography details, and module overview for human_money_core. Load this when you need deep technical context about the library.
---

# human_money_core — Full Project Context

Dies ist die Kontextdatei für die Entwicklung der Rust-Core-Bibliothek `human_money_core`. Sie dient als "README für die KI", um ein umfassendes Verständnis des Projekts und seiner Anforderungen zu gewährleisten.

## 1\. Projekt & Zweck

- **Projektname:** `human_money_core`

- **Zweck:** Implementierung der Kernlogik eines dezentralen, vertrauensbasierten elektronischen Gutschein-Zahlungssystems.

- **Hauptziel:** Bereitstellung einer robusten, sicheren und performanten Bibliothek, die später über FFI (Foreign Function Interface) und WASM (WebAssembly) in anderen Umgebungen (z.B. Desktop-Anwendungen, Web-Clients) genutzt werden kann.

- **Kernfunktionalität:** Erstellung, Verwaltung und Verifizierung von digitalen Gutscheinen und deren Transaktionshistorie.

## 2\. Tech-Stack

- **Sprache:** Rust

- **Zielplattformen:** FFI-kompatibel (für Bindings zu anderen Sprachen) und WASM-kompatibel (für Web-Anwendungen).

- **Kryptographie:** Standard-Rust-Kryptographie-Bibliotheken für digitale Signaturen und Hashing.

## 3\. Architektur & Designprinzipien

- **Modulare Architektur:** Die Bibliothek ist in logische Module unterteilt. Die Architektur trennt klar die Geschäftslogik (in einer `Wallet`-Fassade) von der Persistenz (hinter einem `Storage`-Trait), um Flexibilität und Testbarkeit zu maximieren.

- **Dezentraler Ansatz:** Das System basiert auf dezentralen Gutscheinen (Textdateien), die eine verkettete Liste der Transaktionshistorie enthalten (eine Art "Mini-Blockchain pro Gutschein").

- **Kein globales Ledger:** Im Gegensatz zu traditionellen Blockchains wird bewusst auf ein globales, verteiltes Ledger verzichtet. Die Integrität wird durch digitale Signaturen und soziale Kontrolle gewährleistet.

- **Entkoppelte & Anonymisierte Speicherung:** Die Kernlogik (`Wallet`) ist vom Speicher (`Storage`-Trait) entkoppelt. Die Standardimplementierung `FileStorage` speichert jedes Benutzerprofil in einem eigenen, anonymen Unterverzeichnis. Der Name dieses Verzeichnisses wird aus einem Hash der Benutzergeheimnisse (`mnemonic`, `passphrase`, `prefix`) abgeleitet, um die Privatsphäre auf dem Speichermedium zu schützen.

  - **Separated Account Identity (SAI) für strikte Kontotrennung:** Ein Benutzer besitzt eine einzige kryptographische Identität (Public Key), die aus dem Mnemonic abgeleitet wird. Durch die Verwendung von Präfixen (z.B. "pc", "mobil") werden separate Konten für verschiedene Kontexte definiert. Hierbei kommt die **Context-Bound Key Derivation** via HKDF-SHA256 zum Einsatz: Der geheime Seed für jedes Konto wird kryptographisch sauber aus dem Hauptschlüssel und dem Präfix abgeleitet. Dies gewährleistet:
  - Einheitliche Identität für das Web of Trust: Alle Aktionen werden kryptographisch derselben Identität zugeordnet.
  - Strikte Kontentrennung: Die Wallet-Logik verwendet die vollständige User-ID (z.B. `pc:aB3@did:key:z...`) zur Validierung des Besitzes. Guthaben bleibt im definierten ökonomischen Kontext.
  - Schutz vor "Identity Hopping": Da die Schlüsselableitung an das Präfix gebunden ist, können Identitäten nicht einfach gewechselt werden, ohne die mathematische Falle (Identity Trap) auszulösen.

- **Offline-Fähigkeit:** Transaktionen sollen auch offline durchgeführt werden können, indem die aktualisierte Gutschein-Datei direkt an den neuen Halter übergeben wird.

- **Fokus auf Betrugserkennung, nicht -vermeidung:** Da es kein globales Ledger gibt, kann die Core-Bibliothek nicht verhindern, dass ein Nutzer widersprüchliche Transaktionshistorien (Double Spending) erzeugt. Das System stellt stattdessen sicher, dass jeder Betrugsversuch durch digitale Signaturen kryptographisch beweisbar ist, was eine Erkennung und soziale Sanktionen in einem übergeordneten System (Layer 2) ermöglicht.

- **Peer-to-Peer Gossip-Protokoll (VIP-Impfung):** Zur dezentralen Erkennung von Double Spending tauschen Wallets **Transaktions-Fingerprints** (`ds_tag`) aus. Eine Heuristik (`depth` als `i8`) steuert die Verbreitung:
  - **Normale Fingerprints (positiv):** Altern pro Hop (+1).
  - **VIP-Fingerprints (negativ):** Starten bei `-1` (Betrugserkennung). Sie erhalten bei der Auswahl einen 2-Hop Vorsprung (`abs(depth) - 2`), um sich wie ein "Lauffeuer" zu verbreiten. 
  - **Schutz:** Symmetrie-Prüfung (nur Paare werden als VIP akzeptiert) und Loop-Protection (Bestand ist immun gegen "frischere" negative Updates von außen) verhindern Spam und Network Congestion.

- **Transaction Verification Layer (Layer 2):** Die Bibliothek implementiert nun die Kommunikation und Verifizierung für Layer 2. Dies umfasst die Interaktion mit L2-Gateways, die Validierung von L2-Signaturen und die Handhabung von Quarantäne-Zuständen bei Double-Spending oder Verifizierungsfehlern. Die Struktur ist für eine dezentrale Überprüfung durch "Chain of Authority" (CoA) Knoten optimiert.

- **FFI/WASM-Kompatibilität:** Rust-Typen und -Funktionen müssen so gestaltet sein, dass sie einfach über FFI und WASM exponiert werden können (z.B. durch Verwendung von `#[no_mangle]`, C-kompatiblen Datentypen und `wasm_bindgen`).

## 4\. Coding-Standards & Wichtige Regeln

- **Rust Best Practices:** Einhaltung der idiomatischen Rust-Programmierung, Fokus auf Sicherheit, Performance und Speichereffizienz.

- **Fehlerbehandlung:** Robuste Fehlerbehandlung mit Rusts `Result`-Typ.

- **Dokumentation:** Umfassende interne Dokumentation (Doc-Kommentare) für alle öffentlichen Funktionen und Strukturen.

- **Testen:** Umfassende Unit- und Integrationstests.

- **Keine externen Netzwerkaufrufe:** Die Core-Bibliothek soll keine direkten Netzwerkaufrufe für die Layer-2-Funktionalität enthalten. Diese Interaktionen werden von den übergeordneten Anwendungen gehandhabt, die `human_money_core` nutzen.

## 5\. Kernkonzepte aus dem Paper (Zusammenfassung)

Gutschein-Struktur: Das universelle Gutschein-Container-Format

Ein Gutschein ist im Wesentlichen eine Textdatei (repräsentiert als JSON), die alle möglichen Informationen enthält, die ein Gutschein jemals haben könnte. Jede einzelne Gutscheininstitution wird in diesem einheitlichen JSON-Schema abgebildet. Die spezifischen Regeln und Eigenschaften eines Gutscheintyps (wie "Minuto-Gutschein" oder "FreeTaler-Gutschein") werden in separaten Standard-Definitionen (voucher\_standard\_definitions) festgelegt.

Diese Definitionen werden als externe **TOML-Dateien** (z.B. aus einem `voucher_standards/`-Verzeichnis) bereitgestellt und zur Laufzeit geparst. Die TOML-Struktur ist klar in drei Blocker unterteilt:

- **`[metadata]`**: Enthält allgemeine Informationen wie Name und UUID des Standards.

- **`[template]`**: Definiert Werte (z.B. die `unit` des Nennwerts), die bei der Erstellung eines neuen Gutscheins direkt in diesen kopiert werden.

- **`[validation]`**: Beinhaltet feste Verhaltensregeln (`behavior_rules`) sowie dynamische, durch die CEL-Engine (Common Expression Language) evaluierte Geschäftsregeln (`dynamic_rules`), die zur detaillierten Überprüfung eines Gutscheins verwendet werden.

```json
{
  "voucher_standard": {
    "name": "STRING", // Name des Standards (z.B. "Minuto-Gutschein")
    "uuid": "STRING", // Eindeutige Kennung des Standards
    "standard_definition_hash": "STRING", // Hash der TOML-Definition zur Versionsbindung
    "template": { // Aus dem Standard kopierte Template-Daten
      "description": "STRING", // Menschenlesbare Beschreibung der Gutschein-Art
      "primary_redemption_type": "STRING", // Primärer Zweck (z.B. "goods_or_services")
      "divisible": "BOOLEAN", // Erlaubt der Standard Teilungen?
      "standard_minimum_issuance_validity": "STRING", // Standard-Gültigkeitsdauer (ISO 8601)
      "signature_requirements_description": "STRING", // Beschreibung der Bürgschafts-Regeln
      "footnote": "STRING" // Optionale Fußnote des Standards
    }
  },
  "voucher_id": "STRING", // Eindeutige ID dieses spezifischen Gutscheins
  "voucher_nonce": "STRING", // Zufallswert für den unvorhersehbaren Kettenstart (Layer 2 Schutz)
  "creation_date": "ISO-8601", // Erstellungszeitpunkt des Containers
  "valid_until": "ISO-8601", // Endgültiges Ablaufdatum des Gutscheins
  "non_redeemable_test_voucher": "BOOLEAN", // Kennzeichnung als Testobjekt
  "nominal_value": { // Der aufgedruckte Wert
    "unit": "STRING", // Währung/Einheit (z.B. "Minuten", "Euro")
    "amount": "STRING", // Betrag als String (für hohe Präzision/Dezimalzahlen)
    "abbreviation": "STRING, optional", // Kurzform (z.B. "min", "€")
    "description": "STRING, optional" // Detaillierte Beschreibung des Werts
  },
  "collateral": { // Optionale Hinterlegung/Besicherung
    "unit": "STRING", // Einheit der Besicherung
    "amount": "STRING", // Menge der Besicherung
    "abbreviation": "STRING, optional",
    "description": "STRING, optional",
    "type": "STRING, optional", // Art der Sicherheit (z.B. "Gold", "Community")
    "redeem_condition": "STRING, optional" // Bedingungen für die Einlösung der Sicherheit
  },
  "creator": { // Öffentliches Profil des Ausstellers
    "id": "STRING", // did:key Identität
    "first_name": "STRING, optional",
    "last_name": "STRING, optional",
    "organization": "STRING, optional",
    "..." : "..." // Weitere Felder gemäß PublicProfile
  },
  "signatures": [ // Alle statischen Signaturen (Ersteller, Bürgen, Notare)
    {
      "voucher_id": "STRING", // Verweis auf diesen Gutschein
      "signature_id": "STRING", // Eindeutige ID dieser Signatur (Hash über Metadaten)
      "signer_id": "STRING", // ID des Unterzeichners
      "signature": "STRING", // Die kryptographische Signatur (Ed25519)
      "signature_time": "ISO-8601", // Zeitpunkt der Unterzeichnung
      "role": "STRING", // Rolle (z.B. "creator", "guarantor", "notary")
      "details": { "..." : "..." } // Profil-Details zum Zeitpunkt der Signatur
    }
  ],
  "transactions": [ // Die dynamische Transaktionskette (Mini-Blockchain)
    {
      "t_id": "STRING", // Hash über Transaktionsdaten (Integritätsanker)
      "t_type": "STRING", // "init", "split" (Teilung), "" (Transfer)
      "t_time": "ISO-8601", // Zeitpunkt der Transaktion
      "prev_hash": "STRING", // Kryptographischer Link zur vorherigen Transaktion
      "receiver_ephemeral_pub_hash": "STRING", // Anker (Schloss) für den Empfänger (Hash des Stealth-Keys)
      "sender_id": "STRING, optional", // Identität des Senders (Layer 1 - Public Mode)
      "sender_identity_signature": "STRING, optional", // Soziale Signatur (Layer 1 - Public Mode)
      "recipient_id": "STRING", // Empfänger-ID (did:key oder "Anonym")
      "amount": "STRING", // Übertragener Teilbetrag
      "sender_remaining_amount": "STRING, optional", // Restguthaben beim Sender (nur bei Teilung)
      "sender_ephemeral_pub": "STRING, optional", // Reveal des Stealth-Keys (Preimage für prev_hash Check)
      "change_ephemeral_pub_hash": "STRING, optional", // Neuer Anker für das Wechselgeld des Senders
      "privacy_guard": "STRING, optional", // Verschlüsselter RecipientPayload (nur für Empfänger lesbar)
      "trap_data": { // Mathematische Falle bei Double-Spending (Identity Trap)
        "ds_tag": "STRING", // Deterministsicher Fingerprint des Inputs
        "u": "STRING", // Challenge-Scalar für den ZKP
        "blinded_id": "STRING", // Identitäts-Punkt V = m*U + ID
        "proof": "STRING" // Schnorr-Beweis über Wissen von m
      },
      "layer2_signature": "STRING, optional" // Technische Signatur (Layer 2)
    }
  ]
}
```

### NeueVoucherData Struktur

Diese Struktur bündelt alle notwendigen Daten zur Erstellung eines neuen Gutscheins:

- `validity_duration` (Option<String>): Optionaler String, der die Gültigkeitsdauer des Gutscheins angibt (z.B. "P5Y" für 5 Jahre). Wenn nicht angegeben, wird der Standardwert aus der Gutschein-Standard-Definition verwendet.
- `non_redeemable_test_voucher` (bool): Ein Boolean-Wert, das angibt, ob es sich um einen nicht einlösbaren Testgutschein handelt (true/false).
- `nominal_value` (ValueDefinition): Definiert den Wert, den der Gutschein repräsentiert. Verwendet die neue ValueDefinition-Struktur mit optionalen Feldern für Einheit, Betrag, Abkürzung und Beschreibung. Bei Gutscheinerstellung wird eine benutzerdefinierte Abkürzung bevorzugt; falls keine angegeben ist, wird die aus den Standard-Metadaten verwendet.
- `collateral` (Option<Collateral>): Optionale Informationen zur Besicherung des Gutscheins. Wird nur erstellt, wenn sowohl der Standard dies erlaubt als auch der Benutzer Angaben macht. Kann None sein, wenn keine Besicherung notwendig ist oder keine Angaben gemacht wurden.
- `creator_profile` (PublicProfile): Enthält detaillierte Informationen zum Ersteller des Gutscheins, wie Name, Adresse usw.

- **`voucher_id` & `voucher_nonce`**: Die `voucher_id` ist der globale Anker. Die `voucher_nonce` sorgt dafür, dass selbst zwei identisch erstellte Gutscheine unterschiedliche Start-Hashes haben, was die Anonymität auf Layer 2 erhöht.
- **`nominal_value` vs. `collateral`**: Der `nominal_value` repräsentiert den Wert *im System* (z.B. Zeit). Die `collateral` beschreibt die *Absicherung* außerhalb des Systems (z.B. Gold).
- **`creator` (PublicProfile)**: Detaillierte Identitätsinformationen des Ausstellers. Enthält Adressdaten, Kontaktdaten und optionale Koordinaten.

### Transaktionskette & P2PKH (Layer 2)

Die Transaktionskette folgt einem **Commitment-Reveal-Schema (Hybrid P2PKH)**, das Quantensicherheit und Privatsphäre vereint.

#### Felder im Detail:
- **`receiver_ephemeral_pub_hash` (Der Anker / Commitment)**: Dies ist der Hash eines einmaligen Stealth-Keys des Empfängers. Er dient als "Verschluss" der aktuellen Transaktion. Niemand außer dem Empfänger kann diesen Hash einem Nutzer zuordnen.
- **`sender_ephemeral_pub` (Das Reveal)**: In der *nächsten* Transaktion enthüllt der Sender den Public Key, dessen Hash im `receiver_ephemeral_pub_hash` der vorherigen Transaktion stand. Dies beweist das Recht zum Ausgeben.
- **`layer2_signature` (Technischer Besitz)**: Eine Ed25519-Signatur über die `t_id` (als Roh-Bytes für maximale Robustheit), ausgeführt mit dem nun enthüllten Stealth-Key (`sender_ephemeral_pub`). Sie beweist den technischen Besitz und autorisiert den L2-Lock.
- **`sender_identity_signature` (Sozialer Besitz)**: Eine optionale Signatur mit dem permanenten Identity-Key. Sie ist im "Stealth" Mode verboten und im "Public" Mode Pflicht.
- **Privacy Rule: `init` MUST be Public**: Unabhängig vom gewählten Privacy Mode eines Standards MÜSSEN `init` (Genesis) Transaktionen immer öffentlich (`public`) sein, um eine eindeutige Identifizierung des Gutschein-Erstellers zu ermöglichen.
- **`privacy_guard` (Verschlüsselter Kanal)**: Ein verschlüsselter Container (RecipientPayload), der via X25519 nur für den Empfänger lesbar ist. Er enthält den `next_key_seed`, damit der Empfänger weiß, welchen Schlüssel er generieren muss, um das Guthaben später weiterzugeben (**Forward Secrecy**).
- **`change_ephemeral_pub_hash`**: Bei Teilzahlungen (`split`) wird das Restgeld an einen neuen, vom Sender selbst kontrollierten Anker gesendet.

#### Sicherheit durch BLAKE3:
Da ruhende Guthaben nur als BLAKE3-Hashes (`receiver_ephemeral_pub_hash`) vorliegen, bieten sie Schutz vor zukünftigen Preimage-Angriffen durch Quantencomputer. Die Identität bleibt verborgen, bis das Guthaben ausgegeben wird.

### Double-Spending-Erkennung (Die Falle)

Ein Betrugsversuch wird durch eine mathematische Falle (**Identity Trap**) basierend auf Schnorr Non-Interactive Zero-Knowledge Proofs (NIZK) erkannt.

- **Double-Spend Tag (`ds_tag`):** Ein deterministischer Identifier des Inputs: `ds_tag = hash(prev_hash + sender_ephemeral_pub)`. Die Berechnung ist nun präfix-unabhängig, um konsistente Erkennung über alle Privacy-Modi hinweg zu garantieren. Kollidiert dieser Tag bei unterschiedlichen `t_id`s, liegt ein Double-Spend vor.
- **Mathematisches Hardening:** Die Hash-Berechnungen wurden auf **SHA3-256** (für allgemeine Daten) standardisiert und zentralisiert. Durch die Nutzung von `get_hash_from_slices` wird Malleability verhindert (Längenpräfixe für Segmente). Für interne kryptographische Primitive (HKDF, PBKDF2) wird weiterhin die SHA2-Familie genutzt.
- **The Trap:** Innerhalb der `trap_data` wird eine Relation $V = m \cdot U + ID$ genutzt. Wer denselben Input zweimal ausgibt, muss aufgrund der deterministischen Ableitung von $m$ (via HKDF) zwangsläufig seine Identität ($ID$) offenbaren. Ein Trap-Replay-Schutz verhindert die missbräuchliche Wiederverwendung von Trap-Beweisen.
- **Anonymisierte Analyse:** Auf Layer 2 werden nur Fingerprints ausgetauscht. Ein Server sieht keine Klartext-IDs oder Beträge, sondern nur den `ds_tag` und verschlüsselte Zeitstempel.
- **Beweis:** Ein Double-Spend-Beweis (`ProofOfDoubleSpend`) kombiniert die kollidierenden Transaktionen und ermöglicht die mathematische Extraktion der Täter-ID.

#### Erkennung ohne Layer-2-Server (durch Pfad-Vereinigung)

Ein Double Spend kann auch ohne einen zentralen Server erkannt werden, wenn sich die aufgespaltenen Transaktionspfade bei einem späteren Nutzer wieder treffen. Da Gutscheine im System zirkulieren und oft beim Ersteller wieder eingelöst werden, ist dies ein praxisnaher Anwendungsfall.

- **Mechanismus:** Ein Nutzer, der einen Gutschein erhält, kann dessen Transaktionshistorie mit den Historien von bereits erhaltenen oder archivierten Gutscheinen vergleichen.

- **Beispiel:** Der ursprüngliche Ersteller eines Gutscheins erhält später zwei unterschiedliche Gutschein-Dateien zur Einlösung zurück. Beide leiten ihre Herkunft von seinem ursprünglichen Gutschein ab. Beim Vergleich der Historien stellt er fest, dass beide Dateien eine unterschiedliche Transaktion enthalten, die aber vom selben `prev_hash` abstammt. Damit ist der Double Spend bewiesen.

- **Voraussetzung:** Diese Methode erfordert, dass Nutzer (insbesondere Akteure wie Ersteller, die Einlösungen akzeptieren) alte Gutschein-Zustände vorhalten, um eine Vergleichsbasis zu haben.

### Konfliktlösung: Die "Earliest Wins" Heuristik

Die Reaktion des Wallets auf einen nachgewiesenen Double Spend wurde verbessert, um eine pragmatische Offline-Lösung zu bieten.

- **Offline-Strategie:** Wenn ein Wallet einen Konflikt ohne ein autoritatives Urteil von einem Layer-2-Server feststellt, wendet es die "Der Früheste gewinnt"-Regel an.

  1.  Es entschlüsselt die Zeitstempel beider widersprüchlicher Transaktionen.

  2.  Der Gutschein-Zweig mit der Transaktion, die den **früheren Zeitstempel** hat, wird als wahrscheinlich legitim angesehen und bleibt `Active`.

  3.  Der Gutschein-Zweig mit der **späteren** Transaktion wird auf `VoucherStatus::Quarantined` gesetzt, um eine weitere Nutzung zu verhindern.

- **Layer-2-Urteil:** Ein von einem Server signiertes Urteil (`Layer2Verdict`) hat immer Vorrang vor der lokalen Heuristik. In diesem Fall bestimmt der Server, welcher Zweig gültig ist.

### Privacy Modes

In der `standard.toml` wird der Transparenzgrad gesteuert:

| Modus | Wert | Identität (sender_id) | Empfänger-ID |
| :--- | :--- | :--- | :--- |
| Öffentlich | `"public"` | **PFLICHT** (`did:key`) | **PFLICHT** (`did:key`) |
| Diskret | `"stealth"` | **VERBOTEN** | **HASH/ANONYM** |
| Flexibel | `"flexible"` | **OPTIONAL** | **FREIE WAHL** |

Der technische Layer 2 Schutz durch ephemere Schlüssel ist in **allen** Modi aktiv.

### Verschlüsselung & SecureContainer

Der Austausch von Daten (Bundles, Signaturanfragen) erfolgt via `SecureContainer`.
- **Anonymität:** Keine Klartext-IDs im Header.
- **Sicherheit:** Forward Secrecy durch ephemere X25519-Schlüssel.
- **Double Key Wrapping:** Sowohl Absender als auch Empfänger können den Inhalt entschlüsseln.
- **Payload:** Beinhaltet einen `RecipientPayload` mit dem Seed für den nächsten ephemeren Schlüssel.

## 6\. Aktueller Projektstrukturbaum

```
├── Cargo.lock
├── Cargo.toml
├── docs
│   └── de
│       ├── konliktmanagement.md
│       ├── spec
│       │   └── Spezifikation - Hybride Privatsphäre und Offline-Sicherheit für digitale Gutscheine.md
│       ├── standard-konzepte.md
│       └── zustands-management.md
├── examples
│   ├── playground_crypto_utils.rs
│   ├── playground_double_spend_analysis.rs
│   ├── playground_utils.rs
│   ├── playground_voucher_lifecycle.rs
│   └── playground_wallet.rs
├── LICENSE
├── README.md
├── sign_standards.sh
├── sign_test_standards.sh
├── src
│   ├── app_service
│   │   ├── api_readme.md
│   │   ├── app_queries.rs
│   │   ├── app_signature_handler.rs
│   │   ├── command_handler.rs
│   │   ├── conflict_handler.rs
│   │   ├── data_encryption.rs
│   │   ├── lifecycle.rs
│   │   └── mod.rs
│   ├── archive
│   │   ├── file_archive.rs
│   │   └── mod.rs
│   ├── bin
│   │   └── voucher-cli.rs
│   ├── error.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── models
│   │   ├── conflict.rs
│   │   ├── layer2_api.rs
│   │   ├── mod.rs
│   │   ├── profile.rs
│   │   ├── readme_de.md
│   │   ├── secure_container.rs
│   │   ├── signature.rs
│   │   ├── voucher.rs
│   │   └── voucher_standard_definition.rs
│   ├── services
│   │   ├── bundle_processor.rs
│   │   ├── conflict_manager.rs
│   │   ├── crypto_utils.rs
│   │   ├── decimal_utils.rs
│   │   ├── l2_gateway.rs
│   │   ├── mod.rs
│   │   ├── secure_container_manager.rs
│   │   ├── signature_manager.rs
│   │   ├── standard_manager.rs
│   │   ├── trap_manager.rs
│   │   ├── utils.rs
│   │   ├── voucher_manager.rs
│   │   └── voucher_validation.rs
│   ├── storage
│   │   ├── file_storage.rs
│   │   └── mod.rs
│   ├── test_utils.rs
│   └── wallet
│       ├── conflict_handler.rs
│       ├── instance.rs
│       ├── lifecycle.rs
│       ├── maintenance.rs
│       ├── mod.rs
│       ├── queries.rs
│       ├── signature_handler.rs
│       ├── tests.rs
│       ├── transaction_handler.rs
│       └── types.rs
├── tests
│   ├── architecture
│   │   ├── hardening.rs
│   │   ├── mod.rs
│   │   └── resilience_and_gossip.rs
│   ├── architecture_tests.rs
│   ├── core_logic
│   │   ├── lifecycle.rs
│   │   ├── math.rs
│   │   ├── mod.rs
│   │   ├── privacy_modes.rs
│   │   └── security
│   │       ├── double_spend_identification.rs
│   │       ├── double_spend.rs
│   │       ├── mod.rs
│   │       ├── privacy_evasion.rs
│   │       ├── standard_validation.rs
│   │       ├── state_and_collaboration.rs
│   │       ├── trap_verification.rs
│   │       └── vulnerabilities.rs
│   ├── core_logic_tests.rs
│   ├── flow_integrity.rs
│   ├── l2_integration_test.rs
│   ├── persistence
│   │   ├── archive.rs
│   │   ├── file_storage.rs
│   │   └── mod.rs
│   ├── persistence_tests.rs
│   ├── README.md
│   ├── services
│   │   ├── crypto.rs
│   │   ├── mod.rs
│   │   └── utils.rs
│   ├── services_tests.rs
│   ├── test_data
│   │   └── standards
│   │       ├── standard_behavior_rules.toml
│   │       ├── standard_conflicting_rules.toml
│   │       ├── standard_content_rules.toml
│   │       ├── standard_field_group_rules.toml
│   │       ├── standard_no_split.toml
│   │       ├── standard_path_not_found.toml
│   │       ├── standard_required_signatures.toml
│   │       ├── standard_strict_counts.toml
│   │       └── standard_strict_sig_description.toml
│   ├── validation
│   │   ├── business_rules.rs
│   │   ├── forward_compatibility.rs
│   │   ├── mod.rs
│   │   ├── privacy_modes.rs
│   │   ├── standard_definition.rs
│   │   └── unit_service.rs
│   ├── validation_tests.rs
│   ├── wallet_api
│   │   ├── general_workflows.rs
│   │   ├── hostile_bundles.rs
│   │   ├── hostile_standards.rs
│   │   ├── lifecycle_and_data.rs
│   │   ├── mixed_mode_vulnerability.rs
│   │   ├── mod.rs
│   │   ├── multi_identity_vulnerability.rs
│   │   ├── signature_workflows.rs
│   │   ├── state_management.rs
│   │   └── transactionality.rs
│   ├── wallet_api_tests.rs
│   └── security_audit_fixes.rs
├── update-docs.sh
├── validate_standards.sh
└── voucher_standards
    ├── minuto_v1
    │   └── standard.toml
    ├── readme_de.md
    ├── freetaler_v1
    │   └── standard.toml
    └── standard_template.toml

28 directories, 119 files
```

## 7\. Implementierte Kernfunktionen

Basierend auf den bereitgestellten Dateien:

### `src/app_service` Modul

Definiert den `AppService`, eine übergeordnete Fassade, die die `Wallet`-Logik für Client-Anwendungen (z.B. GUIs) vereinfacht.

- `pub struct AppService`
  - Verwaltet den Anwendungszustand (`Locked`/`Unlocked`).
  - Kapselt `UserIdentity` und `Storage`-Implementierung.
  - Stellt sicher, dass Zustandsänderungen im Wallet automatisch gespeichert werden.
- `pub fn new(base_storage_path: &Path) -> Result<Self, String>`
  - Initialisiert einen neuen `AppService` im `Locked`-Zustand mit einem Basis-Speicherpfad.
- `pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, String>`
  - Listet alle verfügbaren Profile aus der zentralen `profiles.json`-Datei.
- `pub fn generate_mnemonic(word_count: u32) -> Result<String, String>`
  - Generiert eine neue BIP-39 Mnemonic-Phrase.
- `pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String>`
  - Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
- `pub fn create_profile(&mut self, profile_name: &str, mnemonic: &str, passphrase: Option<&str>, user_prefix: Option<&str>, password: Option<&str>) -> Result<(), String>`
  - Erstellt ein komplett neues Wallet und Profil, speichert es und setzt den Service in den `Unlocked`-Zustand. Fügt einen Eintrag zur zentralen `profiles.json` hinzu.
- `pub fn login(&mut self, folder_name: &str, password: Option<&str>, cleanup_on_login: bool) -> Result<(), String>`
  - Entsperrt ein existierendes Wallet. Benötigt die Geheimnisse, um den Speicherort zu finden. Bietet eine Option, beim Login eine Speicherbereinigung durchzuführen.
- `pub fn recover_wallet_and_set_new_password(&mut self, folder_name: &str, mnemonic: &str, passphrase: Option<&str>, new_password: Option<&str>) -> Result<(), String>`
  - Stellt ein Wallet wieder her und setzt ein neues Passwort. Benötigt ebenfalls die Geheimnisse (`mnemonic`, `passphrase`, `prefix`), um den Speicherort zu finden.
- `pub fn logout(&mut self)`
  - Sperrt das Wallet und entfernt sensible Daten aus dem Speicher.
- `pub fn get_voucher_summaries(&self, voucher_standard_uuid_filter: Option<&[String]>, status_filter: Option<&[VoucherStatus]>) -> Result<Vec<VoucherSummary>, String>`
  - Gibt eine Liste von Zusammenfassungen aller Gutscheine im Wallet zurück, optional gefiltert nach Standard und Status.
- `pub fn get_total_balance_by_currency(&self) -> Result<Vec<AggregatedBalance>, String>`
  - Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung.
- `pub fn get_voucher_details(&self, local_id: &str) -> Result<VoucherDetails, String>`
  - Ruft eine detaillierte Ansicht für einen einzelnen Gutschein ab.
- `pub fn get_user_id(&self) -> Result<String, String>`
  - Gibt die User-ID des Wallet-Inhabers zurück.
- `pub fn create_new_voucher(&mut self, standard_toml_content: &str, lang_preference: &str, data: NewVoucherData, password: Option<&str>) -> Result<Voucher, String>`
  - Erstellt einen brandneuen Gutschein. Wenn der Gutschein aufgrund fehlender erforderlicher Signaturen (z.B. Bürgen) zunächst nicht vollständig gültig ist, wird er mit dem Status `VoucherStatus::Incomplete` erstellt, anstatt einen fatalen Fehler auszulösen. Der Gutschein wird trotzdem zum Wallet hinzugefügt und der Zustand gespeichert.
- `pub fn create_transfer_bundle(&mut self, request: MultiTransferRequest, standard_definitions_toml: &HashMap<String, String>, archive: Option<&dyn VoucherArchive>, password: Option<&str>) -> Result<CreateBundleResult, String>`
  - Erstellt eine(n oder mehrere) Transaktion(en) für einen oder mehrere Quell-Gutscheine, verpackt sie in ein `SecureContainer`-Bundle und speichert den neuen Wallet-Zustand. Akzeptiert eine `MultiTransferRequest`-Struktur, die eine Liste von Quell-Gutscheinen und Beträgen enthält. Gibt ein `CreateBundleResult` zurück, das detaillierte Informationen über die involvierten Quell-Gutscheine enthält.
  - Implementiert eine **Selbstheilungsfunktion**: Wenn ein interner Inkonsistenzfehler erkannt wird (z.B. ein 'Active'-Gutschein, der bereits versendet wurde), wird der inkonsistente Gutschein automatisch in den Quarantänezustand (`Quarantined`) verschoben und der Wallet-Zustand gespeichert, um zukünftige Verwendung des fehlerhaften Gutscheins zu verhindern.
- `pub fn receive_bundle(&mut self, bundle_data: &[u8], standard_definitions_toml: &HashMap<String, String>, archive: Option<&dyn VoucherArchive>, password: Option<&str>) -> Result<ProcessBundleResult, String>`
  - Verarbeitet ein empfangenes Transaktions-Bundle, validiert die enthaltenen Gutscheine gegen die bereitgestellten Standard-Definitionen und speichert den neuen Wallet-Zustand. Gibt ein `ProcessBundleResult` zurück, das auch detaillierte Informationen über die involvierten Gutscheine und Transfer-Zusammenfassungen enthält.
- `pub fn create_signing_request_bundle(local_instance_id: &str, recipient_id: &str) -> Result<Vec<u8>, String>`
  - Erstellt ein Bundle, um einen Gutschein zur Unterzeichnung an einen Bürgen zu senden.
- `pub fn create_detached_signature_response_bundle(&self, voucher_to_sign: &Voucher, role: &str, include_details: bool, original_sender_id: &str) -> Result<Vec<u8>, String>`
  - Erstellt eine losgelöste Signatur als Antwort auf eine Signaturanfrage. Die Funktion akzeptiert nun explizit die `role` (z.B. "guarantor", "notary"), und ein Flag `include_details`, das bestimmt, ob die öffentlichen Profildaten des Unterzeichners in die Signatur eingebettet werden sollen.
- `pub fn process_and_attach_signature(&mut self, container_bytes: &[u8], standard_toml_content: &str, password: Option<&str>) -> Result<(), String>`
  - Verarbeitet eine empfangene losgelöste Signatur, validiert den Gutschein neu gegen den Standard, fügt die Signatur hinzu und speichert den Zustand.
- `pub fn save_encrypted_data(name: &str, data: &[u8], password: Option<&str>) -> Result<(), String>`
  - Speichert einen beliebigen Byte-Slice verschlüsselt auf der Festplatte.
- `pub fn run_storage_cleanup(&mut self) -> Result<CleanupReport, VoucherCoreError>`
  - Führt die Speicherbereinigung für Fingerprints und deren Metadaten durch.
- `pub fn load_encrypted_data(name: &str, password: Option<&str>) -> Result<Vec<u8>, String>`
  - Lädt und entschlüsselt einen zuvor gespeicherten, beliebigen Datenblock.
- `pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, String>`
  - Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
- `pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, String>`
  - Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
- `pub fn create_resolution_endorsement(&self, proof_id: &str, notes: Option<String>) -> Result<ResolutionEndorsement, String>`
  - Erstellt eine signierte Beilegungserklärung für einen Konflikt.
- `pub fn import_resolution_endorsement(&mut self, endorsement: ResolutionEndorsement, password: Option<&str>) -> Result<(), String>`
  - Importiert eine Beilegungserklärung, fügt sie dem entsprechenden Konfliktbeweis hinzu und speichert den Wallet-Zustand. Bietet **Import-Schutz**: Lokal bereits existierende Beweise (insb. manuelle Beilegungen) werden nicht überschrieben.
- `pub fn check_reputation(&self, user_id: &str) -> Result<TrustStatus, String>`
  - Führt eine Reputationsabfrage im lokalen `ProofStore` durch. Erkennt Wiederholungstäter und berücksichtigt manuelle `local_override` Entscheidungen.
- `pub fn unlock_session(&mut self, password: &str, duration: chrono::Duration) -> Result<(), String>`: Sperrt eine Session für den angegebenen Zeitraum, um wiederholte Passwort-Eingaben zu vermeiden. Ermöglicht "Remember Password" Funktionalität in Client-Anwendungen.

#### Authentifizierungsmodell

Das `AppService` implementiert ein flexibles Authentifizierungsmodell, um "Remember Password"-Funktionalität in Client-Anwendungen zu unterstützen. Zustandsändernde Operationen (wie `create_transfer_bundle`, `save_encrypted_data`, `process_and_attach_signature` usw.) akzeptieren `password: Option<&str>`.

Zwei Modi der Operation:
- **Modus A (Immer fragen):** Übergabe von `Some(password)` verwendet das Passwort direkt für diese einzelne Operation. Alle bestehenden Tests wurden auf diesen Modus aktualisiert.
- **Modus B (Session):** Ein Benutzer kann einmal `AppService::unlock_session(password, duration)` aufrufen. Nachfolgende Aufrufe von Operationen mit `password: None` verwenden einen zwischengespeicherten, zeitlich begrenzten Session-Schlüssel.

#### Thread-Sicherheit und Locking

Das `AppService` integriert einen **pessimistischen Locking-Mechanismus** zur Verhinderung von "stale state" Double-Spending. Alle zustandsändernden Operationen (`create_new_voucher`, `create_transfer_bundle`, `receive_bundle`, `process_and_attach_signature`, `import_resolution_endorsement`, `save_encrypted_data`, `load_encrypted_data`) verwenden einen `WalletLockGuard` (RAII), der automatisch eine exklusive Sperre auf dem Wallet-Verzeichnis erlangt und freigibt. Dies verhindert, dass gleichzeitige Prozesse (z.B. mehrere Instanzen einer App) dasselbe Wallet modifizieren und so inkonsistente Zustände erzeugen.

Implementierungsdetails:
- Fügt `SessionCache` zum `AppState::Unlocked`-Zustand hinzu, um den abgeleiteten Schlüssel zu halten.
- Einführung eines `AuthMethod`-Enums (`Password` | `SessionKey`) auf der `Storage`-Trait-Ebene.
- `FileStorage` und `Wallet::save` wurden aktualisiert, um `AuthMethod` zu akzeptieren.
- Implementiert Session-Timeout und "Sliding Window"-Logik via `get_session_key` und `refresh_session_activity`.
- Fügt einen "Storage Anchor"-Fix beim Login/Create_Profile hinzu, um sicherzustellen, dass die Session-Schlüssel-Ableitung für neue Wallets funktioniert.

### `src/wallet` Modul

Das `wallet`-Modul wurde umfassend refaktorisiert, um die Komplexität zu reduzieren und die Verantwortlichkeiten klarer zu trennen. Die `Wallet`-Struktur ist weiterhin die zentrale Fassade der Kernlogik, delegiert aber spezifische Aufgaben an neue Sub-Module.

- `pub struct Wallet` (`mod.rs`)
  - Hält `UserProfile`, `VoucherStore`, `BundleMetadataStore`, die getrennten `KnownFingerprints`, `OwnFingerprints`, `ProofStore` und den neuen `CanonicalMetadataStore` für Metadaten als In-Memory-Zustand.
  - Enthält neue Strukturen: `MultiTransferRequest` für die Anforderung von Transfers mit mehreren Quellen und `SourceTransfer` für die Definition einzelner Quellpositionen in einem Transfer.

- **Lebenszyklus & Kernoperationen** (`lifecycle.rs`)
  - `pub fn new_from_mnemonic(...)`: Erstellt ein brandneues Wallet.
  - `pub fn load(...)`: Lädt ein existierendes Wallet aus dem Storage.
  - `pub fn save(...)`: Speichert den aktuellen Zustand des Wallets.
  - `pub fn create_new_voucher(...)`: Erstellt einen brandneuen Gutschein und fügt ihn direkt zum Wallet hinzu.

- **Transaktionsverarbeitung** (`transaction_handler.rs`)
  - `pub fn create_and_encrypt_transaction_bundle(...)`: Erstellt ein `TransactionBundle`, verpackt es und aktualisiert den Wallet-Zustand.
  - `pub fn process_encrypted_transaction_bundle(...)`: Verarbeitet eingehende Gutscheine oder Signaturen, inkl. der Verarbeitung von empfangenen Fingerprints. Implementiert umfassenden Schutz gegen Replay-Angriffe durch zwei Schichten (Bundle-ID-Prüfung und Fingerprint-Prüfung) und weist eingehende Bundles zurück, die nicht explizit für den Wallet-Besitzer bestimmt sind.
  - `pub fn execute_multi_transfer_and_bundle(...)`: Führt einen Transfer durch, der Guthaben aus mehreren Quell-Gutscheinen kombinieren kann. Ersetzt die alte `create_transfer`-Methode. Akzeptiert eine `MultiTransferRequest`-Struktur mit einer Liste von Quellen und führt alle Transaktionen in einem einzigen Bundle durch. Managt den internen Zustand (Archivierung, Restbetrag) und wählt Fingerprints für das Gossip-Protokoll.
  - `pub fn rederive_secret_seed(...)`: **Stateless Seed Recovery.** Leitet ephemere Schlüssel on-demand aus der Identität und dem Gutschein ab, anstatt sie zu speichern.
  - `fn _execute_single_transfer(...)`: Führt die Zustandsveränderung für EINEN Gutschein im Wallet durch. (Private Hilfsmethode)

- **Wartung & Speicher-Management** (`maintenance.rs`)
  - `pub fn run_storage_cleanup(...)`: Führt eine mehrstufige Bereinigung der Fingerprint-Stores durch (abgelaufen, dann nach `depth`).
  - `pub fn rebuild_derived_stores(...)`: Rekonstruiert alle abgeleiteten Stores (Fingerprints, Metadaten) aus dem `VoucherStore`.
  - `pub fn add_voucher_instance(...)`: Fügt eine Gutscheininstanz zum Wallet hinzu.
  - `pub fn get_voucher_instance(...)`: Ruft eine Gutscheininstanz ab.
  - `pub fn update_voucher_status(...)`: Aktualisiert den Status einer Gutscheininstanz.
  - `pub fn calculate_local_instance_id(...)`: Berechnet eine deterministische ID für eine Gutscheininstanz.
  - `pub(super) fn find_transaction_in_stores(...)`: Sucht eine Transaktion anhand ihrer ID zuerst im aktiven `voucher_store` und dann im `VoucherArchive`.
  - `pub(super) fn find_voucher_for_transaction(...)`: Sucht einen Gutschein anhand einer enthaltenen Transaktions-ID.
  - `pub(super) fn find_local_voucher_by_tx_id(...)`: Findet die lokale ID und den Status eines Gutscheins anhand einer enthaltenen Transaktions-ID.

- **Abfragen & Ansichten** (`queries.rs`)
  - `pub fn list_vouchers(&self) -> Vec<VoucherSummary>`: Gibt eine vereinfachte Liste aller Gutscheine zurück.
  - `pub fn get_voucher_details(...) -> Result<VoucherDetails, ...>`: Gibt detaillierte Informationen zu einem Gutschein zurück.
  - `pub fn get_user_id(&self) -> &str`: Gibt die ID des Wallet-Inhabers zurück.
  - `pub fn get_total_balance_by_currency(&self) -> Vec<AggregatedBalance>`: Aggregiert alle Guthaben nach Währung.

- **Signatur-Workflows** (`signature_handler.rs`)
  - `pub fn create_signing_request(...)`: Erstellt einen `SecureContainer` zur Anforderung einer Signatur.
  - `pub fn create_detached_signature_response(...)`: Erstellt eine signierte Antwort auf eine Anfrage.
  - `pub fn process_and_attach_signature(...)`: Verarbeitet eine empfangene Signatur und fügt sie dem passenden Gutschein hinzu.

- **Konflikt-Management** (`conflict_handler.rs`)
  - `pub fn select_fingerprints_for_bundle(...) -> Result<(Vec<TransactionFingerprint>, HashMap<String, i8>), VoucherCoreError>`: Wählt Fingerprints für ein Bundle aus. Nutzt **Effektive Tiefe** (`abs(depth) - 2` für VIPs), um Betrugsbeweise vorrangig zu versenden.
  - `pub fn process_received_fingerprints(...)`: Verarbeitet empfangene Fingerprints. Implementiert **VIP-Symmetrie-Prüfung** und **Loop-Protection** (Bestands-Immunität gegen Replay-Updates).

- **Voucher Instance Management** (`instance.rs`)
  - `pub enum ValidationFailureReason`: Erfasst den genauen, für den Nutzer behebbaren Grund, warum ein Gutschein als unvollständig (`Incomplete`) eingestuft wird.
  - `pub enum VoucherStatus`: Definiert den Status eines Gutscheins (z.B. `Incomplete`, `Active`, `Archived`, `Quarantined`).
  - `pub struct VoucherInstance`: Repräsentiert eine Instanz eines Gutscheins mit einem bestimmten Status.

- **Typdefinitionen** (`types.rs`)
  - Definiert öffentliche Datenstrukturen wie `MultiTransferRequest`, `SourceTransfer`, `TransferSummary`, `ProcessBundleResult`, `DoubleSpendCheckResult`, `InvolvedVoucherInfo`, `CreateBundleResult`, `CleanupReport`, `AggregatedBalance`, `VoucherSummary`, `ProofOfDoubleSpendSummary`, `VoucherDetails`, `TrustStatus`.

- **Tests** (`tests.rs`)
  - Enthält umfassende Unit-Tests für die Wallet-Logik.

### `src/storage` Modul (`mod.rs`, `file_storage.rs`)

Definiert die Abstraktion für die persistente Speicherung und stellt eine Standardimplementierung für das Dateisystem bereit.

- `pub enum StorageError`: Ein generischer Fehler-Typ für alle Speicheroperationen (z.B. `AuthenticationFailed`, `NotFound`, `InvalidFormat`, `Io`, `Generic`, `LockFailed`).
- `pub enum AuthMethod`: Definiert die Authentifizierungsmethode für den Zugriff auf den Speicher (z.B. `Password`, `Mnemonic`, `RecoveryIdentity`, `SessionKey`).
- `pub trait Storage`
  - `load_wallet(...)`: Lädt und entschlüsselt das Kern-Wallet (Profil und VoucherStore).
  - `save_wallet(...)`: Speichert und verschlüsselt das Kern-Wallet (Profil und VoucherStore).
  - `reset_password(...)`: Setzt das Passwort zurück, indem es das Passwort-Schloss mit dem Wiederherstellungs-Schlüssel neu erstellt.
  - `profile_exists()`: Prüft, ob bereits ein Profil am Speicherort existiert.
  - `load_known_fingerprints(...)`: Lädt und entschlüsselt den `KnownFingerprints`-Store.
  - `save_known_fingerprints(...)`: Speichert und verschlüsselt den `KnownFingerprints`-Store.
  - `load_own_fingerprints(...)`: Lädt und entschlüsselt den kritischen `OwnFingerprints`-Store.
  - `save_own_fingerprints(...)`: Speichert und verschlüsselt den kritischen `OwnFingerprints`-Store.
  - `load_bundle_metadata(...)`: Lädt und entschlüsselt die Metadaten der Transaktionsbündel.
  - `save_bundle_metadata(...)`: Speichert und verschlüsselt die Metadaten der Transaktionsbündel.
  - `load_proofs(...)`: Lädt und entschlüsselt den ProofStore.
  - `save_proofs(...)`: Speichert und verschlüsselt den ProofStore.
  - `load_fingerprint_metadata(...)`: Lädt den kanonischen Speicher für Fingerprint-Metadaten.
  - `save_fingerprint_metadata(...)`: Speichert den kanonischen Speicher für Fingerprint-Metadaten.
  - `save_arbitrary_data(...)`: Speichert einen beliebigen, benannten Datenblock verschlüsselt.
  - `load_arbitrary_data(...)`: Lädt einen beliebigen, benannten und verschlüsselten Datenblock.
  - `lock()`: Erlangt eine exklusive Sperre für das Wallet-Verzeichnis, um gleichzeitige Modifikationen zu verhindern.
  - `unlock()`: Gibt die exklusive Sperre frei.
  - `get_lock_file_path()`: Gibt den Pfad zur Sperrdatei zurück.
- `pub struct WalletLockGuard`: Ein RAII-Guard, der sicherstellt, dass eine Sperre automatisch freigegeben wird, wenn der Guard aus dem Geltungsbereich fällt. Wird für transaktionale Operationen wie `create_transfer_bundle` oder `receive_bundle` verwendet.
- `pub struct FileStorage`
  - `new(...)`: Erstellt eine neue `FileStorage`-Instanz für ein spezifisches Benutzerverzeichnis.
  - Implementiert den `Storage`-Trait.
  - Speichert die Daten jedes Profils in einem eigenen **anonymen Unterverzeichnis**, um die Privatsphäre zu erhöhen.
  - Implementiert die "Zwei-Schloss"-Mechanik mit Key-Wrapping für den Passwort-Zugriff und die Mnemonic-Wiederherstellung.
  - Bietet eine Funktion (`reset_password`) zum Zurücksetzen des Passworts, wenn der Benutzer sein Passwort vergessen hat.
  - Implementiert ein **pessimistisches Locking-Mechanismus** mit einer `.wallet.lock`-Datei, die die PID des besitzenden Prozesses enthält. Verwendet `sysinfo`, um veraltete Sperren von abgestürzten Prozessen zu erkennen und zu entfernen. Beinhaltet einen Re-entrancy-Check, um zu verhindern, dass derselbe Prozess sich selbst blockiert.

### `src/archive` Modul (`mod.rs`, `file_archive.rs`)

Definiert die Abstraktion für ein persistentes Archiv von Gutschein-Zuständen.

- `pub trait VoucherArchive`
  - `archive_voucher(...)`: Speichert eine Kopie des übergebenen Gutschein-Zustands bedingungslos im Archiv.
  - `get_archived_voucher(...)`: Ruft einen archivierten Gutschein anhand seiner ID ab.
  - `find_transaction_by_id(...)`: Findet einen Gutschein und die darin enthaltene Transaktion anhand der Transaktions-ID.
  - `find_voucher_by_tx_id(...)`: Findet einen Gutschein anhand einer enthaltenen Transaktions-ID.
  - Wallet-Methoden, die ein Archiv verwenden, akzeptieren nun `&dyn VoucherArchive` (dynamic dispatch).
- `pub struct FileVoucherArchive`
  - Eine Implementierung, die jeden archivierten Gutschein-Zustand als separate JSON-Datei in einer **hierarchischen Struktur** speichert: `{archive_dir}/{voucher_id}/{t_id}.json`.

### `services::bundle_processor` Modul

Kapselt die zustandslose Logik für das Erstellen, Verschlüsseln, Öffnen und Verifizieren von `TransactionBundle`-Objekten.

- `pub fn create_and_encrypt_bundle(identity: &UserIdentity, vouchers: Vec<Voucher>, recipient_id: &str, notes: Option<String>, forwarded_fingerprints: Vec<TransactionFingerprint>, fingerprint_depths: HashMap<String, u8>, sender_profile_name: Option<String>) -> Result<(Vec<u8>, TransactionBundle), VoucherCoreError>`: Erstellt ein `TransactionBundle`, verpackt es in einen `SecureContainer` und serialisiert diesen.
- `pub fn open_and_verify_bundle(identity: &UserIdentity, container_bytes: &[u8]) -> Result<TransactionBundle, VoucherCoreError>`: Öffnet einen `SecureContainer`, validiert den Inhalt als `TransactionBundle` und verifiziert dessen digitale Signatur.

### `services::conflict_manager` Modul

Dieses Modul kapselt die gesamte Geschäftslogik zur Erkennung, Verifizierung und Verwaltung von Double-Spending-Konflikten.

- `pub fn create_fingerprint_for_transaction(transaction: &Transaction, voucher: &Voucher) -> Result<TransactionFingerprint, VoucherCoreError>`: Erstellt einen einzelnen, anonymisierten Fingerprint für eine Transaktion, inklusive des verschlüsselten Zeitstempels.
- `pub fn scan_and_rebuild_fingerprints(voucher_store: &VoucherStore, user_id: &str) -> Result<(OwnFingerprints, KnownFingerprints), VoucherCoreError>`: Baut die Fingerprint-Stores aus dem `VoucherStore` neu auf und partitioniert sie korrekt.
- `pub fn check_for_double_spend(own_fingerprints: &OwnFingerprints, known_fingerprints: &KnownFingerprints) -> DoubleSpendCheckResult`: Führt eine Double-Spend-Prüfung durch, indem die nun getrennten `OwnFingerprints` und `KnownFingerprints` Stores kombiniert werden.
- `pub fn create_proof_of_double_spend(offender_id: String, fork_point_prev_hash: String, conflicting_transactions: Vec<Transaction>, voucher_valid_until: String, reporter_identity: &UserIdentity) -> Result<ProofOfDoubleSpend, VoucherCoreError>`: Erstellt einen fälschungssicheren, portablen Beweis für einen Double-Spend-Versuch mit deterministischer `proof_id`.
- `pub fn create_and_sign_resolution_endorsement(proof_id: &str, victim_identity: &UserIdentity, notes: Option<String>) -> Result<ResolutionEndorsement, VoucherCoreError>`: Erstellt eine signierte Beilegungserklärung für einen Konflikt.
- `pub fn cleanup_known_fingerprints(known_fingerprints: &mut KnownFingerprints)`: Entfernt alle abgelaufenen Fingerprints aus den nicht-kritischen Speichern.
- `pub fn cleanup_expired_histories(own_fingerprints: &mut OwnFingerprints, known_fingerprints: &mut KnownFingerprints, now: &DateTime<chrono::Utc>, grace_period: &chrono::Duration)`: Bereinigt die persistente Fingerprint-History basierend auf einer längeren Aufbewahrungsfrist.
- `pub fn export_own_fingerprints(own_fingerprints: &OwnFingerprints) -> Result<Vec<u8>, VoucherCoreError>`: Serialisiert die Historie der eigenen gesendeten Transaktionen für den Export.
- `pub fn import_foreign_fingerprints(known_fingerprints: &mut KnownFingerprints, data: &[u8]) -> Result<usize, VoucherCoreError>`: Importiert und merged fremde Fingerprints in den Speicher.
- `pub fn encrypt_transaction_timestamp(transaction: &Transaction) -> Result<u128, VoucherCoreError>`: Verschlüsselt einen Transaktionszeitstempel via XOR für die anonymisierte Analyse auf Layer 2.
- `pub fn decrypt_transaction_timestamp(transaction: &Transaction, encrypted_nanos: u128) -> Result<u128, VoucherCoreError>`: Entschlüsselt den Zeitstempel einer Transaktion.

### `src/services/trap_manager` Modul

Implementiert die "Mathematische Falle" (Identity Trap) gemäß Spezifikation.

- `pub fn derive_m(...)`: Leitet den geheimen Slope $m$ via HKDF ab (gebunden an `prev_hash` und `prefix`).
- `pub fn generate_trap(...)`: Erzeugt `TrapData` (Blinded ID, ZKP) für eine Transaktion.
- `pub fn verify_trap(...)`: Verifiziert die mathematische Korrektest von Trap-Daten und ZKP.
- `pub fn hash_to_scalar(...)`: Deterministische Abbildung von Daten auf einen Skalar (SHA-512).

### `services::crypto_utils` Modul

Enthält kryptographische Hilfsfunktionen für Schlüsselgenerierung, Hashing, Signaturen und User-ID-Verwaltung.

- `pub fn generate_mnemonic(word_count: usize, language: Language) -> Result<String, Box<dyn std::error::Error>>`: Generiert eine mnemonic phrase mit angegebener Wortzahl.
- `pub fn validate_mnemonic_phrase(phrase: &str) -> Result<(), String>`: Validiert eine BIP-39 mnemonic phrase.
- `pub fn get_hash(input: impl AsRef<[u8]>) -> String`: Berechnet einen SHA3-256 Hash und gibt ihn als base58-kodierten String zurück.
- `pub fn get_short_hash_from_user_id(user_id: &str) -> [u8; 4]`: Erzeugt einen 4-Byte-Kurz-Hash aus der User-ID für speichereffizientes Tracking.
- `pub fn derive_ephemeral_key_pair(...) -> Result<(SigningKey, EdPublicKey), VoucherCoreError>`: **Context-Bound Key Derivation.** Leitet ephemere Schlüssel deterministisch ab und bindet sie mathematisch an ein `context_prefix`, um Identity-Hopping zu verhindern.
- `pub fn perform_diffie_hellman(...) -> Result<[u8; 32], VoucherCoreError>`: Führt X25519 DH-Austausch mit HKDF-Expansion und Kanonisierung der Public Keys durch.
- `pub fn encrypt_data(...)` / `pub fn decrypt_data(...)`: Authentifizierte Verschlüsselung via ChaCha20Poly1305.
- `pub fn create_user_id(...)`: Erzeugt DID-kompatible User-IDs mit obligatorischem Präfix und Prüfsumme.
- `pub fn get_hash(...)`: Standard-Hashfunktion (SHA3-256) mit Base58-Kodierung.
- `pub fn get_pubkey_from_user_id(user_id: &str) -> Result<EdPublicKey, VoucherCoreError>`: Extrahiert den Ed25519 Public Key aus einer User-ID.
- `pub fn sign_ed25519(signing_key: &SigningKey, message: &[u8]) -> Signature`: Signiert eine Nachricht mit Ed25519.
- `pub fn verify_ed25519(public_key: &EdPublicKey, message: &[u8], signature: &Signature) -> bool`: Verifiziert eine Ed25519-Signatur.
- `pub fn encode_base64(data: &[u8]) -> String`: Kodiert Daten in URL-safe Base64.
- `pub fn decode_base64(encoded_data: &str) -> Result<Vec<u8>, VoucherCoreError>`: Dekodiert URL-safe Base64.
- `pub fn decrypt_data(key: &[u8; 32], encrypted_data_with_nonce: &[u8]) -> Result<Vec<u8>, SymmetricEncryptionError>`: Symmetrisch entschlüsselt Daten.

### `services::decimal_utils` Modul

Enthält Hilfsfunktionen zur konsistenten Validierung und Formatierung von `Decimal`-Werten.

- `pub fn validate_precision(amount: &Decimal, allowed_places: u32) -> Result<(), VoucherCoreError>`: Validiert, dass ein Decimal-Wert die erlaubte Anzahl Nachkommastellen nicht überschreitet.
- `pub fn format_for_storage(amount: &Decimal, places: u32) -> String`: Formatiert einen Decimal-Wert in das kanonische Speicherformat.

### `services::secure_container_manager` Modul

Stellt die Kernlogik für den **anonymisierten und weiterleitungs-sicheren** `SecureContainer` bereit, der für den Austausch von Daten (z.B. Bundles, Signaturanfragen) verwendet wird.

- `pub fn create_secure_container(sender_identity: &UserIdentity, recipient_ids: &[String], payload: &[u8], content_type: PayloadType) -> Result<SecureContainer, VoucherCoreError>`: Erstellt einen **anonymen, weiterleitungs-sicheren** `SecureContainer`. Ein symmetrischer Payload-Schlüssel wird für jeden Empfänger **und den Sender selbst** mittels eines **ephemeren Diffie-Hellman-Austauschs (X25519)** und Key-Wrapping verschlüsselt. Der Container enthält keine direkten Identifikatoren und wird als Ganzes signiert.
- `pub fn open_secure_container(container: &SecureContainer, recipient_identity: &UserIdentity) -> Result<Vec<u8>, VoucherCoreError>`: Entschlüsselt den Payload, indem es versucht, den Payload-Schlüssel mit dem privaten Schlüssel des Nutzers (als Sender oder Empfänger) und dem öffentlichen ephemeren Schlüssel des Containers zu entschlüsseln. Die Signatur des Containers muss vom Aufrufer separat verifiziert werden, da die `sender_id` erst nach der Entschlüsselung bekannt ist.

### `services::l2_gateway` Modul
Dieses Modul implementiert die Kommunikation mit Layer 2 Instanzen.
- `pub struct L2Gateway`: Verwaltet die Verbindung und Protokoll-Logik für L2.
- `pub fn submit_transaction(...)`: Sendet eine Transaktion zur Verifizierung an L2.
- `pub fn query_verdict(...)`: Fragt ein L2-Urteil für einen Konflikt ab.

### `src/services/signature_manager` Modul

Enthält die zustandslose Geschäftslogik für die Erstellung und kryptographische Validierung von losgelösten Signaturen (`DetachedSignature`).

- `pub fn complete_and_sign_detached_signature(mut signature_data: DetachedSignature, signer_identity: &UserIdentity, details: Option<PublicProfile>, voucher_id: &str) -> Result<DetachedSignature, VoucherCoreError>`: Nimmt unvollständige Signatur-Metadaten, berechnet die `signature_id` durch Hashing des kanonischen Inhalts, fügt optionale öffentliche Profildaten hinzu und fügt die digitale Signatur des Unterzeichners hinzu.
- `pub fn validate_detached_signature(signature_data: &DetachedSignature) -> Result<(), VoucherCoreError>`: Validiert eine losgelöste Signatur, indem die `signature_id` neu berechnet und die kryptographische Signatur gegen die ID und den Public Key des Unterzeichners geprüft wird.

### `services::standard_manager` Modul

Dieses Modul enthält die Logik zur Verarbeitung und Verifizierung von Gutschein-Standard-Definitionen (TOML-Dateien).

- `pub fn verify_and_parse_standard(toml_str: &str) -> Result<(VoucherStandardDefinition, String), VoucherCoreError>`: Parst einen TOML-String in eine `VoucherStandardDefinition`. Kanonisiert die Definition (ohne Signatur) in einen stabilen JSON-String. Berechnet den SHA3-256 Hash des kanonischen JSON-Strings (dies ist der "Konsistenz-Hash"). Verifiziert die im TOML enthaltene Ed25519-Signatur gegen den berechneten Hash. Gibt bei Erfolg die verifizierte Definition und den Konsistenz-Hash zurück.
- `pub fn get_localized_text<'a>(texts: &'a [LocalizedText], lang_preference: &str) -> Option<&'a str>`: Löst einen lokalisierten Text gemäß einer definierten Fallback-Logik auf.

### `services::utils` Modul

Enthält allgemeine Hilfsfunktionen, z.B. für Zeitstempel und kanonische Serialisierung.

- `pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error>`: Serialisiert in kanonischen JSON-String gemäß RFC 8785.
- `pub fn get_timestamp(years_to_add: i32, end_of_year: bool) -> String`: Gibt einen Zeitstempel in ISO 8601-Format zurück, optional mit Jahren addiert und/oder am Jahresende.
- `pub fn get_current_timestamp() -> String`: Gibt den aktuellen Zeitstempel in ISO 8601-Format zurück.

### `services::voucher_manager` Modul

Dieses Modul stellt die Kernlogik für die Erstellung und Verarbeitung von Gutscheinen bereit.

- `pub fn from_json(json_str: &str) -> Result<Voucher, VoucherCoreError>`: Deserialisiert einen JSON-String in ein Voucher-Struct.
- `pub fn to_json(voucher: &Voucher) -> Result<String, VoucherCoreError>`: Serialisiert ein Voucher-Struct in einen formatierten JSON-String.
- `pub struct NewVoucherData`: Hilfsstruktur für die Erstellung eines neuen Gutscheins.
- `pub fn create_voucher(data: NewVoucherData, verified_standard: &VoucherStandardDefinition, standard_hash: &str, creator_signing_key: &SigningKey, lang_preference: &str) -> Result<Voucher, VoucherCoreError>`: Orchestriert die Erstellung eines neuen, vollständigen Gutscheins. Erzeugt eine `voucher_nonce`, um den initialen `prev_hash` unvorhersehbar zu machen und so die Anonymität des Erstellers auf Layer 2 zu schützen. Nutzt eine korrigierte Logik zur Berechnung von Gültigkeitsdauern. Implementiert einen **"Gatekeeper"-Validierungsmechanismus** für `issuance_minimum_validity_duration`: Verhindert die Erstellung von Gutscheinen, deren Gültigkeitsdauer die im Standard definierte Mindestgültigkeit unterschreitet (z.B. bei Erstellung mit zu kurz gewählter Gültigkeitsdauer). Nimmt den **Konsistenz-Hash** des verifizierten Standards entgegen und bettet ihn in den Gutschein ein. Verwendet die Logik zur Auswahl des mehrsprachigen Beschreibungstextes aus dem Standard.
- `pub fn add_iso8601_duration(start_date: DateTime<Utc>, duration_str: &str) -> Result<DateTime<Utc>, VoucherManagerError>`: Hilfsfunktion zum Parsen einer ISO 8601 Duration und Addieren zu einem Datum.
- `pub fn round_up_date(date: DateTime<Utc>, rounding_str: &str) -> Result<DateTime<Utc>, VoucherManagerError>`: Hilfsfunktion, um ein Datum auf das Ende des Tages, Monats oder Jahres aufzurunden.
- `pub fn validate_issuance_firewall(voucher: &Voucher, standard: &VoucherStandardDefinition, sender_id: &str, recipient_id: &str) -> Result<(), VoucherCoreError>`: Prüft die "Zirkulations-Firewall" (`issuance_minimum_validity_duration`).
- `pub fn get_spendable_balance(voucher: &Voucher, user_id: &str, standard: &VoucherStandardDefinition) -> Result<Decimal, VoucherCoreError>`: Berechnet das ausgebbare Guthaben für einen bestimmten Benutzer.
- `pub fn create_transaction(voucher: &Voucher, standard: &VoucherStandardDefinition, sender_id: &str, sender_key: &SigningKey, recipient_id: &str, amount_to_send_str: &str) -> Result<Voucher, VoucherCoreError>`: Erstellt eine Kopie des Gutscheins mit einer neuen Transaktion. Die Signatur der Transaktion sichert nun ein minimales Objekt (`{prev_hash, sender_id, t_id}`). Verwendet `decimal_utils` zur **strengen Validierung der Betragspräzision** und zur **kanonischen Formatierung** der Werte. Verwendet explizit den Transaktionstyp "transfer" für einen vollen Transfer. Implementiert eine **"Zirkulations-Firewall" (`issuance_minimum_validity_duration`)**: Verhindert, dass der *ursprüngliche Ersteller* einen Gutschein an einen *Dritten* sendet, wenn die *Restgültigkeit* des Gutscheins die im Standard definierte Mindestgültigkeit unterschreitet. Diese Prüfung gilt *nicht* für nicht-Ersteller oder interne SAI-Transfers (z.B. Creator zu sich selbst). Erfordert bei `init` Transaktionen zwingend eine öffentliche `sender_id`.

### `services::voucher_validation` Modul

Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts gegen die Regeln seines Standards. **Die Validierungslogik wurde erheblich gehärtet.**

- `pub fn validate_voucher_against_standard(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError>`: Führt eine umfassende Prüfung des Gutscheins durch, inklusive der korrekten Verkettung unter Einbeziehung des `voucher_nonce`, der Validierung der vereinfachten Transaktions-Signatur und neuer Geschäftsregeln (z.B. keine Transaktionen an sich selbst).
- Nutzt die **CEL-Engine** (`DynamicPolicyEngine`), um datengesteuerte Geschäftsregeln (`dynamic_rules`) auszuwerten. Dies ersetzt die alten, hartkodierten Zähl- und Inhaltsprüfungen (wie `CountRules` oder `FieldGroupRule`) durch hochflexible, vom Standard-Ersteller definierte Ausdrücke.
- `pub fn validate_behavior_rules(...) -> Result<(), ValidationError>`: Prüft die systemkritischen Kern-Verhaltensregeln (`behavior_rules`), wie erlaubte Transaktionstypen und Gültigkeitsgrenzen.
- Überprüft die **Konsistenz des eingebetteten Standard-Hashes** mit dem Hash des aktuellen Standard-Objekts, um sicherzustellen, dass der Gutschein immer gegen die exakte Version des Standards validiert wird, mit der er erstellt wurde.
- Überprüft, ob der **Transaktionstyp** (`t_type`) laut Standard erlaubt ist.
- Überprüft die Integrität und kryptographische Gültigkeit aller **zusätzlichen Signaturen** (`additional_signatures`).
- Führt eine **Kern-Daten-Integritätsprüfung** durch: Validiert, dass der `voucher_id` (der Hash der Gutschein-Stammdaten) mit den tatsächlichen Inhalten des Gutscheins übereinstimmt. Diese Prüfung schützt gegen Manipulationen an den Kernstammdaten.
- **Hinweis:** Die Validierung der `issuance_minimum_validity_duration` erfolgt nun nicht mehr in dieser Funktion, sondern wird als "Gatekeeper" in `create_voucher` (bei Erstellung) und als "Firewall" in `create_transaction` (bei Transfer) separat behandelt.

Neue Validierungsfehler:
- `ValidationError::InvalidVoucherHash` - Wird ausgelöst, wenn der `voucher_id` (Hash der Stammdaten) nicht mit den tatsächlichen Inhalten des Gutscheins übereinstimmt, was auf eine Manipulation der Kernstammdaten hindeutet.
- Die `FieldGroupRules`-Validierung wurde angepasst, um die neuen verschachtelten Pfade für Signatur-Details zu unterstützen (z.B. `details.gender` statt `gender`). Dies ermöglicht eine präzisere Validierung der Signatur-Metadaten gemäß den Anforderungen im Standard.

### `src/wallet` Modul - Neue Sicherheitsfeatures

Das Wallet-Modul implementiert umfassenden Schutz gegen Replay-Angriffe durch zwei Schichten:

- **Layer 1: Duplicate Processing Guard (Bundle ID Check)**: Eine schnelle Prüfung gegen den `bundle_meta_store`. Wenn die **ID des eingehenden Bundles** bereits bekannt ist, wird das Bundle sofort mit `VoucherCoreError::BundleAlreadyProcessed` abgelehnt. Dies schützt gegen versehentliche oder einfache Wiederholungen derselben Daten und stellt sicher, dass ein Bundle nur einmal verarbeitet wird.

- **Layer 2: Malicious Replay Guard (Transaction Fingerprint Check)**: Eine neue Funktion `check_bundle_fingerprints_against_history` validiert die **Transaktionsfingerprints** (`prvhash_senderid_hash`) aller Gutscheine innerhalb des Bundles. Wenn ein Fingerprint bereits in der Wallet-Historie vorhanden ist, wird das Bundle mit `VoucherCoreError::TransactionFingerprintAlreadyKnown` abgelehnt. Dies verhindert bösartige modifizierte Angriffe, bei denen ein bekannter, signierter Gutschein in ein neues Bundle gepackt wird, um Double-Spending zu versuchen.

- **Empfänger-Validierung**: Ein Wallet lehnt eingehende Bundles ab, die nicht explizit für den Wallet-Besitzer bestimmt sind. Das Wallet prüft, ob jede Transaktion innerhalb des Bundles für die eigene User-ID bestimmt ist, und wirft einen `VoucherCoreError::BundleRecipientMismatch`-Fehler, falls dies nicht der Fall ist.

### Neue Ergebnis- und Informationsstrukturen

Das Wallet-Modul und die AppService-Schnittstelle wurden um neue Informationsstrukturen erweitert, um die API-Effizienz zu verbessern:

- `TransferSummary`: Fasst die Ergebnisse eines Transfers pro Standard zusammen. Enthält aufsummierte Beträge für teilbare Gutscheine und gezählte Einheiten für nicht-teilbare Gutscheine.

- `InvolvedVoucherInfo`: Enthält detaillierte Informationen zu einem einzelnen Gutschein, der an einer Transaktion beteiligt war (lokale ID, globale ID, Standardname, Währung, Betrag, Teilbarkeit).

- `CreateBundleResult`: Das Ergebnis der `create_transfer_bundle`-Methode, das neben den Bundle-Daten auch detaillierte Informationen über die involvierten Quell-Gutscheine (`involved_sources_details`) enthält.

- `ProcessBundleResult`: Das Ergebnis der `receive_bundle`-Methode, das neben den Header-Informationen auch `transfer_summary` und `involved_vouchers_details` enthält, um eine umfassende Übersicht über den empfangenen Transfer zu bieten.

### Zusätzliche Datenstrukturen in `src/models`

- **profile.rs**:
  - `UserIdentity`: Kryptographische Identität eines Nutzers mit privatem/öffentlichem Schlüssel und User-ID.
  - `TransactionDirection`: Enum für Transaktionsrichtung (Sent/Received).
  - `TransactionBundleHeader`: Leichtgewichtige Zusammenfassung eines `TransactionBundle`.
  - `TransactionBundle`: Vollständiges, signiertes Bündel für Gutschein-Austausch, inkl. Fingerprints für Double-Spend-Erkennung.
  - `VoucherStore`: Persistenter Speicher für Gutscheine.
  - `BundleMetadataStore`: Speicher für Transaktionsbündel-Metadaten.
  - `PublicProfile`: Standardisiertes öffentliches Profil für Signaturen und Creator-Feld.
  - `UserProfile`: Hauptstruktur für den Nutzer-Wallet-Zustand.

- **secure_container.rs**:
  - `PayloadType`: Enum für Inhaltsart (TransactionBundle, VoucherForSigning, etc.).
  - `WrappedKey`: Verschlüsselter Payload-Schlüssel für Empfänger/Sender.
  - `SecureContainer`: Anonymer, sicherer Container für Datenaustausch mit Forward Secrecy.

- **conflict.rs**:
  - `TransactionFingerprint`: Anonymisierter Fingerprint einer Transaktion für Double-Spend-Erkennung.
  - `KnownFingerprints`: Speicher für bekannte Fingerprints (lokal und fremd).
  - `OwnFingerprints`: Kritischer Speicher für eigene Fingerprints.
  - `FingerprintMetadata`: Dynamische Metadaten für Fingerprints (depth als `i8`, known_by_peers).
  - `CanonicalMetadataStore`: Zentraler Speicher für Fingerprint-Metadaten.
  - `ProofOfDoubleSpend`: Kryptographischer Beweis für Double-Spend (inkl. `affected_voucher_name`).
  - `ResolutionEndorsement`: Bestätigung einer Konfliktbeilegung (Globaler Typ).
  - `ProofStoreEntry`: Lokaler Wrapper für `ProofOfDoubleSpend` inkl. `local_override` und `ConflictRole`.
  - `ConflictRole`: Unterscheidung zwischen `Victim` (eigenes Guthaben betroffen) und `Witness` (passive Beobachtung).
  - `TrustStatus`: Ergebnis der Reputationsprüfung (`Clean`, `KnownOffender`, `Resolved`).
  - `ProofStore`: Speicher für `ProofStoreEntry` Objekte.
  - `Layer2Verdict`: Signiertes Urteil eines Layer-2-Servers.

- **signature.rs**:
  - `DetachedSignature`: Wrapper für losgelöste Signaturen im Signatur-Workflow.

- **voucher_standard_definition.rs** (Erweiterungen):
  - `LocalizedText`: Sprachabhängiger Text.
  - `StandardMetadata`: Metadaten des Standards.
  - `TemplateNominalValue`, `TemplateCollateral`, `TemplateGuarantorInfo`: Vorlagen für Gutscheinfeld.
  - `TemplateFixed`, `TemplateDefault`: Feste und standardmäßige Vorlagen.
  - `VoucherTemplate`: Vorlage für neue Gutscheine.
  - `SignatureBlock`: Kryptographische Signatur des Standards.
  - `DynamicRule`, `BehaviorRules`: Strukturen für die CEL-basierten dynamischen Regeln und die festen Verhaltensregeln.
  - `Validation`: Hauptstruktur für Validierungsregeln.

### `tests/` Verzeichnis - Wichtige Sicherheits- & Architekturtests

Um die Robustheit des Systems zu gewährleisten, wurden spezialisierte Tests implementiert:

- **Architektur-Hardening (`tests/architecture/hardening.rs`)**: Verifiziert die Integrität der Key-Derivation und den Schutz gegen Identity-Hopping auf Systemebene.
- **Resilience & Gossip (`tests/architecture/resilience_and_gossip.rs`)**: Testet die Stabilität des Fingerprint-Austauschs und die dezentrale Double-Spend Erkennung.
- **Double-Spend Identifikation (`tests/core_logic/security/double_spend_identification.rs`)**: Fokusiert auf die mathematische Extraktion der Täter-ID aus kollidierenden Transaktionen.
- **Mixed Mode Vulnerability (`tests/wallet_api/mixed_mode_vulnerability.rs`)**: Stellt sicher, dass der Wechsel zwischen Public- und Stealth-Modus keine Sicherheitslücken (z.B. durch unterschiedliche Fingerprints) aufreißt.
- **Multi-Identity Vulnerability (`tests/wallet_api/multi_identity_vulnerability.rs`)**: Verifiziert, dass ein Nutzer nicht mehrere Identitäten innerhalb desselben ökonomischen Kontextes missbräuchlich verwenden kann.

### Automatisierung & Workflows

- **Automatisierte Test-Härtung (`scripts/run_mutation_tests.sh`)**: Ein Tool zur Durchführung von Mutationstests für sicherheitskritische Module. Es stellt sicher, dass jede logische Code-Änderung in `trap_manager.rs`, `voucher_validation.rs` und `transaction_handler.rs` zuverlässig von der Test-Suite erkannt wird.

## 8. Dokumentation

- **Haupt-Spezifikation**: `docs/de/spec/Spezifikation - Hybride Privatsphäre und Offline-Sicherheit für digitale Gutscheine.md` - Das maßgebliche Dokument für das gesamte Protokolldesign.
- **Zustands-Management**: `docs/de/zustands-management.md` - Details zur Persistenz und Wallet-Zustandsübergängen.
- **Konfliktmanagement**: `docs/de/konliktmanagement.md` - Vertiefende Informationen zur Double-Spend Erkennung und Beilegung.