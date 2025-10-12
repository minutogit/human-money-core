# llm-context.md für decentral-voucher-system-core

Dies ist die Kontextdatei für die Entwicklung der Rust-Core-Bibliothek `voucher_core`. Sie dient als "README für die KI", um ein umfassendes Verständnis des Projekts und seiner Anforderungen zu gewährleisten.

## 1\. Projekt & Zweck

- **Projektname:** `voucher_core`

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

- **Kryptographisch getrennte Konten:** Jedes Konto (identifiziert durch ein `prefix`, z.B. "pc", "mobil") wird von einem einzigen Master-Mnemonic abgeleitet, erzeugt aber ein eigenes, einzigartiges Schlüsselpaar. Dies geschieht, indem das Präfix an die Passphrase angehängt wird, bevor der Schlüssel abgeleitet wird (`final_passphrase = passphrase + prefix`). Dies verhindert, dass ein Gutschein versehentlich auf dem falschen Gerät angenommen werden kann und erhöht die Sicherheit.

- **Offline-Fähigkeit:** Transaktionen sollen auch offline durchgeführt werden können, indem die aktualisierte Gutschein-Datei direkt an den neuen Halter übergeben wird.

- **Fokus auf Betrugserkennung, nicht -vermeidung:** Da es kein globales Ledger gibt, kann die Core-Bibliothek nicht verhindern, dass ein Nutzer widersprüchliche Transaktionshistorien (Double Spending) erzeugt. Das System stellt stattdessen sicher, dass jeder Betrugsversuch durch digitale Signaturen kryptographisch beweisbar ist, was eine Erkennung und soziale Sanktionen in einem übergeordneten System (Layer 2) ermöglicht.

- **Peer-to-Peer Gossip-Protokoll:** Zur dezentralen und anonymisierten Erkennung von Double Spending tauschen Wallets bei jeder Transaktion "Fingerabdrücke" anderer Transaktionen aus. Eine Heuristik (`depth`, `known_by_peers`) sorgt für eine effiziente Verbreitung.

- **Fokus auf Kernlogik:** Zunächst wird nur die grundlegende Funktionalität der Gutschein- und Transaktionsverwaltung implementiert. Die "Transaction Verification Layer" und "User Trust Verification Layer" (Layer 2 mit Servern) sollen *nicht* implementiert werden, aber die Struktur der Transaktionsketten sollte so optimiert werden, dass eine spätere Erweiterung um diese Layer möglich ist.

- **FFI/WASM-Kompatibilität:** Rust-Typen und -Funktionen müssen so gestaltet sein, dass sie einfach über FFI und WASM exponiert werden können (z.B. durch Verwendung von `#[no_mangle]`, C-kompatiblen Datentypen und `wasm_bindgen`).

## 4\. Coding-Standards & Wichtige Regeln

- **Rust Best Practices:** Einhaltung der idiomatischen Rust-Programmierung, Fokus auf Sicherheit, Performance und Speichereffizienz.

- **Fehlerbehandlung:** Robuste Fehlerbehandlung mit Rusts `Result`-Typ.

- **Dokumentation:** Umfassende interne Dokumentation (Doc-Kommentare) für alle öffentlichen Funktionen und Strukturen.

- **Testen:** Umfassende Unit- und Integrationstests.

- **Keine externen Netzwerkaufrufe:** Die Core-Bibliothek soll keine direkten Netzwerkaufrufe für die Layer-2-Funktionalität enthalten. Diese Interaktionen werden von den übergeordneten Anwendungen gehandhabt, die `voucher_lib` nutzen.

## 5\. Kernkonzepte aus dem Paper (Zusammenfassung)

Gutschein-Struktur: Das universelle Gutschein-Container-Format

Ein Gutschein ist im Wesentlichen eine Textdatei (repräsentiert als JSON), die alle möglichen Informationen enthält, die ein Gutschein jemals haben könnte. Jede einzelne Gutscheininstitution wird in diesem einheitlichen JSON-Schema abgebildet. Die spezifischen Regeln und Eigenschaften eines Gutscheintyps (wie "Minuto-Gutschein" oder "Silber-Umlauf-Gutschein") werden in separaten Standard-Definitionen (voucher\_standard\_definitions) festgelegt.

Diese Definitionen werden als externe **TOML-Dateien** (z.B. aus einem `voucher_standards/`-Verzeichnis) bereitgestellt und zur Laufzeit geparst. Die TOML-Struktur ist klar in drei Blocker unterteilt:

- **`[metadata]`**: Enthält allgemeine Informationen wie Name und UUID des Standards.

- **`[template]`**: Definiert Werte (z.B. die `unit` des Nennwerts), die bei der Erstellung eines neuen Gutscheins direkt in diesen kopiert werden.

- **`[validation]`**: Beinhaltet Regeln (z.B. `required_voucher_fields`, `guarantor_rules`), die zur Überprüfung eines Gutscheins verwendet werden.

```
{
  "voucher_standard": {
    "name": "STRING", // Der Name des Standards, zu dem dieser Gutschein gehört (z.B. "Minuto-Gutschein", "Silber-Umlauf-Gutschein").
    "uuid": "STRING"  // Die eindeutige Kennung (UUID) des Standards, zu dem dieser Gutschein gehört.
    "standard_definition_hash": "STRING" // Der SHA3-256 Hash des kanonisierten Standard-TOML-Inhalts (ohne Signatur), um die Unveränderlichkeit zu gewährleisten.
  },
  "voucher_id": "STRING", // Die eindeutige ID dieses spezifischen Gutscheins.
  "voucher_nonce": "STRING", // Ein zufälliges Nonce, um den ersten `prev_hash` unvorhersehbar zu machen.
  "description": "STRING", // Eine allgemeine, menschenlesbare Beschreibung des Gutscheins (z.B. "Gutschein für 888 Minuten qualitativer Leistung").
  "primary_redemption_type": "STRING", // Der primäre Einlösezweck, übernommen vom Standard (z.B. "goods_or_services").
  "divisible": "BOOLEAN", // Gibt an, ob der Gutschein in kleinere Einheiten aufgeteilt werden kann (true/false).
  "creation_date": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Das Erstellungsdatum des Gutscheins im ISO 8601-Format.
  "valid_until": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ",    // Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
  "standard_minimum_issuance_validity": "STRING", // Die bei der Erstellung gültige Mindestgültigkeitsdauer aus dem Standard (ISO 8601 Duration).
  "non_redeemable_test_voucher": "BOOLEAN", // Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt (true/false).
  "nominal_value": { // Definiert den Wert, den der Gutschein repräsentiert.
    "unit": "STRING",     // Die Einheit des Gutscheinwerts (z.B. "Minuten", "Unzen", "Euro").
    "amount": "STRING",   // Die genaue Menge des Werts (z.B. "888", "1", "50"). Als String für Flexibilität bei Einheiten.
    "abbreviation": "STRING", // Eine gängige Abkürzung der Einheit (z.B. "m", "oz", "€").
    "description": "STRING" // Eine Beschreibung des Werts (z.B. "Objektive Zeit", "Physisches Silber", "Nationale Währung").
  },
  "collateral": { // Informationen zur Besicherung des Gutscheins.
    "type": "STRING",         // Die Art der Besicherung (z.B. "Physisches Edelmetall", "Community-Besicherung", "Fiat-Währung").
    "unit": "STRING",         // Die Einheit der Besicherung (z.B. "Unzen", "Euro").
    "amount": "STRING",       // Die Menge der Besicherung (z.B. "entspricht dem Nennwert", "200").
    "abbreviation": "STRING",// Eine gängige Abkürzung für die Besicherung (z.B. "oz", "€").
    "description": "STRING", // Eine detailliertere Beschreibung der Besicherung (z.B. "Edelmetall Silber, treuhänderisch verwahrt").
    "redeem_condition": "STRING" // **Extrem wichtig:** Bedingungen unter denen die Besicherung eingelöst/ausgezahlt werden kann (z.B. Notfallklausel).
  },
  "creator": { // Detaillierte Informationen zum Ersteller des Gutscheins.
    "id": "STRING",             // Eindeutige ID des Erstellers (oft ein Public Key).
    "first_name": "STRING",     // Vorname des Erstellers.
    "last_name": "STRING",      // Nachname des Erstellers.
    "address": {                // Detaillierte Adressinformationen des Erstellers.
      "street": "STRING",       // Straße.
      "house_number": "STRING", // Hausnummer.
      "zip_code": "STRING",     // Postleitzahl.
      "city": "STRING",         // Stadt.
      "country": "STRING",      // Land.
      "full_address": "STRING"  // Vollständige, formatierte Adresse.
    },
    "organization": "STRING, optional",   // Die Organisation des Erstellers.
    "community": "STRING, optional",      // Beschreibung der Gemeinschaft, zu der der Ersteller gehört.
    "phone": "STRING, optional",          // Telefonnummer des Erstellers.
    "email": "STRING, optional",          // E-Mail-Adresse des Erstellers.
    "url": "STRING, optional",            // URL des Erstellers oder dessen Webseite.
    "gender": "STRING",         // Geschlecht des Erstellers ISO 5218 (1 = male", 2 = female", 0 = not known, 9 = Not applicable).
    "service_offer": "STRING, optional",  // Beschreibt die Angebote oder Talente des Erstellers.
    "needs": "STRING, optional",          // Beschreibt die Gesuche oder Bedürfnisse des Erstellers.
    "signature": "STRING",      // Die digitale Signatur des Erstellers. Sie signiert den Hash des initialen Gutschein-Objekts (ohne voucher_id, Signaturen und Transaktionen).
    "coordinates": "STRING"     // Geografische Koordinaten des Erstellers (z.B. "Breitengrad, Längengrad").
  },
  "guarantor_requirements_description": "STRING", // Eine menschenlesbare Beschreibung der Bürgenanforderungen, übernommen vom Standard.
  "footnote": "STRING", // Ein optionaler Fußnotentext, der vom Standard vorgegeben wird.
  "guarantor_signatures": [ // Ein Array von Signaturen der Bürgen.
    { // Jede Signatur ist ein in sich geschlossenes, überprüfbares Objekt.
      "voucher_id": "STRING",         // Die ID des Gutscheins, zu dem diese Signatur gehört.
      "signature_id": "STRING",       // Eine eindeutige ID für dieses Signatur-Objekt, erzeugt durch Hashing der eigenen Metadaten.
      // Die Metadaten (alles außer signature_id und signature) werden kanonisiert und gehasht, um die signature_id zu erzeugen.
      "guarantor_id": "STRING",         // Eindeutige ID des Bürgen (aus Public Key).
      "first_name": "STRING",
      "last_name": "STRING",
      "organization": "STRING, optional",
      "community": "STRING, optional",
      "address": { // Vollständiges Adressobjekt, optional.
      },
      "gender": "STRING", // ISO 5218
      "email": "STRING, optional",
      "phone": "STRING, optional",
      "coordinates": "STRING, optional",
      "url": "STRING, optional",
      "signature": "STRING",            // Die digitale Signatur des Bürgen, die die `signature_id` dieses Objekts unterzeichnet.
      "signature_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ" // Zeitpunkt der Bürgen-Signatur.
    }
  ],
  "needed_guarantors": "INTEGER", // Die Anzahl der für diesen Gutschein benötigten Bürgen.
  "transactions": [ // Eine chronologische Liste aller Transaktionen dieses Gutscheins.
    { // Jede Transaktion ist ein in sich geschlossenes, signiertes Objekt.
      "t_id": "STRING",                 // Eindeutige ID der Transaktion, erzeugt durch Hashing der Transaktionsdaten (ohne t_id und Signatur).
      "prev_hash": "STRING",            // Der Hash der vorherigen Transaktion (oder der voucher_id bei der "init"-Transaktion), der die Kette kryptographisch sichert.
      "t_type": "STRING, optional",     // Art der Transaktion: "init" für Initialisierung, "split" für Teilung, "transfer" für einen vollen Transfer. Kann bei vollem Transfer leer sein.
      "t_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Zeitpunkt der Transaktion.
      "sender_id": "STRING",            // ID des Senders der Transaktion.
      "recipient_id": "STRING",         // ID des Empfängers der Transaktion.
      "amount": "STRING",               // Der Betrag, der bei dieser Transaktion bewegt wurde.
      "sender_remaining_amount": "STRING",// Der Restbetrag beim Sender. Dieses Feld existiert nur bei "split"-Transaktionen.
      "sender_signature": "STRING"      // Digitale Signatur des Senders. Signiert ein Objekt, das aus prev_hash + sender_id + t_id besteht.
    }
  ],
  "additional_signatures": [ // Ein Array für zusätzliche, optionale Signaturen, die an den Gutschein angehängt werden können.
    {
      "voucher_id": "STRING",           // Die ID des Gutscheins, zu dem diese Signatur gehört.
      "signature_id": "STRING",       // Eine eindeutige ID für dieses Signatur-Objekt, erzeugt durch Hashing der eigenen Metadaten.
      "signer_id": "STRING",            // Eindeutige ID des zusätzlichen Unterzeichners (aus Public Key).
      "signature": "STRING",            // Die digitale Signatur, die die `signature_id` dieses Objekts unterzeichnet.
      "signature_time": "YYYY-MM-DDTHH:MM:SS.SSSSSSZ", // Zeitpunkt der Signatur.
      "description": "STRING"           // Eine Beschreibung, warum diese Signatur hinzugefügt wurde.
    }
  ]
}
```

### Transaktionskette

Die Transaktionen im `transactions`-Array bilden eine kryptographisch verkettete Liste, ähnlich einer Blockchain.

- **Verkettung:** Jede Transaktion enthält ein `prev_hash`-Feld.

  - Die erste Transaktion (`t_type: "init"`) hat einen `prev_hash`, der der Hash der Konkatenation von `voucher_id` und `voucher_nonce` ist. Dies verhindert, dass der `prev_hash` erraten werden kann, was die Anonymität des Erstellers auf Layer 2 schützt.

  - Jede nachfolgende Transaktion hat einen `prev_hash`, der der Hash der vollständigen, kanonisierten vorherigen Transaktion ist.

- **Integrität:** Jede Transaktion hat eine `t_id`, die aus dem Hash ihrer eigenen Daten (ohne `t_id` und `sender_signature`) erzeugt wird. Das stellt sicher, dass die Transaktionsdetails nicht nachträglich geändert werden können, ohne die `t_id` ungültig zu machen.

- **Authentizität:** Die `sender_signature` signiert ein separates, minimales Objekt, das nur die Kern-Metadaten der Transaktion (`prev_hash`, `sender_id`, `t_id`) enthält. Dies beweist, dass der Sender die Transaktion autorisiert hat. Der Zeitstempel (`t_time`) muss nicht explizit signiert werden, da er bereits Teil der Daten ist, die zur Erzeugung der `t_id` gehasht werden und somit implizit durch die Signatur der `t_id` geschützt ist.

### Double-Spending-Erkennung

Ein **Double Spend** liegt vor, wenn ein Nutzer von einem bestimmten Zustand des Gutscheins (repräsentiert durch den `prev_hash` der letzten gültigen Transaktion) zwei oder mehr unterschiedliche neue Transaktionen erstellt und diese an verschiedene Personen verteilt.

#### Anonymisierte Erkennung auf Layer 2 mit verschlüsseltem Zeitstempel

Die Transaktionsstruktur ist für eine **anonymisierte Betrugserkennung** durch ein übergeordnetes System (Layer 2) optimiert:

- **Anonymer Fingerabdruck:** Anstatt `prev_hash` und `sender_id` direkt preiszugeben, erzeugt ein Client einen anonymen "Fingerabdruck": `prvhash_senderid_hash = hash(prev_hash + sender_id)`.

- **Server-Upload:** Der Client lädt ein `TransactionFingerprint`-Objekt hoch. Es enthält den `prvhash_senderid_hash`, die `t_id`, die `sender_signature` und einen **verschlüsselten Zeitstempel**.

- **Verschlüsselter Zeitstempel:** Um eine zeitliche Einordnung im Konfliktfall zu ermöglichen, ohne das Datum an den Server preiszugeben, wird der Zeitstempel (in Nanosekunden) via XOR mit einem deterministischen Schlüssel verschlüsselt: `encrypted_nanos = original_nanos ^ hash(prev_hash + t_id)`. Der Server kann diesen Wert nicht entschlüsseln, da er `prev_hash` und `t_id` nicht kennt.

- **Aufdeckung & Beweis:** Ein Double Spend wird erkannt, wenn der Server für einen bekannten `prvhash_senderid_hash` einen neuen Eintrag mit einer anderen `t_id` erhält. Der Server kann dem zweiten Einreicher die Daten des ersten Eintrags als Beweis zurücksenden. Ein Client, der beide widersprüchlichen Transaktionen besitzt, hat damit den Beweis für den Betrug. Er kann beide Signaturen verifizieren und **beide Zeitstempel entschlüsseln**, um festzustellen, welche Transaktion die frühere war.

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

### Weitere relevante Konzepte (für zukünftige Erweiterungen optimieren)

- **Teilzahlungen:** Ein Gutschein kann in kleinere Beträge aufgeteilt werden. Der Restbetrag verbleibt beim Sender, der daraus weitere Transaktionen erstellen kann.

- **Multi-Quellen-Transfers:** Guthaben kann aus mehreren Gutscheinen in einer einzigen Transaktion an einen Empfänger gebündelt werden. Dies wird durch die `MultiTransferRequest`-Struktur und die `execute_multi_transfer_and_bundle`-Methode ermöglicht.

- **Zusätzliche Signaturen:** Möglichkeit, weitere Signaturen (z.B. von Bürgen/Garanten) in die Gutschein-Datei zu integrieren.

- **Verschlüsselung:** Die Übertragung von Daten (z.B. Transaktionsbündel) wird durch einen generischen, **anonymisierten** `SecureContainer` geschützt. Dieser implementiert **Forward Secrecy durch ephemere X25519-Schlüssel**. Ein "Double Key Wrapping"-Mechanismus stellt sicher, dass sowohl die Empfänger als auch der Sender selbst den Container entschlüsseln können. Alle binären Daten werden als Base64-Strings kodiert.

- **Begrenzte Gültigkeitsdauer:** Gutscheine sollen nach einer bestimmten Zeit ihre Gültigkeit verlieren.

- **Keine Layer 2 Implementierung:** Die Logik für die "Transaction Verification Layer" (Server-basiertes Double-Spending-Matching) und die "User Trust Verification Layer" (Reputationsmanagement) wird in dieser Core-Bibliothek *nicht* implementiert. Die Datenstrukturen für Transaktionsketten sollen jedoch eine spätere Anbindung an solche Systeme ermöglichen.

## 6\. Aktueller Projektstrukturbaum

```
├── Cargo.lock
├── Cargo.toml
├── README.md
├── sign_standards.sh
├── sign_test_standards.sh
├── src
│   ├── app_service
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
│   │   ├── validate-standard.rs
│   │   └── voucher-cli.rs
│   ├── error.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── models
│   │   ├── conflict.rs
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
│   │   ├── mod.rs
│   │   ├── secure_container_manager.rs
│   │   ├── signature_manager.rs
│   │   ├── standard_manager.rs
│   │   ├── utils.rs
│   │   ├── voucher_manager.rs
│   │   └── voucher_validation.rs
│   ├── storage
│   │   ├── file_storage.rs
│   │   └── mod.rs
│   ├── test_utils.rs
│   └── wallet
│       ├── conflict_handler.rs
│       ├── instance.rs
│       ├── mod.rs
│       ├── queries.rs
│       ├── signature_handler.rs
│       └── tests.rs
├── test_plan.txt
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
│   │   └── security.rs
│   ├── core_logic_tests.rs
│   ├── persistence
│   │   ├── archive.rs
│   │   ├── file_storage.rs
│   │   └── mod.rs
│   ├── persistence_tests.rs
│   ├── services
│   │   ├── crypto.rs
│   │   ├── mod.rs
│   │   └── utils.rs
│   ├── services_tests.rs
│   ├── test_data
│   │   └── standards
│   │       ├── standard_behavior_rules.toml
│   │       ├── standard_conflicting_rules.toml
│   │       ├── standard_content_rules.toml
│   │       ├── standard_field_group_rules.toml
│   │       ├── standard_no_split.toml
│   │       ├── standard_path_not_found.toml
│   │       ├── standard_required_signatures.toml
│   │       ├── standard_strict_counts.toml
│   │       └── standard_strict_sig_description.toml
│   ├── validation
│   │   ├── business_rules.rs
│   │   ├── forward_compatibility.rs
│   │   ├── mod.rs
│   │   ├── standard_definition.rs
│   │   └── unit_service.rs
│   ├── validation_tests.rs
│   ├── wallet_api
│   │   ├── general_workflows.rs
│   │   ├── hostile_bundles.rs
│   │   ├── hostile_standards.rs
│   │   ├── lifecycle_and_data.rs
│   │   ├── mod.rs
│   │   ├── signature_workflows.rs
│   │   ├── state_management.rs
│   │   └── transactionality.rs
│   └── wallet_api_tests.rs
├── validate_standards.sh
└── voucher_standards
    ├── minuto_v1
    │   └── standard.toml
    ├── readme_de.md
    ├── silver_v1
    │   └── standard.toml
    └── standard_template.toml
```

## 7\. Implementierte Kernfunktionen

Basierend auf den bereitgestellten Dateien:

### `src/app_service` Modul

Definiert den `AppService`, eine übergeordnete Fassade, die die `Wallet`-Logik für Client-Anwendungen (z.B. GUIs) vereinfacht.

- `pub struct AppService`
  - Verwaltet den Anwendungszustand (`Locked`/`Unlocked`).
  - Kapselt `UserIdentity` und `Storage`-Implementierung.
  - Stellt sicher, dass Zustandsänderungen im Wallet automatisch gespeichert werden.
- `pub fn new(...) -> Result<Self, String>`
  - Initialisiert einen neuen `AppService` im `Locked`-Zustand.
- `pub fn generate_mnemonic(word_count: u32) -> Result<String, String>`
  - Generiert eine neue BIP-39 Mnemonic-Phrase.
- `pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String>`
  - Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
- `pub fn create_profile(&mut self, mnemonic: &str, passphrase: Option<&str>, user_prefix: Option<&str>, password: &str) -> Result<(), String>`
  - Erstellt ein komplett neues Wallet und Profil, speichert es und setzt den Service in den `Unlocked`-Zustand.
- `pub fn login(&mut self, ..., cleanup_on_login: bool) -> Result<...>`
  - Entsperrt ein existierendes Wallet. Benötigt die Geheimnisse, um den Speicherort zu finden. Bietet eine Option, beim Login eine Speicherbereinigung durchzuführen.
- `pub fn recover_wallet_and_set_new_password(&mut self, mnemonic: &str, passphrase: Option<&str>, prefix: Option<&str>, new_password: &str) -> Result<(), String>`
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
- `pub fn create_new_voucher(&mut self, standard_toml_content: &str, lang_preference: &str, data: NewVoucherData, password: &str) -> Result<Voucher, String>`
  - Erstellt einen brandneuen Gutschein, validiert ihn gegen den bereitgestellten Standard, fügt ihn zum Wallet hinzu und speichert den Zustand.
- `pub fn create_transfer_bundle(&mut self, request: MultiTransferRequest, standard_definitions_toml: &HashMap<String, String>, archive: Option<&dyn VoucherArchive>, password: &str) -> Result<Vec<u8>, String>`
  - Erstellt eine(n oder mehrere) Transaktion(en) für einen oder mehrere Quell-Gutscheine, verpackt sie in ein `SecureContainer`-Bundle und speichert den neuen Wallet-Zustand. Akzeptiert eine `MultiTransferRequest`-Struktur, die eine Liste von Quell-Gutscheinen und Beträgen enthält.
- `pub fn receive_bundle(&mut self, bundle_data: &[u8], standard_definitions_toml: &HashMap<String, String>, archive: Option<&dyn VoucherArchive>, password: &str) -> Result<ProcessBundleResult, String>`
  - Verarbeitet ein empfangenes Transaktions-Bundle, validiert die enthaltenen Gutscheine gegen die bereitgestellten Standard-Definitionen und speichert den neuen Wallet-Zustand.
- `pub fn create_signing_request_bundle(...) -> Result<Vec<u8>, String>`
  - Erstellt ein Bundle, um einen Gutschein zur Unterzeichnung an einen Bürgen zu senden.
- `pub fn create_detached_signature_response_bundle(...) -> Result<Vec<u8>, String>`
  - Erstellt eine losgelöste Signatur als Antwort auf eine Signaturanfrage.
- `pub fn process_and_attach_signature(&mut self, container_bytes: &[u8], standard_toml_content: &str, password: &str) -> Result<(), String>`
  - Verarbeitet eine empfangene losgelöste Signatur, validiert den Gutschein neu gegen den Standard, fügt die Signatur hinzu und speichert den Zustand.
- `pub fn save_encrypted_data(...) -> Result<(), String>`
  - Speichert einen beliebigen Byte-Slice verschlüsselt auf der Festplatte.
- `pub fn run_storage_cleanup(&mut self) -> Result<CleanupReport, VoucherCoreError>`
  - Führt die Speicherbereinigung für Fingerprints und deren Metadaten durch.
- `pub fn load_encrypted_data(...) -> Result<Vec<u8>, String>`
  - Lädt und entschlüsselt einen zuvor gespeicherten, beliebigen Datenblock.
- `pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, String>`
  - Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
- `pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, String>`
  - Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
- `pub fn create_resolution_endorsement(&self, proof_id: &str, notes: Option<String>) -> Result<ResolutionEndorsement, String>`
  - Erstellt eine signierte Beilegungserklärung für einen Konflikt.
- `pub fn import_resolution_endorsement(&mut self, endorsement: ResolutionEndorsement, password: &str) -> Result<(), String>`
  - Importiert eine Beilegungserklärung, fügt sie dem entsprechenden Konfliktbeweis hinzu und speichert den Wallet-Zustand.

### `src/wallet` Modul

Das `wallet`-Modul wurde refaktorisiert, um die Komplexität zu reduzieren und die Verantwortlichkeiten klarer zu trennen. Die `Wallet`-Struktur ist weiterhin die zentrale Fassade der Kernlogik, delegiert aber spezifische Aufgaben an Sub-Module.

- `pub struct Wallet` (`mod.rs`)
  - Hält `UserProfile`, `VoucherStore`, `BundleMetadataStore`, die getrennten `KnownFingerprints`, `OwnFingerprints`, `ProofStore` und den neuen `CanonicalMetadataStore` für Metadaten als In-Memory-Zustand.
  - Enthält neue Strukturen: `MultiTransferRequest` für die Anforderung von Transfers mit mehreren Quellen und `SourceTransfer` für die Definition einzelner Quellpositionen in einem Transfer.
- **Lebenszyklus & Kernoperationen** (`mod.rs`)
  - `pub fn new_from_mnemonic(...)`: Erstellt ein brandneues Wallet.
  - `pub fn load(...)`: Lädt ein existierendes Wallet aus dem Storage.
  - `pub fn save(...)`: Speichert den aktuellen Zustand des Wallets.
  - `pub fn create_new_voucher(...)`: Erstellt einen neuen Gutschein und fügt ihn direkt zum Wallet hinzu.
  - `pub fn execute_multi_transfer_and_bundle(...)`: Führt einen Transfer durch, der Guthaben aus mehreren Quell-Gutscheinen kombinieren kann. Ersetzt die alte `create_transfer`-Methode. Akzeptiert eine `MultiTransferRequest`-Struktur mit einer Liste von Quellen und führt alle Transaktionen in einem einzigen Bundle durch. Managt den internen Zustand (Archivierung, Restbetrag) und wählt Fingerprints für das Gossip-Protokoll.
  - `pub fn process_encrypted_transaction_bundle(...)`: Verarbeitet eingehende Gutscheine oder Signaturen, inkl. der Verarbeitung von empfangenen Fingerprints.
- **Speicher-Management** (`mod.rs`)
  - `pub fn run_storage_cleanup(...)`: Führt eine mehrstufige Bereinigung der Fingerprint-Stores durch (abgelaufen, dann nach `depth`).
  - `pub fn rebuild_derived_stores(...)`: Rekonstruiert alle abgeleiteten Stores (Fingerprints, Metadaten) aus dem `VoucherStore`.
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
  - `pub fn scan_and_rebuild_fingerprints(...)`: Scannt das Wallet und baut die getrennten Fingerprint-Stores (`OwnFingerprints`, `KnownFingerprints`) neu auf.
  - `pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult`: Prüft auf Double-Spending-Konflikte, indem es die verschiedenen Fingerprint-Stores zusammenführt.
  - `pub fn export_own_fingerprints(...)` & `import_foreign_fingerprints(...)`: Ermöglichen den Austausch von Fingerprints zwischen Wallets.
- **Voucher Instance Management** (`instance.rs`)
  - `pub struct VoucherInstance`: Repräsentiert eine Instanz eines Gutscheins mit einem bestimmten Status.
  - `pub enum VoucherStatus`: Definiert den Status eines Gutscheins (z.B. `Incomplete`, `Active`, `Archived`, `Quarantined`).
  - `pub fn calculate_local_instance_id(...)`: Berechnet eine deterministische ID für eine Gutscheininstanz.
- **Tests** (`tests.rs`)
  - Enthält umfassende Unit-Tests für die Wallet-Logik.

### `src/storage` Modul (`mod.rs`, `file_storage.rs`)

Definiert die Abstraktion für die persistente Speicherung und stellt eine Standardimplementierung für das Dateisystem bereit.

- `pub trait Storage`
  - Definiert die Schnittstelle für Speicheroperationen, die nun für jeden Datenspeicher separat existieren (`load/save_wallet`, `load/save_bundle_metadata`, `load/save_known_fingerprints`, `load/save_own_fingerprints`, `load/save_fingerprint_metadata`, `load/save_proofs`).
- `pub struct FileStorage`
  - Implementiert den `Storage`-Trait.
  - Speichert die Daten jedes Profils in einem eigenen **anonymen Unterverzeichnis**, um die Privatsphäre zu erhöhen.
  - Implementiert die "Zwei-Schloss"-Mechanik mit Key-Wrapping für den Passwort-Zugriff und die Mnemonic-Wiederherstellung.
  - Bietet eine Funktion (`reset_password`) zum Zurücksetzen des Passworts, wenn der Benutzer sein Passwort vergessen hat.

### `src/archive` Modul (`mod.rs`, `file_archive.rs`)

Definiert die Abstraktion für ein persistentes Archiv von Gutschein-Zuständen.

- `pub trait VoucherArchive`
  - Definiert die Schnittstelle für ein Archiv, das dazu dient, **jeden jemals gesehenen Zustand** eines Gutscheins zu speichern (forensische Analyse). Die Archivierung erfolgt **unabhängig vom Guthaben**.
  - Wallet-Methoden, die ein Archiv verwenden, akzeptieren nun `&dyn VoucherArchive` (dynamic dispatch).
- `pub struct FileVoucherArchive`
  - Eine Implementierung, die jeden archivierten Gutschein-Zustand als separate JSON-Datei in einer **hierarchischen Struktur** speichert: `{archive_dir}/{voucher_id}/{t_id}.json`.

### `services::bundle_processor` Modul

Kapselt die zustandslose Logik für das Erstellen, Verschlüsseln, Öffnen und Verifizieren von `TransactionBundle`-Objekten.

- `pub fn create_and_encrypt_bundle(...)`: Erstellt ein `TransactionBundle`, signiert es, verpackt es in einen `SecureContainer` und serialisiert das Ergebnis.
- `pub fn open_and_verify_bundle(...)`: Öffnet einen `SecureContainer`, validiert den Inhalt als `TransactionBundle` und verifiziert dessen digitale Signatur.

### `services::crypto_utils` Modul

### `services::conflict_manager` Modul

Dieses Modul kapselt die Geschäftslogik zur Erkennung, Verifizierung und Verwaltung von Double-Spending-Konflikten.

- `pub fn create_fingerprint_for_transaction(...) -> Result<TransactionFingerprint, ...>`: Erstellt einen einzelnen, anonymisierten Fingerprint für eine Transaktion, inklusive des verschlüsselten Zeitstempels.
- `pub fn scan_and_rebuild_fingerprints(...) -> Result<(OwnFingerprints, KnownFingerprints), ...>`: Baut die Fingerprint-Stores aus dem `VoucherStore` neu auf und partitioniert sie korrekt.
- `pub fn check_for_double_spend(...) -> DoubleSpendCheckResult`: Führt eine Double-Spend-Prüfung durch, indem die nun getrennten `OwnFingerprints` und `KnownFingerprints` Stores kombiniert werden.
- `pub fn create_proof_of_double_spend(...) -> Result<ProofOfDoubleSpend, ...>`: Erstellt einen fälschungssicheren, portablen Beweis für einen Double-Spend-Versuch mit deterministischer `proof_id`.
- `pub fn create_and_sign_resolution_endorsement(...) -> Result<ResolutionEndorsement, ...>`: Erstellt eine signierte Beilegungserklärung für einen Konflikt.
- `pub fn encrypt_transaction_timestamp(...) -> Result<u128, ...>`: Verschlüsselt einen Transaktionszeitstempel via XOR für die anonymisierte Analyse auf Layer 2.

Dieses Modul enthält kryptographische Hilfsfunktionen für Schlüsselgenerierung, Hashing, Signaturen und User-ID-Verwaltung.

- `pub fn get_hash(input: impl AsRef<[u8]>) -> String`
  - Berechnet einen SHA3-256-Hash der Eingabe und gibt ihn als Base58-kodierten String zurück.
- `pub fn derive_ed25519_keypair(mnemonic_phrase: &str, passphrase: Option<&str>) -> Result<(EdPublicKey, SigningKey), VoucherCoreError>`
  - Leitet ein Ed25519-Schlüsselpaar aus einer mnemonischen Phrase ab. Die übergebene `passphrase` sollte bereits das `prefix` des Kontos enthalten, um kryptographisch getrennte Konten zu erzeugen.
- `pub fn create_user_id(public_key: &EdPublicKey, user_prefix: Option<&str>) -> Result<String, UserIdError>`
  - Generiert eine User ID konform zum **`did:key`-Standard** mit einer integrierten Prüfsumme. Das Format ist `[prefix-]checksum@did:key:z...`.
- `pub fn get_pubkey_from_user_id(user_id: &str) -> Result<EdPublicKey, GetPubkeyError>`
  - Extrahiert den Ed25519 Public Key aus einer `did:key`-basierten User ID-Zeichenkette.
- `pub fn get_short_hash_from_user_id(user_id: &str) -> [u8; 4]`
  - Erzeugt einen 4-Byte-Kurz-Hash aus der User ID für speichereffizientes Tracking von bekannten Peers im Gossip-Protokoll.
- Bietet Funktionen zur Generierung und Validierung von BIP-39 Mnemonic-Phrasen (`generate_mnemonic`, `validate_mnemonic_phrase`).

### `services::secure_container_manager` Modul

Stellt die Kernlogik für den **anonymisierten und weiterleitungs-sicheren** `SecureContainer` bereit, der für den Austausch von Daten (z.B. Bundles, Signaturanfragen) verwendet wird.

- `pub fn create_secure_container(...)`: Erstellt einen **anonymen, weiterleitungs-sicheren** `SecureContainer`. Ein symmetrischer Payload-Schlüssel wird für jeden Empfänger **und den Sender selbst** mittels eines **ephemeren Diffie-Hellman-Austauschs (X25519)** und Key-Wrapping verschlüsselt. Der Container enthält keine direkten Identifikatoren und wird als Ganzes signiert.
- `pub fn open_secure_container(...)`: Entschlüsselt den Payload, indem es versucht, den Payload-Schlüssel mit dem privaten Schlüssel des Nutzers (als Sender oder Empfänger) und dem öffentlichen ephemeren Schlüssel des Containers zu entschlüsseln. Die Signatur des Containers muss vom Aufrufer separat verifiziert werden, da die `sender_id` erst nach der Entschlüsselung bekannt ist.

### `services::signature_manager` Modul

Enthält die zustandslose Geschäftslogik für die Erstellung und kryptographische Validierung von losgelösten Signaturen (`DetachedSignature`).

- `pub fn complete_and_sign_detached_signature(...)`: Nimmt unvollständige Signatur-Metadaten, berechnet die `signature_id` durch Hashing des kanonischen Inhalts und fügt die digitale Signatur des Unterzeichners hinzu.
- `pub fn validate_detached_signature(...)`: Validiert eine losgelöste Signatur, indem die `signature_id` neu berechnet und die kryptographische Signatur gegen die ID und den Public Key des Unterzeichners geprüft wird.

### `services::standard_manager` Modul

Dieses Modul enthält die Logik zur Verarbeitung und Verifizierung von Gutschein-Standard-Definitionen (TOML-Dateien).

- `pub fn verify_and_parse_standard(toml_str: &str) -> Result<(VoucherStandardDefinition, String), VoucherCoreError>`
  - Parst einen TOML-String in eine `VoucherStandardDefinition`.
  - Kanonisiert die Definition (ohne Signatur) in einen stabilen JSON-String.
  - Berechnet den SHA3-256 Hash des kanonischen JSON-Strings (dies ist der "Konsistenz-Hash").
  - Verifiziert die im TOML enthaltene Ed25519-Signatur gegen den berechneten Hash.
  - Gibt bei Erfolg die verifizierte Definition und den Konsistenz-Hash zurück.
- `pub fn get_localized_text<'a>(texts: &'a [LocalizedText], lang_preference: &str) -> Option<&'a str>`
  - Löst einen lokalisierten Text gemäß einer definierten Fallback-Logik auf.

### `services::voucher_manager` Modul

Dieses Modul stellt die Kernlogik für die Erstellung und Verarbeitung von Gutscheinen bereit.

- `pub fn create_voucher(data: NewVoucherData, verified_standard: &VoucherStandardDefinition, standard_hash: &str, creator_signing_key: &SigningKey, lang_preference: &str) -> Result<Voucher, VoucherCoreError>`
  - Orchestriert die Erstellung eines neuen, vollständigen Gutscheins.
  - Erzeugt eine `voucher_nonce`, um den initialen `prev_hash` unvorhersehbar zu machen und so die Anonymität des Erstellers auf Layer 2 zu schützen.
  - Nutzt eine korrigierte Logik zur Berechnung von Gültigkeitsdauern.
  - Nimmt den **Konsistenz-Hash** des verifizierten Standards entgegen und bettet ihn in den Gutschein ein.
  - Verwendet die Logik zur Auswahl des mehrsprachigen Beschreibungstextes aus dem Standard.
- `pub fn create_transaction(voucher: &Voucher, standard: &VoucherStandardDefinition, sender_id: &str, sender_key: &SigningKey, recipient_id: &str, amount_to_send_str: &str) -> Result<Voucher, VoucherCoreError>`
  - Erstellt eine Kopie des Gutscheins mit einer neuen Transaktion.
  - Die Signatur der Transaktion sichert nun ein minimales Objekt (`{prev_hash, sender_id, t_id}`).
  - Verwendet `decimal_utils` zur **strengen Validierung der Betragspräzision** und zur **kanonischen Formatierung** der Werte.
  - Verwendet explizit den Transaktionstyp "transfer" für einen vollen Transfer.

### `services::voucher_validation` Modul

Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts gegen die Regeln seines Standards. **Die Validierungslogik wurde erheblich gehärtet.**

- `pub fn validate_voucher_against_standard(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError>`  - Führt eine umfassende Prüfung des Gutscheins durch, inklusive der korrekten Verkettung unter Einbeziehung des `voucher_nonce`, der Validierung der vereinfachten Transaktions-Signatur und neuer Geschäftsregeln (z.B. keine Transaktionen an sich selbst).
- Überprüft die **Konsistenz des eingebetteten Standard-Hashes** mit dem Hash des aktuellen Standard-Objekts, um sicherzustellen, dass der Gutschein immer gegen die exakte Version des Standards validiert wird, mit der er erstellt wurde.
- Überprüft, ob der **Transaktionstyp** (`t_type`) laut Standard erlaubt ist.
- Überprüft die Integrität und kryptographische Gültigkeit aller **zusätzlichen Signaturen** (`additional_signatures`).