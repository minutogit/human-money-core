---
name: project-context
description: Complete API reference, data structures, cryptography details, and module overview for human_money_core. Load this when you need deep technical context about the library.
---

# human_money_core — Full Project Context

Dies ist die Kontextdatei für die Entwicklung der Rust-Core-Bibliothek `human_money_core`. Sie dient als "README für die KI", um ein umfassendes Verständnis des Projekts und seiner Anforderungen zu gewährleisten.

## 1\. Projekt & Zweck

- **Projektname:** `human_money_core`

### Was ist die human_money_core?
Die human_money_core ist eine Rust-Bibliothek zur Verwaltung und Übertragung von selbstgeschöpften, kryptographischen Wertdokumenten. Sie ermöglicht einen dezentralen Werteaustausch, der fundamentale Konzepte klassischer Krypto-Systeme auf den Kopf stellt und den Menschen wieder in den Mittelpunkt rückt.

**1. Architektur: Autarke Container statt globales Ledger**
Das System nutzt bewusst keine Blockchain und benötigt keinen Netzwerkkonsens. Jedes Wertdokument ist eine isolierte, portable JSON-Datei. Diese Datei fungiert als autarker Container, der seine komplette, kryptographisch verkettete Transaktionshistorie (Signaturkette) in sich selbst trägt. Transaktionen können asynchron und offline erfolgen durch die direkte, P2P-basierte Übergabe der aktualisierten Datei.

**2. "Human Money": Identität, Reputation und Vertrauen**
Warum Human Money? Weil bei der Schöpfung von Werten (wie Dienstleistungen, Zeit oder Gütern) nicht die Technik, sondern der Mensch im Fokus steht. Transaktionen nutzen in der Regel bekannte kryptographische Identitäten (did:key). Sicherheit und Akzeptanz des Geldes basieren somit nicht auf einem abstrakten Algorithmus, sondern primär auf der realen Reputation und Vertrauenswürdigkeit der handelnden Akteure.

**3. Sicherheitsparadigma: Betrugserkennung statt Betrugsvermeidung**
Da es auf Layer 1 keinen globalen Konsens-Mechanismus gibt, der Transaktionen vor der Ausführung validiert, setzt die Kernarchitektur auf deterministische Betrugserkennung. Das System garantiert, dass jeder Betrugsversuch (z. B. Double-Spending) durch kryptographische NIZK-Fallen (Identity Traps) fälschungssichere mathematische Beweise in der Signaturkette hinterlässt, welche die Identität des Betrügers mathematisch offenlegen.

**4. Datenschutz vs. Rückverfolgbarkeit**
Das System erlaubt es, Transaktionen mit zusätzlichen Datenschutzschichten (Verschlüsselung, ephemere Schlüssel) zu versehen. Dies ist eine bewusste Abwägung: Während die Privatsphäre der Nutzer steigt, wird die Aufklärung von Betrugsfällen und Sybil-Identitäten aufwendiger, da sie eine manuelle, kryptographische Rückverfolgung der Kette erfordert.

**5. Skalierung: Layer 2 für globale Betrugsvermeidung**
Während der Core (Layer 1) offline funktioniert und primär auf Erkennung setzt, kann das System durch eine zusätzliche, optionale Online-Schicht (Layer 2) mit präventiver Betrugsvermeidung erweitert werden. Im Gegensatz zu Blockchains erfordert dieser Layer 2 keinen globalen Konsens. Er fungiert lediglich als dezentrales Register für kryptographische "Locks" (Sperren). Clients können online asynchron abprüfen, ob ein Gutschein-Fingerprint bereits als ausgegeben markiert wurde, wodurch ein globaler, präventiver Schutz vor Double-Spending entsteht, ohne die Skalierbarkeit zu gefährden.

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

- **Separated Account Identity (SAI) für strikte Kontotrennung:** Ein Benutzer besitzt eine einzige kryptographische Identität (Public Key), die aus dem Mnemonic abgeleitet wird. Durch die Verwendung von Präfixen (z.B. "pc", "mobil") oder die Nutzung von **prefix-losen Root-Accounts** (`did:key`) werden separate Konten definiert. Hierbei kommt die **Context-Bound Key Derivation** via HKDF-SHA256 zum Einsatz: Der geheime Seed für jedes Konto wird kryptographisch sauber aus dem Hauptschlüssel und dem optionalen Präfix abgeleitet. Dies gewährleistet:
  - Einheitliche Identität für das Web of Trust: Alle Aktionen werden kryptographisch derselben Identität zugeordnet.
  - Strikte Kontentrennung: Die Wallet-Logik verwendet die vollständige User-ID (z.B. `pc:aB3@did:key:z...` oder `did:key:z...`) zur Validierung des Besitzes. Guthaben bleibt im definierten ökonomischen Kontext.
  - Schutz vor "Identity Hopping": Da die Schlüsselableitung an den Kontext gebunden ist, können Identitäten nicht einfach gewechselt werden, ohne die mathematische Falle (Identity Trap) auszulösen.

- **WalletSeal Rollback Guard:** Ein kryptographisches Epochen-System mit hash-verketteten Siegeln (`WalletSeal`), das das Wallet vor Rollback-Angriffen (Wiedereinspielen alter Backups) und Forking schützt. Es beinhaltet einen Fork-Lock-Mechanismus und ein Zonen-Modell für Replay-Schutz mit benutzergesteuerten Recovery-Overrides.

- **Storage Integrity (Integritätsschutz):** Jede Datei im Wallet-Speicher ist durch einen SHA3-256 Integritätsnachweis geschützt, der fest an das aktuelle `WalletSeal` gebunden ist. Dies ermöglicht die Erkennung von manipulierten, fehlenden oder unbekannten Dateien im Profilverzeichnis bei jedem Zugriff.

- **Wallet Event Sourcing:** Alle statusändernden Aktionen werden in einem Append-only Ledger (`WalletEvent`) aufgezeichnet (z.B. `VoucherCreated`, `TransferReceived`). Dies ermöglicht eine lückenlose Transaktionshistorie und die Wiederherstellung des Zustands. Um Skalierbarkeit zu gewährleisten, werden Events in monatlichen, verschlüsselten Chunks (`YYYY_MM.json.enc`) gespeichert.

- **Offline-Fähigkeit:** Transaktionen sollen auch offline durchgeführt werden können, indem die aktualisierte Gutschein-Datei direkt an den neuen Halter übergeben wird.

- **Fokus auf Betrugserkennung, nicht -vermeidung:** Da es kein globales Ledger gibt, kann die Core-Bibliothek nicht verhindern, dass ein Nutzer widersprüchliche Transaktionshistorien (Double Spending) erzeugt. Das System stellt stattdessen sicher, dass jeder Betrugsversuch durch digitale Signaturen kryptographisch beweisbar ist, was eine Erkennung und soziale Sanktionen in einem übergeordneten System (Layer 2) ermöglicht.

- **Peer-to-Peer Gossip-Protokoll (30/70 KISS):** Zur dezentralen Erkennung von Double Spending tauschen Wallets bei jeder Transaktion **Transaktions-Fingerprints** (`ds_tag`) anderer Transaktionen aus ($V \times 10$ Standard-Fingerprints, $V \times 3$ Quarantäne-Paare). Die Verteilung erfolgt über 30 % direkte Spitzen (`direct_queue`) und 70 % frischen Foreign Gossip (`fresh_gossip_pool`) via Bernoulli-Münzwurf. Fingerprints sind deterministisch aus dem Input abgeleitet (`hash(prev_hash + sender_ephemeral_pub)`), was eine O(1) Erkennung von Kollisionen ermöglicht.

- **Transaction Verification Layer (Layer 2):** Die Bibliothek implementiert nun die Kommunikation und Verifizierung für Layer 2. Dies umfasst die Interaktion mit L2-Gateways, die Validierung von L2-Signaturen und die Handhabung von Quarantäne-Zuständen bei Double-Spending oder Verifizierungsfehlern. Die Struktur ist für eine dezentrale Überprüfung durch "Chain of Authority" (CoA) Knoten optimiert.

- **FFI/WASM-Kompatibilität:** Rust-Typen und -Funktionen müssen so gestaltet sein, dass sie einfach über FFI and WASM exponiert werden können (z.B. durch Verwendung von `#[no_mangle]`, C-kompatiblen Datentypen und `wasm_bindgen`).

## 4\. Coding-Standards & Wichtige Regeln

- **Rust Best Practices:** Einhaltung der idiomatischen Rust-Programmierung, Fokus auf Sicherheit, Performance und Speichereffizienz.

- **Fehlerbehandlung:** Robuste Fehlerbehandlung mit Rusts `Result`-Typ.

- **Dokumentation:** Umfassende interne Dokumentation (Doc-Kommentare) für alle öffentlichen Funktionen und Strukturen.

- **Testen:** Umfassende Unit- und Integrationstests.

- **Keine externen Netzwerkaufrufe:** Die Core-Bibliothek soll keine direkten Netzwerkaufrufe für die Layer-2-Funktionalität enthalten. Diese Interaktionen werden von den übergeordneten Anwendungen gehandhabt, die `human_money_core` nutzen.

## 5\. Kernkonzepte aus dem Paper (Zusammenfassung)

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
      "amount": "STRING", // Übertragener Teilbedrag
      "sender_remaining_amount": "STRING, optional", // Restguthaben beim Sender (nur bei Teilung)
      "sender_ephemeral_pub": "STRING, optional", // Reveal des Stealth-Keys (Preimage für prev_hash Check)
      "change_ephemeral_pub_hash": "STRING, optional", // Neuer Anker für das Wechselgeld des Senders
      "privacy_guard": "STRING, optional", // Verschlüsselter RecipientPayload (nur für Empfänger lesbar)
      "trap_data": { // Mathematische Falle bei Double-Spending (V3 Shared-Signature Trap)
        "ds_tag": "STRING", // Deterministischer Fingerprint des Inputs
        "trap_r": "STRING", // Shard R_i = R_sig + tau_i * M_R (Base58, 32 Byte, komprimierter Edwards-Punkt)
        "trap_s": "STRING" // Shard s_i = s_sig + tau_i * m_s mod q (Base58, 32 Byte, kanonischer Skalar)
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

### Double-Spending-Erkennung (Die Falle) — V3 Shared-Signature Trap (SST)

Ein Betrugsversuch wird durch die **V3 Shared-Signature Trap (SST)** unter Domain-Tag `HMC_TX_AUTH_V3` erkannt — eine deterministische Schnorr-Falle mit **autonomer did:key-Deanonymisierung ohne Framing-Möglichkeit** (EUF-CMA).

- **Double-Spend Tag (`ds_tag`):** Ein deterministischer Identifier des Inputs: `ds_tag = hash(prev_hash || sender_ephemeral_pub)` (SHA3-256, längenpräfixiert via `get_hash_from_slices`, präfix-unabhängig). Kollidiert dieser Tag bei unterschiedlichen `t_id`s, liegt ein Double-Spend vor.
- **Mathematisches Hardening:** Die Hash-Berechnungen wurden auf **SHA3-256** (für allgemeine Daten) standardisiert und zentralisiert. Durch die Nutzung von `get_hash_from_slices` wird Malleability verhindert (Längenpräfixe für Segmente). Für interne kryptographische Primitive (HKDF, PBKDF2) wird weiterhin die SHA2-Familie genutzt.
- **The Trap (V3 SST):** Jede Spend-Transaktion trägt in `trap_data` nur einen **Shard** `TrapData { ds_tag, trap_r, trap_s }` einer einzigen deterministischen Schnorr-Signatur $\sigma = (R_{sig}, s_{sig})$ über $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \| ds\_tag \| E)$. $R_i = R_{sig} + \tau_i \cdot M_R$ (komprimierter Edwards-Punkt, Base58), $s_i = s_{sig} + \tau_i \cdot m_s \pmod q$ (kanonischer Skalar, Base58), mit $\tau_i = H(\text{"HMC\_TAU\_V1"} \| ds\_tag \| t\_id_i) \pmod q$. Die Masken $M_R = \text{hash\_to\_curve}(\text{"HMC\_MASK\_R\_V1"} \| x \| E \| ds\_tag)$ und $m_s = H(\text{"HMC\_MASK\_S\_V1"} \| x \| E \| ds\_tag)$ leiten sich ausschließlich aus dem langfristigen Schlüssel $x$ ab. V2-Felder (`u`, `blinded_id`, `proof`) existieren nicht mehr und werden beim Laden hart abgewiesen (`InvalidFormat`). Genesis-Transaktionen tragen keine `trap_data` (`trap_r/s = "none"` im Fingerprint). **Einzel-Shard-Anonymität:** Ein einzelner Shard verbirgt den Signierer informationstheoretisch (4 Unbekannte vs. 3 Gleichungen) — kein Register-Mining möglich. **Kollisions-Enttarnung:** Zwei kollidierende Shards ($\tau_1 \neq \tau_2$) erlauben lineare Rekonstruktion $M_R = (R_1 - R_2) / (\tau_1 - \tau_2)$, $m_s = (s_1 - s_2) / (\tau_1 - \tau_2)$ und Extraktion $\hat{X} = (\hat{s} \cdot G - \hat{R}) \cdot c^{-1}$ — der `did:key` des Täters. Framing erfordert Schnorr-Fälschung (EUF-CMA-unmöglich); degenerierte Fälle ($\tau$-Gleichheit, identische Shards, $c=0$, neutrales Element) werden als Firewall abgewiesen. Der private Zeuge $W = (R_{sig}, s_{sig}, M_R, m_s)$ reist verschlüsselt im `RecipientPayload` und wird via `verify_sst_witness` bei Übergabe geprüft.
- **Anonymisierte Analyse:** Auf Layer 2 werden nur Fingerprints ausgetauscht. Ein Server sieht keine Klartext-IDs oder Beträge, sondern nur den `ds_tag`, `trap_r/s`-Shards und verschlüsselte Zeitstempel. Fingerprints sind **selbstauthentifizierend**: `layer2_signature` über `HMC_TX_AUTH_V3` ist allein aus Fingerprint-Daten verifizierbar.
- **Beweis:** Ein Double-Spend-Beweis (`ProofOfDoubleSpend`) kombiniert die kollidierenden Transaktionen/Fingerprints und ermöglicht via `extract_sst_identity` / `verify_stored_trap_shards_against_identity` die mathematische Extraktion der Täter-`did:key`.

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

### Wallet-Sicherheit: Seal & Integrity

Um den lokalen Speicher gegen physische Manipulation und Rollbacks zu schützen, verwendet das System zwei eng verzahnte Mechanismen:

1.  **WalletSeal (Rollback Guard):** Jedes Speichern des Wallets erzeugt ein neues Siegel, das den Hash des vorherigen Siegels enthält. Diese Kette verhindert das unbemerkte Zurückrollen auf einen älteren Zustand (Backup). Ein `ForkLock` erkennt, wenn mehrere Instanzen desselben Wallets divergieren.
2.  **Storage Integrity:** Alle Datensätze (Voucher, Fingerprints, Events) werden in einer Integritätsliste erfasst. Ein SHA3-256 Hash über diese Liste wird im `WalletSeal` signiert. So wird jede Manipulation an den Dateien auf der Festplatte sofort erkannt.

### Wallet Event Sourcing

Das Wallet führt ein lückenloses Protokoll aller Ereignisse (`WalletEvent`).
- **Transaktionstypen:** `VoucherCreated`, `TransferSent`, `TransferReceived`, `VoucherExpired`, `VoucherQuarantined`.
- **Speicherung:** Events werden atomar mit dem Wallet-Zustand gespeichert und periodisch in monatliche, verschlüsselten Archiv-Dateien (`YYYY_MM.json.enc`) ausgelagert, um den Speicherbedarf im RAM gering zu halten.
- **Wiederherstellung:** Ermöglicht die Rekonstruktion der Historie für UI-Zwecke und Audit-Logs.

## 6. Codebase & API Details

For concrete function signatures and live API details, inspect `src/` directly or run `cargo doc`.
