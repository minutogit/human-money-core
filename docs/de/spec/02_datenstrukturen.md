---
creation date: 2026-02-01 10:28
modification date: 2026-02-10
tags:
  - human-money-core
  - data-structure
  - privacy
---
# 02. Datenstrukturen & Privacy Modes

**Kontext:** Teil 2 der Human Money Core Spezifikation.

## 1. Privacy Modes & Transaktionsstruktur

### 1.1 Grundkonzept: Privacy als Overlay

Das System trennt strikt zwischen **technischer Sicherheit (Layer 2)** und **sozialer Identität (Layer 1)**.

- **Layer 2 (Technischer Layer):** Jede Transaktion verwendet immer ephemere Schlüssel und kryptographische Anker, um Double-Spending durch das Layer 2 verhindern zu können. Das zentrale Feld hierfür ist `receiver_ephemeral_pub_hash` (der "Private Key" / Anker für die nächste Transaktion). Dies ist der unveränderliche Unterbau.
- **Layer 1 (Sozialer Layer):** Die Offenlegung der Identität (`did:key`) in den Feldern `sender_id` und `recipient_id` ist ein optionales Overlay. Ein Sender kann entscheiden (oder durch den Standard gezwungen werden), ob diese Felder mit lesbaren DIDs gefüllt werden oder leer/anonym bleiben.

**Merksatz:** Das Netzwerk validiert technisch immer Anonym (Zero-Knowledge bzgl. Identität), aber sozial optional Transparent.

### 1.2 Konfiguration: Die Privacy Modes

In der `standard.toml` (bzw. `VoucherStandardDefinition`) wird der Modus über die Variable `privacy_mode` gesteuert.

#### 1.2.1 Die Modi

| Modus | Wert (TOML) | Beschreibung | Sender-Identität (sender_id) | Empfänger-Identität (recipient_id) |
| :--- | :--- | :--- | :--- | :--- |
| Öffentlich | `"public"` | Transparenz ist erzwungen. | **PFLICHT** (`did:key`) | **PFLICHT** (`did:key`) |
| Diskret | `"private"` | Identitäten sind verboten. | **VERBOTEN** (None/Hash) | **VERBOTEN** (None/Hash) |
| Flexibel | `"flexible"` | Sender entscheidet. | **OPTIONAL** | **OPTIONAL** (Darf `did:key` sein) |

**Hinweis:** Unabhängig von diesen Feldern ist der technische Anker `receiver_ephemeral_pub_hash` immer vorhanden und sichert die Transaktion.

**Sonderregel Issuer:** Der Ersteller des Gutscheins (`creator_id`) ist immer öffentlich, unabhängig vom Modus, um das Vertrauen in die Deckung zu gewährleisten.

### 1.3 Definition in standard.toml

```toml
[privacy]
# Optionen: "public", "private", "flexible"
mode = "flexible"
```

## 2. Datenstrukturen

### 2.1 Format der Bezeichner (Composite Identifier)

Um Domain Separation und menschliche Lesbarkeit zu vereinen, folgen alle Identitäten im System einem festen Muster:

`[PRÄFIX]:[CHECKSUMME]@[DID-KEY]`

- **Präfix:** Der logische Kontext oder Sub-Account (z. B. `pc-wallet`, `mobile`, `trading`). Es dient dazu, verschiedene Verwendungszwecke unter einer einzigen Identität zu trennen.
    
- **Checksumme:** Eine kurze alphanumerische Zeichenfolge zur Validierung des Präfixes.
    
- **DID-Key:** Die vollständige dezentrale Identität (z. B. `did:key:z6Mk...`).

**Beispiel:**

`creator:fY7@did:key:z6MkfoBD8yWs1ECX31fEZk8EGbVjJQckRUCLrUMP6ctc5Fn`

### 2.2 Transaktions-Struct

Das `Transaction` Struct wird erweitert, um die zwei Signaturebenen (Technisch vs. Identität) abzubilden.

```rust
pub struct Transaction {
    /// Eindeutige ID der Transaktion (Hash über alle Felder inkl. Nonce).
    pub t_id: String,
    
    /// Art der Transaktion (Standard, Split, Merge, Mint).
    pub t_type: String,

    // --- TECHNISCHER LAYER (Layer 2 - Immer vorhanden) ---
    
    /// Der Hash des vorherigen Private-Public-Keys oder Transaktions-Hash.
    /// Dient als Anker in der Kette.
    pub prev_hash: String,

    /// Der Hash des ephemeren Public Keys des Empfängers (Private Key).
    /// Dies ist der Anker für die nächste Transaktion.
    /// Existiert IMMER, auch wenn recipient_id öffentlich ist.
    pub receiver_ephemeral_pub_hash: String,

    // --- SOZIALER LAYER (Layer 1 - Abhängig vom Privacy Mode) ---

    /// Die öffentliche Identität des Senders (z.B. "did:key:z6Mk...").
    /// - public: ZWINGEND
    /// - private: LEER (None)
    /// - flexible: OPTIONAL
    pub sender_id: Option<String>,

    /// Die Signatur ausgeführt durch den Identity-Key (sender_id).
    /// Beweist, dass der Sender 'sozial' zu dieser technischen Transaktion steht.
    /// Signiert: Hash(t_id).
    /// Muss vorhanden sein, wenn sender_id gesetzt ist.
    pub sender_identity_signature: Option<String>,

    /// Die technische Signatur des Senders (Layer 2).
    /// Beweist den technischen Besitz des Gutscheins.
    /// Signiert: Die t_id der Transaktion.
    /// Signierer: Der Private Key von sender_ephemeral_pub (der enthüllte Key).
    /// Zweck: Autorisierung des L2-Locks und Nachweis des Besitzes.
    pub layer2_signature: Option<String>,

    /// An wen geht das Geld (Layer 1)?
    /// - public: Muss ein `did:key` sein.
    /// - private: Darf KEIN `did:key` sein (z.B. leer oder Hash).
    /// - flexible: Darf ein `did:key` sein ODER leer/Hash.
    pub recipient_id: String,

    pub amount: String,
    // ... weitere Felder (sender_remaining_amount, etc.) ...
    
    // --- SICHERHEITSMECHANISMEN (Layer 2) ---
    
    /// Verschlüsselte Wiederherstellungsdaten (ChaCha20-Poly1305).
    /// Binär-Layout (Base64 kodiert): [EphemeralPK(32)] + [Nonce(12)] + [Ciphertext]
    /// Enthält das serialisierte `RecipientPayload`-Struct.
    /// Ermöglicht dem Empfänger die Wiederherstellung von Kontext und Seeds.
    pub privacy_guard: String,

    /// Die mathematische Falle für Double-Spend Erkennung.
    /// Enthält Challenge `u`, Response `v` und den Zero-Knowledge-Proof.
    pub trap_data: TrapData,
}
```

### 2.3 Der verschlüsselte Payload (RecipientPayload)

Dies ist der entschlüsselte Inhalt von `privacy_guard`.

```rust
#[derive(Serialize, Deserialize)]
struct RecipientPayload {
    /// Die vollständige Composite-DID des Absenders
    /// Beispiel: "minuto:a1b@did:key:zAlice..."
    /// Ermöglicht dem Empfänger, den Sender im Adressbuch anzuzeigen.
    pub sender_permanent_did: String, 

    /// Präfix-Validierung: Das Ziel-Unterkonto inklusive Checksumme.
    /// Beispiel: "creator:fY7"
    pub target_prefix: String,

    /// Zeitstempel der Erstellung (u64)
    pub timestamp: u64,

    /// Der Seed für den nächsten ephemeren Schlüssel (damit der Empfänger ihn generieren kann).
    /// Dies ermöglicht dem Empfänger, den nächsten Private Key abzuleiten, ohne dass dieser über das Netzwerk übertragen wird.
    pub next_key_seed: String, 
}
```

#### 2.3.1 Schlüsselableitung (HKDF)
Für die symmetrische Verschlüsselung des Payloads wird der Shared Secret aus dem X25519-Austausch mittels HKDF-SHA256 expandiert.

**Info-String Format:**
`"human-money-core/x25519-exchange" + sort(public_key_1, public_key_2)`

Wobei `public_key_1` und `public_key_2` die 32-Byte X25519 Public Keys (ephemeral und statisch) in lexikographischer Sortierung sind. Dies stellt sicher, dass beide Parteien denselben Info-String unabhängig von ihrer Rolle berechnen.


### 2.4 Layer 2 Response Envelope

Jede Antwort vom Layer 2 Server ist in einen signierten Container verpackt, um die Authentizität des Servers sicherzustellen.

```rust
pub struct L2ResponseEnvelope {
    /// Das eigentliche Urteil des Servers (Ok, Verified, MissingLocks, etc.).
    pub verdict: L2Verdict,
    
    /// Die Ed25519-Signatur des Servers über das serialisierte Urteil.
    /// Der Server nutzt hierfür seinen privaten identity_key.
    pub server_signature: [u8; 64],
}
```

## 3. Validierungslogik

Der Validator prüft Transaktionen basierend auf dem `privacy_mode` des Standards.

### 3.1 Basispfrüfung (Immer)
- **Hash-Integrität:** Prüfe ob `t_id` korrekt aus dem Inhalt gehasht wurde.
- **Layer 2 Beweis:** Verifiziere `layer2_signature` gegen den bekannten ephemeral Public Key (aus `prev_hash` bzw. Vorläufer-Transaktion).

### 3.2 Modus-Spezifische Prüfung

**Modus: "public"**
- **Prüfung A:** Ist `sender_id` vorhanden? Falls `None` → **FEHLER**.
- **Prüfung B:** Ist `sender_id` ein gültiger `did:key`? Falls Nein → **FEHLER**.
- **Prüfung C:** Verifiziere `sender_identity_signature` mit `sender_id` gegen `t_id`. Falls ungültig → **FEHLER**.

**Modus: "private"**
- **Prüfung A:** Ist `sender_id` vorhanden? Falls `Some(...)` → **FEHLER**.
- **Prüfung B:** Enthält `recipient_id` einen `did:key`? Falls Ja → **FEHLER** (Empfänger muss geschützt werden).

**Modus: "flexible"**
- **Fall A (Sender will transparent sein):**
    - Wenn `sender_id` gesetzt ist: Muss `sender_identity_signature` gültig sein.
- **Fall B (Sender will anonym bleiben):**
    - Wenn `sender_id` leer ist: Nur `layer2_signature` (technisch) ist notwendig.
- **Empfänger-Wahl:** Das Feld `recipient_id` darf einen `did:key` enthalten (öffentlich addressiert) oder anonym bleiben. Die technische Sicherheit ist durch `receiver_ephemeral_pub_hash` in beiden Fällen gegeben.

### 3.3 Anwendung in der Praxis (User Story "Flexible")

Alice (Sender) hat einen Gutschein. Sie will an Bob (Empfänger) senden.
Der Standard ist "flexible".

**Szenario:** Alice möchte transparent senden (z.B. Projektabrechnung), Bob gibt ihr einfach seine DID.
1. Alice setzt ihre `sender_id` auf ihren `did:key`.
2. Alice signiert mit ihrem Identity Key (`sender_identity_signature`).
3. Alice trägt Bobs DID in `recipient_id` ein (damit jeder sieht: "Ging an Bob").
4. **Technischer Hintergrund:** Alice berechnet trotzdem lokal einen Private Key aus Bobs DID und schreibt dessen Hash in `receiver_ephemeral_pub_hash`.

**Ergebnis:**
- **Layer 1 (Sozial):** Jeder sieht "Alice -> Bob".
- **Layer 2 (Technik):** Das Netzwerk sieht einen kryptographischen Anker (`receiver_ephemeral_pub_hash`), der das Double-Spending verhindert.

Bob kann den Gutschein später weiterverwenden, indem er den Private-Key (Private Key) ableitet. Ob er sich dabei dann selbst als "Bob" im `sender_id` Feld offenbart, ist seine Entscheidung (da Modus "Flexible").

## 4. Design-Exkurs: Teilbarkeit vs. Split-Recht

Eine Besonderheit im Standard ist die Koexistenz von `allow_partial_transfers` (Eigenschaft) und dem Transaktionstyp `"split"` (Berechtigung). Diese Trennung ermöglicht präzise Kontrolle über das Verhalten von Werten.

| `allow_partial_transfers` | `"split"` erlaubt? | Bedeutung & Nutzen |
| :--- | :--- | :--- |
| **`true`** | **Ja** | ✅ **Standard Währung:** Der Wert ist teilbar und darf geteilt werden (z.B. Minuto). |
| **`false`** | **Nein** | ✅ **Unteilbares Gut:** Der Wert ist atomar (z.B. Konzert-Ticket). |
| `false` | Ja | ❌ **Logischer Widerspruch:** Wird technisch verhindert. Semantik (`false`) schlägt Berechtigung. |
| **`true`** | **Nein** | 💡 **Sonderfall "Change-Only":** Der Wert ist rechnerisch teilbar (Guthaben), darf aber **nicht** aufgeteilt weitergegeben werden. Erlaubt ist nur "Alles oder Nichts". |

## 5. Konfliktmanagement & Reputation (Dezentrales Immunsystem)

Das Human Money Netzwerk nutzt ein dezentrales Reputations- und Konfliktmanagement, um Double-Spends zu bestrafen und bösartige Knoten im Netzwerk zu identifizieren. Da es keinen zentralen Konsens gibt, verwaltet jeder Client lokal einen eigenen `ProofStore`.

### 5.1 Fingerprints & Metadaten (VIP-Gossip)

Um auf kollidierende Transaktionen hinzuweisen, gossipt das Netzwerk anonyme `TransactionFingerprint`s. Die Verbreitung und das Routing werden über getrennte Metadaten (`FingerprintMetadata`) gesteuert.

```rust
pub struct FingerprintMetadata {
    /// Die Verbreitungstiefe des Fingerprints im Netzwerk (Anzahl der Hops).
    /// Datentyp `i8`.
    /// 
    /// - Positive Werte (0 bis 127): Organischer Gossip (harmlos)
    /// - Negative Werte (-1 bis -128): "VIP"-Verbreitung (Betrugserkennung)
    pub depth: i8,
    // ...
}
```

**Effektive Tiefe & Priorisierung:**
Damit "toxische" Fingerprints (Betrug) sich schnell im P2P-Netzwerk ausbreiten können, erhalten sie bei der Auswahl für ein Gossip-Bundle einen 2-Hop Vorrang, altern aber dennoch organisch. Logik: `effektive_tiefe = abs(depth) - 2`. Ein VIP-Tag mit `depth: -1` wird also behandelt als hätte er Tiefe `-1`, und wird somit vor einem taufrischen harmlosen Tag (Tiefe `0`) weitergeleitet.

### 5.2 Der Double-Spend Beweis (Fraud Proof)

Lokale oder verifizierte Konflikte werden in einem fälschungssicheren Beweis gespeichert.

```rust
pub struct ProofOfDoubleSpend {
    pub proof_id: String,           // Deterministischer Hash des Konflikts
    pub offender_id: String,        // Identität des Täters
    pub conflicting_transactions: Vec<Transaction>, // Mindestens 2 verschiedene Pfade
    pub affected_voucher_name: Option<String>,      
    pub voucher_standard_uuid: Option<String>,
    // ...
}
```

### 5.3 Der Lokale Zustand (ProofStoreEntry & ConflictRole)

Der Nutzer bewertet empfangene Beweise nicht nur kryptografisch, sondern auch persönlich in Bezug auf sich selbst. Dies wird im `ProofStoreEntry` gekapselt.

```rust
pub struct ProofStoreEntry {
    pub proof: ProofOfDoubleSpend,
    pub local_override: bool,       // Nutzer verzeiht Täter explizit
    pub conflict_role: ConflictRole,
}

pub enum ConflictRole {
    Victim,   // Unser lokales Guthaben wurde direkt beschädigt
    Witness,  // Wir haben den Konflikt nur passiv/extern beobachtet
}
```

### 5.4 Impliziter Reputationsstatus

Basierend auf den vorliegenden, ungeklärten `ProofOfDoubleSpend` Objekten berechnet das System die Reputation dynamisch:

```rust
pub enum TrustStatus {
    Clean,                          // Alles ok, keine Betrugsfälle
    KnownOffender(String),          // Ungelöster Betrugsbeweis liegt vor
    Resolved(String, bool),         // Konflikt durch Opfer oder manuell geklärt
}
```

