---
creation date: 2026-02-01 10:28
modification date: Sonntag 1. Februar 2026 10:28:06
tags:
  - human-money-core
vc-id: 3b29e076-55bb-4fde-93ea-5bac0b28cd8a
---
# Spezifikation: Hybride Privatsphäre, Offline-Sicherheit & Quantensichere Anker

**Version:** 4.5 (Privacy Modes Extension)

**Datum:** 03.02.2026

**Status:** IMPLEMENTIERUNGSVORLAGE (REVISED)

**Kontext:** `human_money_core` Library

**Tags:** `cryptography`, `privacy`, `zkp`, `post-quantum`, `offline-cash`

## 1. Einführung und Design-Philosophie

Das System `human_money` realisiert ein digitales Bargeld, das radikaler ist als herkömmliche Kryptowährungen. Es verzichtet auf eine globale Blockchain zugunsten lokaler, dateibasierter Gutscheine ("Voucher"). Um in diesem dezentralen Umfeld Sicherheit und Privatsphäre zu garantieren, kombiniert das Protokoll drei fortschrittliche Konzepte:

1. **Quantensichere Forward Secrecy (Der Anker):**
    
    Die Identität (Public Key) des aktuellen Besitzers wird niemals im Klartext in der Kette gespeichert. Stattdessen nutzt das Protokoll kryptographische Commitments (Hashes). Erst im Moment der Ausgabe wird der Schlüssel enthüllt. Dies schützt ruhende Guthaben selbst vor zukünftigen Angriffen durch Quantencomputer, da der Private Key nicht aus dem Hash abgeleitet werden kann.
    
2. **Mathematische Double-Spend Erkennung (Die Falle):**
    
    Da es keine zentrale Instanz gibt, die "Doppelausgaben" in Echtzeit verhindert, nutzt das System eine mathematische Falle. Wer denselben Gutschein-Zustand zweimal ausgibt, muss zwangsläufig seine kryptographische Identität enthüllen. Dies geschieht rein rechnerisch durch den Vergleich von zwei anonymen Transaktions-Fingerprints (Slope-Calculation).
    
3. **Kontext-Integrität (Sub-Accounts):**
    
    Durch "Präfix-Validierung" im verschlüsselten Payload wird sichergestellt, dass Guthaben strikt in seinem definierten ökonomischen Kontext (z. B. "Regionalwährung A" vs. "Zeitbank B") bleibt, auch wenn der Nutzer denselben kryptographischen Hauptschlüssel (did:key) verwendet.
    

## 2. Bedrohungsmodell & Sicherheitsanalyse

Dieses Modell beschreibt, wie das System spezifische Angriffe durch kryptographische Garantien abwehrt.

### 2.1 Angriff: "Brute Force Deanonymization"

- **Szenario:** Ein Angreifer sammelt Millionen von Public Keys und versucht, durch Einsetzen in die mathematische Falle (Trap) herauszufinden, wer der Sender einer anonymen Transaktion war.
    
- **Analyse:** Die Trap-Gleichung lautet $V = m \cdot U + ID$. Da der Angreifer den Zufallsfaktor $m$ (die Steigung) nicht kennt, gibt es für jeden beliebigen Public Key auf der Welt ein hypothetisches $m$, das die Gleichung lösen würde.
    
- **Ergebnis (Perfect Hiding):** Es ist mathematisch unmöglich, den wahren Sender von einer zufälligen Annahme zu unterscheiden. Die Privatsphäre ist informationstheoretisch sicher.
    

### 2.2 Angriff: "Trap Evasion" (Ausweichen der Falle)

- **Szenario:** Ein böswilliger Sender versucht, beim zweiten Ausgeben (Double Spend) ein anderes $m$ zu wählen, damit die mathematische Enttarnung fehlschlägt.
    
- **Abwehr (Deterministischer Zwang):** Der Zero-Knowledge-Proof (ZKP) validiert nicht nur die Gleichung, sondern erzwingt deterministische Ableitung via HKDF:
    
    $$m = HKDF(SenderPrivateKey, prev\_hash, info = prefix)$$
    (Wobei das Präfix via HKDF-Expand untrennbar mit dem Schlüssel $m$ gebunden wird).
- **Ergebnis:**
    
    - Wählt der Angreifer das korrekte (gleiche) $m$ $\rightarrow$ Die Falle schnappt zu (Identität wird berechnet).
        
    - Wählt der Angreifer ein anderes $m$ $\rightarrow$ Der ZKP ist ungültig. Die Transaktion wird technisch abgewiesen.

### 2.3 Angriff: "Prefix Confusion" (Falschbuchung)

- **Szenario:** Ein Sender schickt "Währung A" an die Adresse von "Währung B" desselben Empfängers (gleicher Public Key).
    
- **Abwehr:** Das Ziel-Präfix (z. B. `minuto:bth`) ist untrennbar im verschlüsselten Payload eingebettet. Das Präfix ist der Teil der ID vor dem `@` (frei wählbar, mit Checksumme verifiziert).


### 2.4 Angriff: "Sybil-Identität" (Fake DID Proxy)

- **Szenario:** Ein Angreifer sendet Guthaben von seinem Hauptkonto an eine frische Wegwerf-Identität ("Fake DID"). Diese Fake-Identität führt den Double-Spend aus.

- **Analyse:** Die mathematische Falle enthüllt die Fake-ID. Da diese keine Reputation im Web of Trust hat, ist der direkte Reputationsschaden für den Angreifer gering.

- **Abwehr (Manuelle Rückverfolgung):** Hier greift die soziale Komponente des Systems. Da der kryptographische Schutz bei der Fake-ID endet, muss der Pfad manuell rekonstruiert werden:

    1.  **Rückwärts (vom Opfer):** Wer hat den Gutschein von der Fake-ID angenommen?
    2.  **Vorwärts (vom Ersteller):** Wer hat Guthaben AN die Fake-ID gesendet?

    **Konsequenz:** Der letzte *bekannte* Teilnehmer der Kette, der Guthaben an die unbekannte Fake-ID weitergeleitet hat, gerät unter Generalverdacht. Er ist entweder der Angreifer selbst oder hat grob fahrlässig mit einer unvertrauenswürdigen Partei gehandelt. In einem Web of Trust gilt das Prinzip: Wer Werte an Anonyme leitet, haftet sozial für deren Fehlverhalten.
    

## 3. Spezifikation Erweiterung: Privacy Modes & Transaktionsstruktur

**Kontext:** Ergänzung zu Spezifikation - Hybride Privatsphäre und Offline-Sicherheit.
**Betrifft:** Transaction Struct, VoucherStandardDefinition, Validierungslogik.

### 3.1 Grundkonzept: Privacy als Overlay

Das System trennt strikt zwischen **technischer Sicherheit (Layer 2)** und **sozialer Identität (Layer 1)**.

- **Layer 2 (Technischer Layer):** Jede Transaktion verwendet immer ephemere Schlüssel und kryptographische Anker, um Double-Spending durch das Layer 2 verhindern zu können. Das zentrale Feld hierfür ist `receiver_ephemeral_pub_hash` (der "Stealth Key" / Anker für die nächste Transaktion). Dies ist der unveränderliche Unterbau.
- **Layer 1 (Sozialer Layer):** Die Offenlegung der Identität (`did:key`) in den Feldern `sender_id` und `recipient_id` ist ein optionales Overlay. Ein Sender kann entscheiden (oder durch den Standard gezwungen werden), ob diese Felder mit lesbaren DIDs gefüllt werden oder leer/anonym bleiben.

**Merksatz:** Das Netzwerk validiert technisch immer Anonym (Zero-Knowledge bzgl. Identität), aber sozial optional Transparent.

### 3.2 Konfiguration: Die Privacy Modes

In der `standard.toml` (bzw. `VoucherStandardDefinition`) wird der Modus über die Variable `privacy_mode` gesteuert.

#### 3.2.1 Die Modi

| Modus | Wert (TOML) | Beschreibung | Sender-Identität (sender_id) | Empfänger-Identität (recipient_id) |
| :--- | :--- | :--- | :--- | :--- |
| Öffentlich | `"public"` | Transparenz ist erzwungen. | **PFLICHT** (`did:key`) | **PFLICHT** (`did:key`) |
| Diskret | `"stealth"` | Identitäten sind verboten. | **VERBOTEN** (None/Hash) | **VERBOTEN** (None/Hash) |
| Flexibel | `"flexible"` | Sender entscheidet. | **OPTIONAL** | **OPTIONAL** (Darf `did:key` sein) |

**Hinweis:** Unabhängig von diesen Feldern ist der technische Anker `receiver_ephemeral_pub_hash` immer vorhanden und sichert die Transaktion.

**Sonderregel Issuer:** Der Ersteller des Gutscheins (`creator_id`) ist immer öffentlich, unabhängig vom Modus, um das Vertrauen in die Deckung zu gewährleisten.

### 3.3 Datenstruktur: Die angepasste Transaktion

Das `Transaction` Struct wird erweitert, um die zwei Signaturebenen (Technisch vs. Identität) abzubilden.

```rust
pub struct Transaction {
    /// Eindeutige ID der Transaktion (Hash über alle Felder inkl. Nonce).
    pub t_id: String,
    
    /// Art der Transaktion (Standard, Split, Merge, Mint).
    pub t_type: String,

    // --- TECHNISCHER LAYER (Layer 2 - Immer vorhanden) ---
    
    /// Der Hash des vorherigen Stealth-Public-Keys oder Transaktions-Hash.
    /// Dient als Anker in der Kette.
    pub prev_hash: String,

    /// Der Hash des ephemeren Public Keys des Empfängers (Stealth Key).
    /// Dies ist der Anker für die nächste Transaktion.
    /// Existiert IMMER, auch wenn recipient_id öffentlich ist.
    pub receiver_ephemeral_pub_hash: String,

    /// Die Signatur ausgeführt durch den Stealth-Key (Private Key passend zum prev_hash).
    /// Beweist den technischen Besitz des Gutscheins.
    /// Signiert: Hash(t_id).
    pub sender_proof_signature: String,

    // --- SOZIALER LAYER (Layer 1 - Abhängig vom Privacy Mode) ---

    /// Die öffentliche Identität des Senders (z.B. "did:key:z6Mk...").
    /// - public: ZWINGEND
    /// - stealth: LEER (None)
    /// - flexible: OPTIONAL
    pub sender_id: Option<String>,

    /// Die Signatur ausgeführt durch den Identity-Key (sender_id).
    /// Beweist, dass der Sender 'sozial' zu dieser technischen Transaktion steht.
    /// Signiert: Hash(t_id).
    /// Muss vorhanden sein, wenn sender_id gesetzt ist.
    pub sender_identity_signature: Option<String>,

    /// Signatur des Layer-2 Ankers.
    /// WICHTIG: Der Inhalt (Payload) dieser Signatur hängt vom Transaktionstyp ab!
    ///
    /// 1. Typ 'init': 
    /// Signiert: Hash(pre_l2_tid + valid_until + sender_ephemeral_pub)
    ///    Signierer: Der Private Key von sender_ephemeral_pub (Genesis).
    ///    Zweck: Bindet das Ablaufdatum kryptographisch an den Genesis-Key.
    ///
    /// 2. Typ 'transfer' / 'split': 
    ///    Signiert: Hash(pre_l2_tid + sender_ephemeral_pub + receiver_ephemeral_pub_hash + [sender_change_anchor_hash])
    ///    Signierer: Der Private Key von sender_ephemeral_pub (der gerade enthüllte Key).
    ///    Zweck: "Staffelstab-Übergabe". Bestätigt, dass der Besitzer des aktuellen Keys
    ///    die neuen Hashes (Anker) autorisiert hat.
    pub layer2_signature: Option<String>,

    /// An wen geht das Geld (Layer 1)?
    /// - public: Muss ein `did:key` sein.
    /// - stealth: Darf KEIN `did:key` sein (z.B. leer oder Hash).
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

### 3.4 Validierungslogik

Der Validator prüft Transaktionen basierend auf dem `privacy_mode` des Standards.

#### 3.4.1 Basispfrüfung (Immer)
- **Hash-Integrität:** Prüfe ob `t_id` korrekt aus dem Inhalt gehasht wurde.
- **Layer 2 Beweis:** Verifiziere `sender_proof_signature` gegen den bekannten ephemeral Public Key (aus `prev_hash` bzw. Vorläufer-Transaktion).

#### 3.4.2 Modus-Spezifische Prüfung

**Modus: "public"**
- **Prüfung A:** Ist `sender_id` vorhanden? Falls `None` → **FEHLER**.
- **Prüfung B:** Ist `sender_id` ein gültiger `did:key`? Falls Nein → **FEHLER**.
- **Prüfung C:** Verifiziere `sender_identity_signature` mit `sender_id` gegen `t_id`. Falls ungültig → **FEHLER**.

**Modus: "stealth"**
- **Prüfung A:** Ist `sender_id` vorhanden? Falls `Some(...)` → **FEHLER**.
- **Prüfung B:** Enthält `recipient_id` einen `did:key`? Falls Ja → **FEHLER** (Empfänger muss geschützt werden).

**Modus: "flexible"**
- **Fall A (Sender will transparent sein):**
    - Wenn `sender_id` gesetzt ist: Muss `sender_identity_signature` gültig sein.
- **Fall B (Sender will anonym bleiben):**
    - Wenn `sender_id` leer ist: Nur `sender_proof_signature` (Layer 2) ist notwendig.
- **Empfänger-Wahl:** Das Feld `recipient_id` darf einen `did:key` enthalten (öffentlich addressiert) oder anonym bleiben. Die technische Sicherheit ist durch `receiver_ephemeral_pub_hash` in beiden Fällen gegeben.

### 3.5 Anwendung in der Praxis (User Story "Flexible")

Alice (Sender) hat einen Gutschein. Sie will an Bob (Empfänger) senden.
Der Standard ist "flexible".

**Szenario:** Alice möchte transparent senden (z.B. Projektabrechnung), Bob gibt ihr einfach seine DID.
1. Alice setzt ihre `sender_id` auf ihren `did:key`.
2. Alice signiert mit ihrem Identity Key (`sender_identity_signature`).
3. Alice trägt Bobs DID in `recipient_id` ein (damit jeder sieht: "Ging an Bob").
4. **Technischer Hintergrund:** Alice berechnet trotzdem lokal einen Stealth Key aus Bobs DID und schreibt dessen Hash in `receiver_ephemeral_pub_hash`.

**Ergebnis:**
- **Layer 1 (Sozial):** Jeder sieht "Alice -> Bob".
- **Layer 2 (Technik):** Das Netzwerk sieht einen kryptographischen Anker (`receiver_ephemeral_pub_hash`), der das Double-Spending verhindert.

Bob kann den Gutschein später weiterverwenden, indem er den Stealth-Key (Private Key) ableitet. Ob er sich dabei dann selbst als "Bob" im `sender_id` Feld offenbart, ist seine Entscheidung (da Modus "Flexible").

### 3.6 Definition in standard.toml

```toml
[privacy]
# Optionen: "public", "stealth", "flexible"
mode = "flexible"
```

## 4. Architektur: Die P2PKH-Verkettung (Layer 2 Details)

Die Sicherheit der Transaktionskette basiert nicht mehr auf der direkten Nennung des Nachfolgers, sondern auf einem **Commitment-Reveal-Schema**. Dies ist die Basis für die Layer-2-Sicherheit und Quantenresistenz.

### 4.1 Das Konzept

Wir speichern pro Transaktionsschritt nur das absolute Minimum, um die Kette zu validieren:

- **Der Anker (The Lock):** Ein Hash eines Public Keys. Er repräsentiert das "Schloss" für die Zukunft. Nur wer den passenden Schlüssel besitzt, kann weitermachen.
    
- **Der Beweis (The Reveal):** Der Klartext-Public-Key, der zum Hash der _vorherigen_ Transaktion passt. Er beweist, dass der aktuelle Sender berechtigt ist, den alten Zustand aufzulösen.
    

### 4.2 Visuelle Darstellung der Kette

```
Transaktion 1 (Init)       Transaktion 2 (Transfer)       Transaktion 3 ...
+----------------------+   +-----------------------+      +------------------
| t_type: init         |   | t_type: transfer      |      |
|                      |   |                       |      |
| sender_pub: KEY_A    |   | sender_pub: KEY_B <-------+ (Reveal KEY_B)
| (Genesis Key)        |   | (KEY_B enthüllt)      |   | |
|                      |   |                       |   | | Hash(KEY_B) muss
| receiver_hash: HASH_B+---> Prüfe: Hash(KEY_B) == HASH_B| übereinstimmen!
| (Anker für Zukunft)  |   |                       |     |
|                      |   | receiver_hash: HASH_C +-----> ...
+----------------------+   +-----------------------+
```

### 5. Datenstrukturen & Formate

Das System nutzt etablierte kryptographische Standards: **Ed25519** für Signaturen, **SHA3-256** für Hashing, **ChaCha20-Poly1305** für Verschlüsselung und **HKDF-SHA256** zur deterministischen Schlüsselableitung und Side-Channel-Resistenz.

### 5.1 Format der Bezeichner (Composite Identifier)

Um Domain Separation und menschliche Lesbarkeit zu vereinen, folgen alle Identitäten im System einem festen Muster:

`[PRÄFIX]:[CHECKSUMME]@[DID-KEY]`

- **Präfix:** Der logische Kontext oder Sub-Account (z. B. `pc-wallet`, `mobile`, `trading`). Es dient dazu, verschiedene Verwendungszwecke unter einer einzigen Identität zu trennen.
    
- **Checksumme:** Eine kurze alphanumerische Zeichenfolge zur Validierung des Präfixes.
    
- **DID-Key:** Die vollständige dezentrale Identität (z. B. `did:key:z6Mk...`).
    

**Beispiel:**

`creator:fY7@did:key:z6MkfoBD8yWs1ECX31fEZk8EGbVjJQckRUCLrUMP6ctc5Fn`

### 5.2 Die mathematische Falle (TrapData)

Enthält die öffentlichen Komponenten des **Schnorr Non-Interactive Zero-Knowledge Proofs (NIZK)**.

Der Proof beweist die Kenntnis von $m$ für die Relation $V - ID = m \cdot U$, ohne $m$ zu enthüllen. Als Hash-Funktion für die Challenge-Berechnung wird **SHA3-256** verwendet.

```rust
#[derive(Serialize, Deserialize)]
struct TrapData {
    /// Challenge Index -> Feldname: ds_tag
    /// Deterministischer Hash der INPUT-Daten (prev_hash, input_key, etc.).
    /// Er MUSS konstant sein für alle Transaktionen, die denselben Input verwenden.
    /// Dient der O(1) Erkennung von Double Spends.
    ds_tag: String,

    /// Variierender Challenge-Scalar (u) -> Feldname: u
    /// Deterministischer Hash der OUTPUT-Daten (amount, receiver, etc.) auf einen Skalar.
    /// u = HashToScalar(ds_tag + amount + receiver...)
    /// Dieser Wert unterscheidet sich bei Double Spends mathematisch und ermöglicht die Identifikations-Wiederherstellung.
    u: String,
    
    /// Response (V = u * m + ID) -> Feldname: blinded_id
    /// Wobei 'm' hier als Projektions-Punkt (M = slope * G) interpretiert werden kann, 
    /// sodass V = u * M + ID.
    blinded_id: String,
    
    /// Der kryptographische Beweis (Schnorr-Signatur).
    /// Beweist: "Ich kenne m, sodass V = u*m + ID".
    /// Format: Serialisiertes Tupel (Commitment R, Response s)
    proof: String, 
}
```

### 5.3 Der verschlüsselte Payload (RecipientPayload)

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

#### 5.3.1 Schlüsselableitung (HKDF)
Für die symmetrische Verschlüsselung des Payloads wird der Shared Secret aus dem X25519-Austausch mittels HKDF-SHA256 expandiert.

**Info-String Format:**
`"human-money-core/x25519-exchange" + sort(public_key_1, public_key_2)`

Wobei `public_key_1` und `public_key_2` die 32-Byte X25519 Public Keys (ephemeral und statisch) in lexikographischer Sortierung sind. Dies stellt sicher, dass beide Parteien denselben Info-String unabhängig von ihrer Rolle berechnen.

## 6. Protokoll-Ablauf & Algorithmen

Der Ablauf unterscheidet sich fundamental zwischen der Erzeugung (Init) und der Weitergabe (Transfer).

### 6.1 Initialisierung (Die Anker-Erzeugung)

Der Ersteller erzeugt den Gutschein. Hier muss das **Ablaufdatum** kryptographisch gesichert werden, damit Layer-2-Server alte Daten sicher löschen können.

1. **Genesis Key:** Einmaliger Key für den Sender (`sender_ephemeral_pub`).
    
2. **Holder Key:** Erster Empfänger-Key. Dessen Hash kommt in `receiver_ephemeral_pub_hash`.
    
3. **L2 Signatur (Payload):**
    
    `Hash(pre_l2_tid + valid_until + sender_ephemeral_pub)`
    
    _Dies garantiert: Dieser Gutschein ist gültig bis Datum X und startet mit Key Y._
    

### 6.2 Transfer & Split (Die Staffelstab-Übergabe)

Alice (`minuto:bth@did:alice`) sendet Guthaben an Bob.

1. **HKDF Ableitung (Side-Channel Protection):**
    
    Alice leitet $m$ kryptographisch sauber ab, um Leakage des Private Keys zu verhindern.
    
    - `prk = HKDF-Extract(salt=prev_hash, ikm=AlicePrivateKey)`
        
    - `m = HKDF-Expand(prk, info=context_prefix + "|" + label, len=32)`
      (Label ist z.B. "genesis" oder "holder". Das `context_prefix` stellt sicher, dass derselbe Seed in unterschiedlichen ökonomischen Kontexten zu unterschiedlichen Schlüsseln führt).

    - **Neu: Change-Key Seed:**
      Falls Wechselgeld entsteht (Split), wird der Seed für den neuen Schlüssel ebenfalls deterministisch abgeleitet, um Statelessness zu garantieren:
      `change_seed = HKDF-Expand(prk, info=context_prefix + "|change_seed", len=32)`
        
2. **ZKP Challenge (Fiat-Shamir & Schnorr Proof):**
    
    Damit Alice $U$ nicht manipulieren kann, wird er deterministisch abgeleitet.
    
    - **Basis-Punkt:** $U = Hash(prev\_hash + sender\_ephemeral\_pub + receiver\_ephemeral\_pub\_hash + amount + prefix)$  
        
    - **Ziel-Punkt:** $V = m \cdot U + AliceID$  
        
    - **Beweis-Erstellung (Prover):**
        
        - Alice wählt zufälligen Nonce $r$.
            
        - Berechnet Commitment $R = r \cdot U$.
            
        - Berechnet Challenge $c = Hash(U, V, R, prefix)$.
            
        - Berechnet Response $s = r + c \cdot m$.
            
        - `proof` = Serialisierung von $(R, s)$.
            
3. **Verifizierung durch Empfänger (Inbound Check):**
    
    Bevor Bob die Transaktion akzeptiert, **MUSS** er den Proof prüfen. Ohne Prüfung wäre `trap_data` nutzlos.
    
    - Berechne $U$ und lese $V$.
        
    - Parse $(R, s)$ aus `proof`.
        
    - Berechne Challenge $c = Hash(U, V, R, prefix)$ mittels **SHA3-256**.
        
    - Prüfe: $s \cdot U \stackrel{?}{=} R + c \cdot (V - AliceID)$.
        
    - Wenn ungültig: Ablehnung (Gefahr von gefälschtem Double-Spend-Schutz).
        
4. **Forking (Anker setzen):**
    
    - **Bob:** Hash seines neuen Keys -> `receiver_ephemeral_pub_hash`.
        
    - **Alice (Rest):** Hash ihres neuen Keys -> `sender_change_anchor_hash`.
        
5. **L2 Signatur (Payload):**
    
    `Hash(pre_l2_tid + sender_ephemeral_pub + receiver_ephemeral_pub_hash + [sender_change_anchor_hash])`
    
    _Dies garantiert: Ich, Alice, autorisiere exakt diese zwei neuen Hashes als rechtmäßige Nachfolger. Der Server prüft nur diese Autorisierung._
    
6. **Finalisierung:** Signatur der gesamten Tx und Anhängen an die Datei.
    

## 7. Fingerprints & Double-Spend Erkennung

### 7.1 Der Double-Spend-Tag (DS-Tag)

Der **Double-Spend-Tag** (symbolisch **$u$**) ist die kryptographische Garantie, dass ein spezifischer Input nur ein einziges Mal ausgegeben werden kann.

**Kritische Sicherheits-Regel:**
Der DS-Tag darf **ausschließlich** von den **Input-Daten** abhängen (Was gebe ich aus?), niemals von den **Output-Daten** (Wieviel sende ich an wen?).
*Würde der Betrag in den Tag einfließen, könnte ein Angreifer denselben Input zweimal mit unterschiedlichen Beträgen ausgeben, ohne dass die Tags kollidieren.*

**Die korrekte Berechnung:**
Der Tag identifiziert eindeutig den *Verbrauch* eines spezifischen Ankers. Er ist unabhängig von der gewählten Identität (Präfix), da die mathematische Bindung bereits auf Layer 2 durch den ephemeren Schlüssel erfolgt.

$$u = Hash(prev\_hash + sender\_ephemeral\_pub) \text{ (mittels SHA3-256)}$$

Die Komponenten sind:
1.  `prev_hash`: Die ID der Quelle (Vorgänger-Gutschein).
2.  `sender_ephemeral_pub`: Der **Input-Key** (der "Schlüssel zum Schloss"), der in diesem Moment enthüllt wird.

**Warum kein Präfix im Tag? (Entwicklungs-Historie)**
In früheren Versionen des Protokolls (ohne ephemere Schlüssel) war die Einbindung des Präfixes in den DS-Tag notwendig, um verschiedene "Unterkonten" desselben `did:key` zu unterscheiden. Da der `prev_hash` beim Splitten identisch blieb, hätten zwei legale Zahlungen von unterschiedlichen Unterkonten (z.B. Alice:PC und Alice:Mobil) sonst denselben Tag erzeugt (False Positive).

Mit dem **Privacy Mode** und **ephemeren Schlüsseln** ist dies hinfällig: Jeder Unteraccount (`context_prefix`) leitet bereits einen *eindeutigen* `sender_ephemeral_pub` für seine Transaktion ab. Da diese Keys bereits global eindeutig sind, ist das Präfix im `ds_tag` redundant. Das Entfernen schließt zudem die Sicherheitslücke des "Identity Hopping", bei der ein Angreifer versuchen könnte, denselben ephemeren Key mit verschiedenen Präfixes mehrfach auszugeben.

**Lösung für Split-Transaktionen (Gabelung):**
Wie unterscheidet das System beim Split zwischen "Transfer" und "Restgeld", wenn beide denselben `prev_hash` haben?

Durch den **Input-Key (`sender_ephemeral_pub`)**!
Die vorherige Split-Transaktion hat zwei unterschiedliche Anker (Schlösser) hinterlegt:
1.  Einen Anker für den Empfänger.
2.  Einen separaten Anker für das Restgeld (Change).

*   **Transfer-Zweig:** Der Empfänger öffnet SEINEN Anker (mit seinem Key $Key_{Receiver}$).
    $\rightarrow u_{Transfer} = Hash(prev\_hash + Key_{Receiver})$
*   **Restgeld-Zweig:** Der Sender öffnet den CHANGE-Anker (mit dem Change-Key $Key_{Change}$).
    $\rightarrow u_{Change} = Hash(prev\_hash + Key_{Change})$

Da $Key_{Receiver}$ und $Key_{Change}$ kryptographisch verschieden sind (unterschiedliche Seeds), sind auch die resultierenden DS-Tags global eindeutig.

**Definition Double-Spend:**
Ein Double-Spend liegt vor, wenn **derselbe Double-Spend-Tag ($u$) zweimal** im Netzwerk registriert wird.
Dies beweist, dass derselbe Input-Key für dieselbe Quelle mehrfach verwendet wurde.
    

### 7.2 Die Fingerprint-Struktur (Die Falle)

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionFingerprint {
    /// Der Double-Spend-Tag (entspricht mathematisch U)
    pub ds_tag: String,
    
    /// Die Transaktions-ID
    pub t_id: String,
    
    /// Verschlüsselter Zeitstempel
    pub encrypted_timestamp: u128,

    // ... weitere Felder wie signature, valid_until
}
```

## 8. Zusammenfassung und Sicherheits-Nuancen

|   |   |   |
|---|---|---|
|**Eigenschaft**|**Garantie**|**Mechanismus**|
|**Privatsphäre**|**Perfect Hiding**|Angreifer können IDs nicht erraten, da $m$ via HKDF geschützt ist.|
|**Sicherheit**|**Unbreakable**|Trap kann nicht umgangen werden, da ZKP deterministisches $m$ erzwingt.|
|**Ordnung**|**Prefix Scoping**|Bezeichner wie `creator:fY7@did...` erzwingen strikte Kontext-Trennung.|

### 8.1 Hinweis zur Quantensicherheit

Das System bietet eine **hybride Sicherheit**:

1. **Layer 2 (Post-Quantum):** Die Anker (`receiver_ephemeral_pub_hash`) basieren auf kryptographischen Hashes (**SHA3-256**). Ein Quantencomputer kann das Preimage nicht berechnen. Ruhende Guthaben (Cold Storage) sind daher sicher, solange der Key nicht enthüllt wurde.
    
2. **Layer 1 (Pre-Quantum):** Die Identitäten (`did:key`) und Signaturen basieren auf Ed25519 (Elliptische Kurven). Ein hinreichend mächtiger Quantencomputer könnte theoretisch den Private Key aus einem Public Key errechnen.
    
    - **Risiko-Einordnung:** Das Brechen von Ed25519 erfordert staatliche Ressourcen. Für lokale Netzwerke und private Kreise bleibt das Verfahren sicher.
        
    - **Schutz:** Selbst wenn eine Identität gebrochen wird, kann der Angreifer Guthaben **nicht** stehlen, solange er nicht den _aktuellen_ Layer-2-Anker (den Hash-Preimage) kennt.
        

## 9. Implementierungshinweise

- **HKDF:** Verwende `HKDF-SHA256` für alle Schlüsselableitungen.
    
- **Proof:** Implementiere das Schnorr-Protokoll strikt nach Definition, um Interoperabilität zu gewährleisten.
    
- **Neu:** Beachte die Privacy-Regeln aus Section 3!