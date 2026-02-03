---
creation date: 2026-02-01 10:28
modification date: Sonntag 1. Februar 2026 10:28:06
tags:
  - human-money-core
vc-id: 3b29e076-55bb-4fde-93ea-5bac0b28cd8a
---
# Spezifikation: Hybride Privatsphäre, Offline-Sicherheit & Quantensichere Anker

**Version:** 4.4 (Restored Critical Details)

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
    
    $$m = HKDF(SenderPrivateKey, prev\_hash, prefix)$$
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
    

## 3. Architektur: Die P2PKH-Verkettung (Pay-to-Public-Key-Hash)

Die Sicherheit der Transaktionskette basiert nicht mehr auf der direkten Nennung des Nachfolgers, sondern auf einem **Commitment-Reveal-Schema**. Dies ist die Basis für die Layer-2-Sicherheit und Quantenresistenz.

### 3.1 Das Konzept

Wir speichern pro Transaktionsschritt nur das absolute Minimum, um die Kette zu validieren:

- **Der Anker (The Lock):** Ein Hash eines Public Keys. Er repräsentiert das "Schloss" für die Zukunft. Nur wer den passenden Schlüssel besitzt, kann weitermachen.
    
- **Der Beweis (The Reveal):** Der Klartext-Public-Key, der zum Hash der _vorherigen_ Transaktion passt. Er beweist, dass der aktuelle Sender berechtigt ist, den alten Zustand aufzulösen.
    

### 3.2 Visuelle Darstellung der Kette

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

## 4. Datenstrukturen & Formate

Das System nutzt etablierte kryptographische Standards: **Ed25519** für Signaturen, **BLAKE3** für Hashing, **XChaCha20-Poly1305** für Verschlüsselung und **HKDF-SHA256** zur deterministischen Schlüsselableitung und Side-Channel-Resistenz.

### 4.1 Format der Bezeichner (Composite Identifier)

Um Domain Separation und menschliche Lesbarkeit zu vereinen, folgen alle Identitäten im System einem festen Muster:

`[PRÄFIX]:[CHECKSUMME]@[DID-KEY]`

- **Präfix:** Der logische Kontext oder Sub-Account (z. B. `pc-wallet`, `mobile`, `trading`). Es dient dazu, verschiedene Verwendungszwecke unter einer einzigen Identität zu trennen.
    
- **Checksumme:** Eine kurze alphanumerische Zeichenfolge zur Validierung des Präfixes.
    
- **DID-Key:** Die vollständige dezentrale Identität (z. B. `did:key:z6Mk...`).
    

**Beispiel:**

`creator:fY7@did:key:z6MkfoBD8yWs1ECX31fEZk8EGbVjJQckRUCLrUMP6ctc5Fn`

### 4.2 Hauptstruktur Transaction (JSON/Rust)

Diese Struktur spiegelt die Implementierung wider und trennt die mathematische Falle (`trap_data`) vom verschlüsselten Payload (`privacy_guard`).

```
struct Transaction {
    /// Eindeutiger Identifier der Transaktion (Hash)
    t_id: String,
    
    /// Typ: "standard", "split", "issue"
    t_type: String,
    
    /// Hash der vorherigen Transaktion (Verkettung)
    prev_hash: String,
    
    /// Im Privacy Mode ist dies NULL.
    sender_did: Option<String>, 
    
    /// Der übertragene Betrag
    amount: Decimal,
    
    /// Restbetrag für den Sender (nur bei Split)
    sender_remaining_amount: Option<Decimal>,

    // --- Layer 2 & Privacy Fields ---

    /// Der Stealth-Key (Klartext) für den Empfänger, falls öffentlich (selten),
    /// oder der Proof-Key des Senders, um die vorherige Tx aufzulösen.
    /// Bei Typ 'init': Der neue Genesis-Key.
    /// Bei Typ 'transfer'/'split': Der enthüllte Key der vorherigen Transaktion (Input-Key).
    sender_ephemeral_pub: Option<String>,

    /// Der Anker für die NÄCHSTE Transaktion (Hash des Empfänger-Keys).
    /// P2PKH: Wir speichern nur den Hash, um Quantensicherheit zu gewährleisten.
    receiver_ephemeral_pub_hash: Option<String>,

    /// Der Anker für das RESTGELD (Hash des Sender-Keys für den Restbetrag).
    /// Nur bei "split" Transaktionen gesetzt. Ermöglicht dem Sender, den Restbetrag
    /// anonym weiterzuverwenden (Gabelung der Kette).
    sender_change_anchor_hash: Option<String>,

    /// Verschlüsselter Container (RecipientPayload).
    /// Enthält Ziel-Präfix, Memo und den ephemeren Key für den Empfänger.
    privacy_guard: Option<String>,

    /// Die mathematische Falle für Double-Spend Erkennung (ZKP).
    trap_data: Option<TrapData>,
    
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
    layer2_signature: Option<String>,

    /// Gültigkeitsdatum (ISO 8601).
    /// Nur in der 'init'-Transaktion zwingend für die Layer-2 Signatur erforderlich.
    /// Dient der Garbage Collection auf dem Server.
    valid_until: Option<String>,

    /// Signiert den Hash der Tx
    signature: Signature,
}
```

### 4.3 Die mathematische Falle (TrapData)

Enthält die öffentlichen Komponenten des **Schnorr Non-Interactive Zero-Knowledge Proofs (NIZK)**.

Der Proof beweist die Kenntnis von $m$ für die Relation $V - ID = m \cdot U$, ohne $m$ zu enthüllen.

```
#[derive(Serialize, Deserialize)]
struct TrapData {
    /// Challenge U (Fiat-Shamir).
    /// Deterministischer Hash der öffentlichen Transaktionsdaten auf einen Kurvenpunkt (Hash-to-Curve).
    /// u = HashToCurve(prev_hash + sender_ephemeral_pub + receiver_ephemeral_pub_hash + amount + prefix)
    /// Verfahren: SHA-512 Hash -> Elligator2 oder deterministisches Mapping auf validen Ed25519 Punkt.
    /// Damit wird garantiert, dass alle Clients denselben Punkt U berechnen.
    u: String,
    
    /// Response (V = m*U + ID)
    v: String,
    
    /// Der kryptographische Beweis (Schnorr-Signatur über U).
    /// Beweist: "Ich kenne m, sodass V = m*U + ID".
    /// Format: Serialisiertes Tupel (Commitment R, Response s)
    proof: String, 
}
```

### 4.4 Der verschlüsselte Payload (RecipientPayload)

Dies ist der entschlüsselte Inhalt von `privacy_guard`.

```
#[derive(Serialize, Deserialize)]
struct RecipientPayload {
    /// Die vollständige Composite-DID des Absenders
    /// Beispiel: "minuto:a1b@did:key:zAlice..."
    /// Ermöglicht dem Empfänger, den Sender im Adressbuch anzuzeigen.
    pub sender_permanent_did: String, 

    /// Präfix-Validierung: Das Ziel-Unterkonto inklusive Checksumme.
    /// Beispiel: "creator:fY7"
    pub target_prefix: String,

    /// Optionale Nachricht / Verwendungszweck
    pub memo: Option<String>,

    /// Zeitstempel der Erstellung (u64)
    pub timestamp: u64, 
}
```

## 5. Protokoll-Ablauf & Algorithmen

Der Ablauf unterscheidet sich fundamental zwischen der Erzeugung (Init) und der Weitergabe (Transfer).

### 5.1 Initialisierung (Die Anker-Erzeugung)

Der Ersteller erzeugt den Gutschein. Hier muss das **Ablaufdatum** kryptographisch gesichert werden, damit Layer-2-Server alte Daten sicher löschen können.

1. **Genesis Key:** Einmaliger Key für den Sender (`sender_ephemeral_pub`).
    
2. **Holder Key:** Erster Empfänger-Key. Dessen Hash kommt in `receiver_ephemeral_pub_hash`.
    
3. **L2 Signatur (Payload):**
    
    `Hash(pre_l2_tid + valid_until + sender_ephemeral_pub)`
    
    _Dies garantiert: Dieser Gutschein ist gültig bis Datum X und startet mit Key Y._
    

### 5.2 Transfer & Split (Die Staffelstab-Übergabe)

Alice (`minuto:bth@did:alice`) sendet Guthaben an Bob.

1. **HKDF Ableitung (Side-Channel Protection):**
    
    Alice leitet $m$ kryptographisch sauber ab, um Leakage des Private Keys zu verhindern.
    
    - `prk = HKDF-Extract(salt=prev_hash, ikm=AlicePrivateKey)`
        
    - `m = HKDF-Expand(prk, info=prefix, len=32)`
      (Info ist der Präfix-String z.B. "minuto:bth")

    - **Neu: Change-Key Seed:**
      Falls Wechselgeld entsteht (Split), wird der Seed für den neuen Schlüssel ebenfalls deterministisch abgeleitet, um Statelessness zu garantieren:
      `change_seed = HKDF-Expand(prk, info=prefix + "change_seed", len=32)`
        
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
        
    - Berechne $c = Hash(U, V, R, prefix)$.
        
    - Prüfe: $s \cdot U \stackrel{?}{=} R + c \cdot (V - AliceID)$.
        
    - Wenn ungültig: Ablehnung (Gefahr von gefälschtem Double-Spend-Schutz).
        
4. **Forking (Anker setzen):**
    
    - **Bob:** Hash seines neuen Keys -> `receiver_ephemeral_pub_hash`.
        
    - **Alice (Rest):** Hash ihres neuen Keys -> `sender_change_anchor_hash`.
        
5. **L2 Signatur (Payload):**
    
    `Hash(pre_l2_tid + sender_ephemeral_pub + receiver_ephemeral_pub_hash + [sender_change_anchor_hash])`
    
    _Dies garantiert: Ich, Alice, autorisiere exakt diese zwei neuen Hashes als rechtmäßige Nachfolger. Der Server prüft nur diese Autorisierung._
    
6. **Finalisierung:** Signatur der gesamten Tx und Anhängen an die Datei.
    

## 6. Fingerprints & Double-Spend Erkennung

### 6.1 Der LinkingTag (Der Index)

Die Formel lautet:

$$LinkingTag = Hash(SenderPrivateKey \times Hash(prev\_hash + prefix))$$

- **Domain Separation:** Durch die Einbindung des Präfixes (z. B. `desktop:x9Z` oder `mobile:a1B`) erzeugt derselbe Private Key für unterschiedliche **Sub-Accounts (Unterkonten)** unterschiedliche Tags. Das Präfix dient hier der logischen Trennung von Kontexten (z. B. Gerätetyp, Verwendungszweck) unter derselben Identität. Ein Cross-Replay-Angriff zwischen verschiedenen Kontexten ist damit mathematisch ausgeschlossen.
    
- **Sicherheits-Differenzierung (Einweg-Schutz):** Da der `LinkingTag` öffentlich ist, muss er mathematisch strikt von $m$ getrennt sein, um Rückrechnungen auf die Identität zu verhindern.
    

### 6.2 Die Fingerprint-Struktur (Die Falle)

```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionFingerprint {
    pub tag: [u8; 32],
    
    /// Deterministischer Basis-Punkt U
    pub u: [u8; 32],
    
    /// V = m*U + ID (Enthält die Identität versteckt)
    pub v: [u8; 32],
}
```

## 7. Zusammenfassung und Sicherheits-Nuancen

|   |   |   |
|---|---|---|
|**Eigenschaft**|**Garantie**|**Mechanismus**|
|**Privatsphäre**|**Perfect Hiding**|Angreifer können IDs nicht erraten, da $m$ via HKDF geschützt ist.|
|**Sicherheit**|**Unbreakable**|Trap kann nicht umgangen werden, da ZKP deterministisches $m$ erzwingt.|
|**Ordnung**|**Prefix Scoping**|Bezeichner wie `creator:fY7@did...` erzwingen strikte Kontext-Trennung.|

### 7.1 Hinweis zur Quantensicherheit

Das System bietet eine **hybride Sicherheit**:

1. **Layer 2 (Post-Quantum):** Die Anker (`receiver_ephemeral_pub_hash`) basieren auf kryptographischen Hashes (BLAKE3). Ein Quantencomputer kann das Preimage nicht berechnen. Ruhende Guthaben (Cold Storage) sind daher sicher, solange der Key nicht enthüllt wurde.
    
2. **Layer 1 (Pre-Quantum):** Die Identitäten (`did:key`) und Signaturen basieren auf Ed25519 (Elliptische Kurven). Ein hinreichend mächtiger Quantencomputer könnte theoretisch den Private Key aus einem Public Key errechnen.
    
    - **Risiko-Einordnung:** Das Brechen von Ed25519 erfordert staatliche Ressourcen. Für lokale Netzwerke und private Kreise bleibt das Verfahren sicher.
        
    - **Schutz:** Selbst wenn eine Identität gebrochen wird, kann der Angreifer Guthaben **nicht** stehlen, solange er nicht den _aktuellen_ Layer-2-Anker (den Hash-Preimage) kennt.
        

## 8. Implementierungshinweise

- **HKDF:** Verwende `HKDF-SHA256` für alle Schlüsselableitungen.
    
- **Proof:** Implementiere das Schnorr-Protokoll strikt nach Definition, um Interoperabilität zu gewährleisten.
    

Diese Spezifikation ist bindend für die Entwicklung der Core-Bibliothek.