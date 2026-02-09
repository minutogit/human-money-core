---
creation date: 2026-02-01 10:28
modification date: 2026-02-10
tags:
  - human-money-core
  - cryptography
  - math
---
# 04. Kryptographie & Mathematik

**Kontext:** Teil 4 der Human Money Core Spezifikation.

## 1. Verwendete Algorithmen

Das System nutzt etablierte kryptographische Standards: **Ed25519** für Signaturen, **SHA3-256** für Hashing, **ChaCha20-Poly1305** für Verschlüsselung und **HKDF-SHA256** zur deterministischen Schlüsselableitung und Side-Channel-Resistenz.

## 2. Die mathematische Falle (TrapData)

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

## 3. Fingerprints & Double-Spend Erkennung

### 3.1 Der Double-Spend-Tag (DS-Tag)

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
    
### 3.2 Die Fingerprint-Struktur (Die Falle)

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
