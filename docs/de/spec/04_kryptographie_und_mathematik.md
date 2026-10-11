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

## 2. Die mathematische Falle (TrapData - V3 SST)

In Protokoll V3 nutzt das System das **Shared-Signature Trap (SST)** Schema. Jede Spend-Transaktion trägt Shards einer gemeinsamen deterministischen Schnorr-Signatur $\sigma = (R_{sig}, s_{sig})$ über $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \parallel ds\_tag \parallel E)$ mit $E = \text{sender\_ephemeral\_pub}$.

```rust
#[derive(Serialize, Deserialize)]
pub struct TrapData {
    /// Challenge Index -> Feldname: ds_tag
    /// Deterministischer Hash der INPUT-Daten (prev_hash, input_key, etc.).
    /// Er MUSS konstant sein für alle Transaktionen, die denselben Input verwenden.
    /// Dient der O(1) Erkennung von Double Spends.
    pub ds_tag: String,

    /// Schnorr-Commitment-Shard R_i = R_sig + tau_i * M_R (Base58, Edwards-Punkt, 32 Byte)
    pub trap_r: String,
    
    /// Schnorr-Response-Shard s_i = s_sig + tau_i * m_s mod q (Base58, kanonischer Skalar, 32 Byte)
    pub trap_s: String,
}
```

### Mathematische Definition & Shard-Ableitung

1. **Spend-spezifischer Skalar:**
   $$\tau_i = H(\text{"HMC\_TAU\_V1"} \parallel ds\_tag \parallel t\_id_i) \pmod q$$
2. **Maskierungswerte (aus dem privaten Langzeitschlüssel $x$ abgeleitet):**
   $$M_R = \text{hash\_to\_curve}(\text{"HMC\_MASK\_R\_V1"} \parallel x \parallel E \parallel ds\_tag)$$
   $$m_s = H(\text{"HMC\_MASK\_S\_V1"} \parallel x \parallel E \parallel ds\_tag) \pmod q$$
3. **Shards:**
   $$R_i = R_{sig} + \tau_i \cdot M_R, \quad s_i = s_{sig} + \tau_i \cdot m_s \pmod q$$
4. **Auflösung bei Double-Spend:**
   Zwei kollidierende Spends mit demselben $ds\_tag$ haben $t\_id_1 \neq t\_id_2$ und somit $\tau_1 \neq \tau_2$:
   $$s_1 - s_2 = (\tau_1 - \tau_2) \cdot m_s \pmod q \implies m_s = \frac{s_1 - s_2}{\tau_1 - \tau_2} \pmod q$$
   $$s_{sig} = s_1 - \tau_1 \cdot m_s \pmod q$$
   Da $s_{sig} = k + e \cdot x \pmod q$ (wobei $k$ die Schnorr-Nonce und $e = H(R_{sig} \parallel E \parallel \mu)$ die Challenge ist), lässt sich der private Langzeitschlüssel $x$ des Senders direkt berechnen und seine permanente DID wird unwiderruflich offenbart.

Veraltete V2-Felder (`u`, `blinded_id`, `proof`) existieren nicht mehr und werden bei der Deserialisierung hart abgewiesen.

## 3. Fingerprints & Double-Spend Erkennung

### 3.1 Der Double-Spend-Tag (DS-Tag)

Der **Double-Spend-Tag** ist die kryptographische Garantie, dass ein spezifischer Input nur ein einziges Mal ausgegeben werden kann.

**Kritische Sicherheits-Regel:**
Der DS-Tag darf **ausschließlich** von den **Input-Daten** abhängen (Was gebe ich aus?), niemals von den **Output-Daten** (Wieviel sende ich an wen?).
*Würde der Betrag in den Tag einfließen, könnte ein Angreifer denselben Input zweimal mit unterschiedlichen Beträgen ausgeben, ohne dass die Tags kollidieren.*

**Die korrekte Berechnung:**
Der Tag identifiziert eindeutig den *Verbrauch* eines spezifischen Ankers:

$$ds\_tag = Hash(prev\_hash \parallel sender\_ephemeral\_pub) \text{ (mittels SHA3-256)}$$

Die Komponenten sind:
1.  `prev_hash`: Die ID der Quelle (Vorgänger-Gutschein).
2.  `sender_ephemeral_pub`: Der **Input-Key** (der "Schlüssel zum Schloss"), der in diesem Moment enthüllt wird.

**Warum kein Präfix im Tag? (Entwicklungs-Historie)**
In früheren Versionen des Protokolls (ohne ephemere Schlüssel) war die Einbindung des Präfixes in den DS-Tag notwendig, um verschiedene "Unterkonten" desselben `did:key` zu unterscheiden. Da der `prev_hash` beim Splitten identisch blieb, hätten zwei legale Zahlungen von unterschiedlichen Unterkonten sonst denselben Tag erzeugt (False Positive).

Mit dem **Privacy Mode** und **ephemeren Schlüsseln** ist dies hinfällig: Jeder Unteraccount (`context_prefix`) leitet bereits einen *eindeutigen* `sender_ephemeral_pub` für seine Transaktion ab. Da diese Keys bereits global eindeutig sind, ist das Präfix im `ds_tag` redundant.

**Lösung für Split-Transaktionen (Gabelung):**
Wie unterscheidet das System beim Split zwischen "Transfer" und "Restgeld", wenn beide denselben `prev_hash` haben?

Durch den **Input-Key (`sender_ephemeral_pub`)**!
Die vorherige Split-Transaktion hat zwei unterschiedliche Anker (Schlösser) hinterlegt:
1.  Einen Anker für den Empfänger.
2.  Einen separaten Anker für das Restgeld (Change).

*   **Transfer-Zweig:** Der Empfänger öffnet SEINEN Anker (mit seinem Key $Key_{Receiver}$).
    $\rightarrow ds\_tag_{Transfer} = Hash(prev\_hash \parallel Key_{Receiver})$
*   **Restgeld-Zweig:** Der Sender öffnet den CHANGE-Anker (mit dem Change-Key $Key_{Change}$).
    $\rightarrow ds\_tag_{Change} = Hash(prev\_hash \parallel Key_{Change})$

Da $Key_{Receiver}$ und $Key_{Change}$ kryptographisch verschieden sind (unterschiedliche Seeds), sind auch die resultierenden DS-Tags global eindeutig.

**Definition Double-Spend:**
Ein Double-Spend liegt vor, wenn **derselbe Double-Spend-Tag (`ds_tag`) zweimal** im Netzwerk registriert wird.
Dies beweist, dass derselbe Input-Key für dieselbe Quelle mehrfach verwendet wurde.
    
### 3.2 Die Fingerprint-Struktur (V3 Selbstauthentifizierender Instant-Proof)

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionFingerprint {
    pub ds_tag: String,               // Base58, 32 Byte
    pub t_id: String,                 // Base58, 32 Byte
    pub encrypted_timestamp: u128,    // original_nanos ^ hash(prev_hash || t_id)
    pub layer2_signature: String,     // Base58, 64 Byte, Ed25519 über HMC_TX_AUTH_V3
    pub sender_ephemeral_pub: String, // Base58, 32 Byte
    pub deletable_at: String,         // RFC3339; Wire: "" (neutralisiert), lokal: now+180 Tage
    pub trap_r: String,               // Base58 Shard R_i ("none" für Genesis)
    pub trap_s: String,               // Base58 Shard s_i ("none" für Genesis)
    pub layer2_voucher_id: String,    // Hex für Spends, "none" für Genesis
    pub privacy_guard_hash: String,   // Base58 SHA3-256 des Guards oder ""
}
```

Die eingebettete `layer2_signature` wird unter der Domain **`HMC_TX_AUTH_V3`** gegen den kanonischen längenpräfixierten Digest validiert:
`HMC_TX_AUTH_V3 || layer2_voucher_id || challenge_ds_tag || t_id || sender_ephemeral_pub || trap_r || trap_s || encrypted_timestamp || deletable_at || privacy_guard_hash`.
Damit sind Gossip-Fingerprints autonom und ohne Anforderung vollständiger Gutscheinketten im P2P-Netzwerk verifizierbar.
