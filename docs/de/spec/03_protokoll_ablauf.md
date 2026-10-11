---
creation date: 2026-02-01 10:28
modification date: 2026-02-10
tags:
  - human-money-core
  - protocol
  - flow
---
# 03. Protokoll-Ablauf & Verkettung

**Kontext:** Teil 3 der Human Money Core Spezifikation.

## 1. Architektur: Die P2PKH-Verkettung (Layer 2 Details)

Die Sicherheit der Transaktionskette basiert nicht mehr auf der direkten Nennung des Nachfolgers, sondern auf einem **Commitment-Reveal-Schema**. Dies ist die Basis für die Layer-2-Sicherheit und Quantenresistenz.

### 1.1 Das Konzept

Wir speichern pro Transaktionsschritt nur das absolute Minimum, um die Kette zu validieren:

- **Der Anker (The Lock):** Ein Hash eines Public Keys. Er repräsentiert das "Schloss" für die Zukunft. Nur wer den passenden Schlüssel besitzt, kann weitermachen.
    
- **Der Beweis (The Reveal):** Der Klartext-Public-Key, der zum Hash der _vorherigen_ Transaktion passt. Er beweist, dass der aktuelle Sender berechtigt ist, den alten Zustand aufzulösen.
    

### 1.2 Visuelle Darstellung der Kette

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

## 2. Protokoll-Ablauf & Algorithmen

Der Ablauf unterscheidet sich fundamental zwischen der Erzeugung (Init) und der Weitergabe (Transfer).

### 2.1 Initialisierung (Die Anker-Erzeugung)

Der Ersteller erzeugt den Gutschein. Hier muss das **Ablaufdatum** kryptographisch gesichert werden, damit Layer-2-Server alte Daten sicher löschen können.

1. **Genesis Key:** Einmaliger Key für den Sender (`sender_ephemeral_pub`).
    
2. **Holder Key:** Erster Empfänger-Key. Dessen Hash kommt in `receiver_ephemeral_pub_hash`.
    
3. **L2 Signatur (Payload):**
    
    `Hash(pre_l2_tid + valid_until + sender_ephemeral_pub)`
    
    _Dies garantiert: Dieser Gutschein ist gültig bis Datum X und startet mit Key Y._
    

### 2.2 Transfer & Split (Die Staffelstab-Übergabe)

Alice (`minuto:bth@did:alice`) sendet Guthaben an Bob.

1. **HKDF Ableitung (Side-Channel Protection):**
    
    Alice leitet $m$ kryptographisch sauber ab, um Leakage des Private Keys zu verhindern.
    
    - `prk = HKDF-Extract(salt=prev_hash, ikm=AlicePrivateKey)`
        
    - `m = HKDF-Expand(prk, info=context_prefix + "|" + label, len=32)`
      (Label ist z.B. "genesis" oder "holder". Das `context_prefix` stellt sicher, dass derselbe Seed in unterschiedlichen ökonomischen Kontexten zu unterschiedlichen Schlüsseln führt).

    - **Neu: Change-Key Seed:**
      Falls Wechselgeld entsteht (Split), wird der Seed für den neuen Schlüssel ebenfalls deterministisch abgeleitet, um Statelessness zu garantieren:
      `change_seed = HKDF-Expand(prk, info=context_prefix + "|change_seed", len=32)`
        
2. **V3 SST Shard-Erstellung (Shared-Signature Trap):**
    
    Damit die Double-Spend-Falle deterministisch und unmanipulierbar greift:
    
    - **Spend-Skalar:** $\tau_i = H(\text{"HMC\_TAU\_V1"} \parallel ds\_tag \parallel t\_id_i) \pmod q$  
    - **Maskierung:** $M_R = \text{hash\_to\_curve}(\text{"HMC\_MASK\_R\_V1"} \parallel x \parallel E \parallel ds\_tag)$, $m_s = H(\text{"HMC\_MASK\_S\_V1"} \parallel x \parallel E \parallel ds\_tag)$  
    - **Gemeinsame Schnorr-Signatur:** $\sigma = (R_{sig}, s_{sig})$ über $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \parallel ds\_tag \parallel E)$  
    - **Shards:**  
      $R_i = R_{sig} + \tau_i \cdot M_R$  
      $s_i = s_{sig} + \tau_i \cdot m_s \pmod q$  
    - **Privater Zeuge:** $W = (R_{sig}, s_{sig}, M_R, m_s)$ wird im `privacy_guard` verschlüsselt an Bob übergeben.
        
3. **Verifizierung durch Empfänger (Inbound Check - R5 Fail-Closed):**
    
    Bevor Bob die Transaktion akzeptiert, **MUSS** er die SST-Integrität prüfen:
    
    - Entschlüssele `privacy_guard` und extrahiere den Zeugen $W = (R_{sig}, s_{sig}, M_R, m_s)$.
    - Berechne $\tau_i$ aus $ds\_tag$ und $t\_id$.
    - Prüfe: $R_i \stackrel{?}{=} R_{sig} + \tau_i \cdot M_R$ und $s_i \stackrel{?}{=} s_{sig} + \tau_i \cdot m_s \pmod q$.
    - Verifiziere die Schnorr-Signatur $(R_{sig}, s_{sig})$ gegen den ephemeren Schlüssel $E$.
    - Wenn ungültig oder Zeuge fehlt: Sofortige Ablehnung (Schutz vor manipulierter Double-Spend-Falle).
        
4. **Forking (Anker setzen):**
    
    - **Bob:** Hash seines neuen Keys -> `receiver_ephemeral_pub_hash`.
    - **Alice (Rest):** Hash ihres neuen Keys -> `change_ephemeral_pub_hash`.
        
5. **L2 Signatur (`HMC_TX_AUTH_V3`):**
    
    Kanonischer längenpräfixierter Digest:  
    `HMC_TX_AUTH_V3 || layer2_voucher_id || challenge_ds_tag || t_id || sender_ephemeral_pub || trap_r || trap_s || encrypted_timestamp || deletable_at || privacy_guard_hash`
    
    _Signiert mit dem ephemeren Schlüssel von Alice (`sender_ephemeral_pub`). Damit sind alle Transaktionen und Gossip-Fingerprints selbstauthentifizierend und binden den Trap-Shard untrennbar an die Transaktion._
    
6. **Finalisierung:** Signatur der gesamten Tx und Anhängen an die Datei.

## 3. Implementierungshinweise

- **HKDF:** Verwende `HKDF-SHA256` für alle Schlüsselableitungen.
    
- **Proof:** Implementiere das Schnorr-Protokoll strikt nach Definition, um Interoperabilität zu gewährleisten.
    
- **Neu:** Beachte die Privacy-Regeln aus Teil 2!
    
## 4. Zukünftige Erweiterungen (TODOs)

### 4.1 Signierte Empfangsbestätigung (Signed Receipt)
**Konzept:** Für kritische Zahlungen oder geschäftliche Transaktionen soll optional eine kryptografisch signierte Quittung vom Empfänger angefordert werden können. 
- Dies dient als rechtssicherer Nachweis des Erhalts.
- Ermöglicht dem Empfänger eine Prüfung der Transaktionsdetails (Betrag, Verwendungszweck) vor der finalen Annahme.
- Muss so implementiert werden, dass es den atomaren Charakter der Transaktion nicht gefährdet (z.B. via Layer-2-Handshake vor der On-Chain/Ledger-Finalisierung).

## 5. VIP-Gossip & Double-Spend Erkennung (Dezentrales Immunsystem)

Da es keine zentrale Blockchain gibt, nutzt das P2P-Netzwerk ein modifiziertes Gossip-Protokoll, um Betrugsbeweise zu verbreiten.

### 5.1 Normale vs. VIP Fingerprints

Bei jeder Interaktion tauschen Clients zufällige `TransactionFingerprint`s aus ihrer Historie aus. Jeder Gutschein kann bis zu MAX_FINGERPRINTS_TO_SEND (derzeit 150) Huckepack nehmen.
Normalerweise altern diese Fingerprints (depth += 1 pro Hop). Trifft ein Client auf zwei unterschiedliche Transaktionen mit demselben `ds_tag`, ist dies der Beweis für einen Double-Spend.

Sobald ein Double-Spend erkannt wird, generiert der Client einen `ProofOfDoubleSpend` und wandelt die beteiligten Fingerprints in **"VIP-Fingerprints"** um.

### 5.2 Der VIP-Status (Negative Tiefe)

Die Tiefe (`depth`) in der `FingerprintMetadata` wird auf einen negativen Wert (z.B. `-1`) gesetzt. 
Dies triggert drei wichtige Schutzmechanismen:

1. **Effektiver Vorsprung (Head Start):**
   VIP-Fingerprints drängeln sich bei der Auswahl für das nächste Bundle vor. Die effektive Sortiertiefe berechnet sich als `abs(depth) - 2`. Ein VIP-Tag mit Tiefe `-1` wird behandelt als hätte er Tiefe `-1` (also vor Tiefe `0`). Das stellt sicher, dass Betrugswarnungen wie ein Lauffeuer das Netzwerk durchdringen und "gesunde" Tags verdrängen, wenn das Paketlimit erreicht ist.

2. **Organische Alterung:**
   Ein VIP-Fingerprint bleibt nicht ewig auf Platz 1. Mit jedem Hop wird er *negativer* (via `saturating_sub(1)`). Ein VIP-Tag mit Tiefe `-10` fällt hinter einen frischen normalen Tag (Tiefe `0`) zurück, da `abs(-10) - 2 = 8`. So wird verhindert, dass alte Warnungen ewig das Netzwerk blockieren (Network Congestion).

3. **Loop-Protection & Symmetrie:**
   - **Symmetrie-Zwang:** Um Denial-of-Service-Spam zu verhindern, muss ein externer Client einen VIP-Fingerprint immer paarweise (zwei mit dem gleichen `ds_tag`) anliefern. Asymmetrische Lieferungen werden vom Client auf eine normale (positive) Tiefe strafversetzt.
   - **Loop-Schutz:** Bereits lokal als VIP bekannte Transaktionen ignorieren "frischere" VIP-Updates von außen. Die erste lokale Erkennung bestimmt den natürlichen Alterungsprozess. Endlosschleifen zwischen Knoten werden somit unterbrochen.
