# Dokumentation: Transaktionsstruktur und Double-Spending-Erkennung

## 1. Motivation und Designziele

Die Transaktionsstruktur in `human_money_core` wurde entwickelt, um zwei Hauptziele zu erreichen:

- **Interne Integrität:** Die Historie innerhalb einer einzelnen Gutschein-Datei muss fälschungssicher und kryptographisch nachvollziehbar sein.

- **Globale Validierung:** Es muss möglich sein, eine externe (Layer 2) Infrastruktur zur Erkennung von Double-Spending aufzubauen. Dabei sollen die Anonymität der Nutzer und die Details der Gutscheine gewahrt bleiben, aber dennoch eine zeitliche Einordnung von Konflikten möglich sein.

Das Ergebnis ist eine mehrschichtige Sicherheitsarchitektur, die auf einer expliziten kryptographischen Verkettung und einem datenschutzfreundlichen Shared-Signature-Trap (SST, Protokoll V3) sowie dem Fingerprint-Schema unter `HMC_TX_AUTH_V3` beruht.

---

## 2. On-Voucher-Integrität: Die `prev_hash`-Kette

Jede Transaktion ist über das Feld `prev_hash` untrennbar mit ihrem Vorgänger verbunden.

- **Init-Transaktion:** Die allererste Transaktion (`t_type: "init"`) ist ein Sonderfall. Ihr `prev_hash` ist der Hash über `voucher_id` und `voucher_nonce` (`hash(voucher_id_bytes || nonce_bytes)`). Dies verankert die gesamte Transaktionskette fest mit der Identität des Gutscheins.

- **Folgetransaktionen:** Bei jeder weiteren Transaktion ist `prev_hash` der Hash des gesamten, kanonisch serialisierten Vorgänger-Transaktionsobjekts.

Diese Verkettung stellt sicher, dass die Reihenfolge der Transaktionen nicht unbemerkt verändert und keine Transaktion aus der Mitte entfernt werden kann, ohne die Kette zu brechen.

---

## 3. Anatomie einer Transaktion

### Transaction ID (`t_id`)

Jede Transaktion besitzt eine eindeutige `t_id`. Diese wird berechnet, indem das Transaktionsobjekt selbst (mit temporär leeren `t_id`-, `sender_signature`- und – seit V3 – ohne `trap_data`/`privacy_guard`/`layer2_signature`) kanonisch serialisiert und gehasht wird. Dies gibt jeder Transaktion eine von ihrem Inhalt abhängige, fälschungssichere Identität. Die Fallen-Shards hängen von `tau(t_id)` ab – daher muss `trap_data` zirkelfrei außerhalb des `t_id`-Preimage bleiben und wird stattdessen über `HMC_TX_AUTH_V3` gebunden.

### Transaction Signature (`sender_signature` / `layer2_signature`)

Die technische Autorisierung erfolgt über `layer2_signature` (ephemerer Schlüssel) unter dem Domain-Tag `HMC_TX_AUTH_V3`. Der Zeitstempel `t_time` ist **nicht** direkter Teil des Signatur-Payloads, sondern fließt über `t_id` (implizit) und `encrypted_timestamp` in den Digest ein. Das minimale signierte Objekt umfasst kanonisch längenpräfixiert:

```
HMC_TX_AUTH_V3 || layer2_voucher_id || challenge_ds_tag || t_id || sender_ephemeral_pub
               || trap_r || trap_s || encrypted_timestamp || deletable_at || privacy_guard_hash
```

- **`layer2_voucher_id`**: Hex-ID für Spends, kanonisch `"none"` für Genesis (Vermeidung von Zirkularität).
- **`challenge_ds_tag`**: `t_id` für Genesis, `ds_tag` für Spends.
- **`trap_r` / `trap_s`**: V3-SST-Shards (`"none"` für Genesis).
- **`privacy_guard_hash`**: `SHA3-256(Base64(privacy_guard))` bzw. Leerstring, bindet Guard-Äquivokation (HMSEC-SA04-08).

**Warum ist das sicher?** Da `t_time` Teil der Daten für `t_id` ist, ist der Zeitstempel über `t_id` implizit fälschungssicher gebunden. Alle weiteren Felder sind malleability-fest längenpräfixiert; jede Bit-Änderung invalidiert die Signatur.

---

## 4. Layer 2: Anonymisierte Double-Spending-Erkennung (V3 SST)

Die `human_money_core`-Bibliothek erlaubt einer übergeordneten Anwendung, eine globale Datenbank zur Betrugserkennung zu nutzen, ohne sensible Daten preiszugeben.

### Das Konzept des „Anonymen Fingerabdrucks“

Um einen Double-Spend global zu erkennen, muss ein Server wissen, ob ein Sender versucht, vom selben Zustand (`prev_hash`) zweimal auszugeben. Dafür wird ein anonymer Fingerabdruck erzeugt.

- **Fingerprint-ID (V3):** `ds_tag = hash(prev_hash || sender_ephemeral_pub)` (SHA3 über die rohen 32-Byte-Hashes, längenpräfixiert via `get_hash_from_slices`). Die Bindung erfolgt **ausschließlich** an den **enthüllten Einmalschlüssel** `sender_ephemeral_pub`, **präfixunabhängig**. Unterschiedliche logische Präfixe (`creator:fY7@did:key:...` vs. `mobile:xyz@did:key:...`) leiten bereits unterschiedliche ephemere Schlüssel ab; das Präfix im Tag wäre redundant und würde Identity-Hopping ermöglichen.

- **Server-Upload (V3):** Ein Client lädt ein **`TransactionFingerprint`**-Objekt hoch. Schema (V3 SST):

  ```rust
  pub struct TransactionFingerprint {
      pub ds_tag: String,               // Base58, 32 Byte, hash(prev_hash || sender_ephemeral_pub)
      pub t_id: String,                 // Base58, 32 Byte
      pub encrypted_timestamp: u128,    // XOR-verschlüsselt, siehe unten
      pub layer2_signature: String,     // Base58, 64 Byte, über HMC_TX_AUTH_V3
      pub sender_ephemeral_pub: String, // Base58, 32 Byte, enthüllter Einmalschlüssel
      pub deletable_at: String,         // RFC3339; Wire: neutralisiert, lokal: +180 Tage
      pub trap_r: String,               // Base58, 32 Byte, Shard R_i  ("none" nur für Genesis)
      pub trap_s: String,               // Base58, 32 Byte, Shard s_i  ("none" nur für Genesis)
      pub layer2_voucher_id: String,    // Hex für Spends, "none" für Genesis
      pub privacy_guard_hash: String,   // Base58 SHA3-256 des Guards oder ""
  }
  ```

  Der Server kennt weder `prev_hash` noch Details zum Gutschein und kann `sender_id` nicht aus dem Hash rekonstruieren. Er sieht nur den deterministischen `ds_tag`.

- **TrapData (V3, on-chain):** Jede Spend-Transaktion trägt **nur** ihren Shard:

  ```rust
  pub struct TrapData {
      pub ds_tag: String, // identisch zum Fingerprint-ds_tag
      pub trap_r: String, // R_i = R_sig + tau_i * M_R (Base58, komprimierter Edwards-Punkt)
      pub trap_s: String, // s_i = s_sig + tau_i * m_s  (Base58, kanonischer Skalar)
  }
  ```

  V2-Felder `u`, `blinded_id` und `proof` existieren nicht mehr und werden beim Laden **hart abgewiesen** (`InvalidFormat`). Genesis-Transaktionen tragen keine `trap_data`; ihre Fingerprints nutzen kanonisch `"none"` für beide Shards.

### Die Innovation: Der verschlüsselte Zeitstempel

Der Schlüssel ist der **verschlüsselte Zeitstempel**. Er löst das Dilemma, eine zeitliche Einordnung für Konflikte zu ermöglichen, ohne das Datum an den Server preiszugeben.

- **Verschlüsselung:** `encrypted_nanos = original_nanos ^ schlüssel` (XOR, `u128` little-endian).
- **Schlüsselableitung:** `schlüssel = hash(prev_hash || t_id)` (erste 128 Bit, rohe Bytes, SHA3).
- **Datenschutz:** Der Server kann nicht entschlüsseln, da `prev_hash` nicht im Fingerprint enthalten ist.
- **Beweisführung:** Ein Opfer mit `ProofOfDoubleSpend` besitzt `prev_hash`, `t_id_A` und `t_id_B` und rekonstruiert beide Schlüssel, entschlüsselt und vergleicht die Zeitstempel.

### V3 Shared-Signature Trap (SST): Autonome Enttarnung

Jeder Spend publiziert nur einen **Shard** einer **einzigen deterministischen Schnorr-Signatur** `sigma = (R_sig, s_sig)` über die Spend-Nachricht `mu = H("HMC_TRAP_SIG_V1" || ds_tag || E)` (`E = sender_ephemeral_pub`):

```
tau_i  = H("HMC_TAU_V1" || ds_tag || t_id_i)  mod q
R_i    = R_sig + tau_i * M_R
s_i    = s_sig + tau_i * m_s                mod q
```

- `M_R = hash_to_curve("HMC_MASK_R_V1" || x || E || ds_tag)`, `m_s = H("HMC_MASK_S_V1" || x || E || ds_tag)` – ausschließlich aus dem **langfristigen Schlüssel** `x` des Senders abgeleitet.
- **Einzel-Shard-Anonymität:** Ein einzelner Shard verbirgt den Signierer informationstheoretisch (4 Unbekannte `R_sig, s_sig, M_R, m_s` vs. 3 Gleichungen). Kein Register-Mining („P-pre“) kann ihn verknüpfen.
- **Kollisions-Enttarnung:** Zwei kollidierende Shards (`ds_tag` gleich, `t_id` verschieden, `tau_1 != tau_2`) erlauben **lineare Rekonstruktion**:

  ```
  M_R  = (R1 - R2) / (tau1 - tau2)
  m_s  = (s1 - s2) / (tau1 - tau2)
  R_hat = R1 - tau1 * M_R
  s_hat = s1 - tau1 * m_s
  c     = H("HMC_TRAP_CHAL_V1" || mu || R_hat)
  X_hat = (s_hat * G - R_hat) * c^{-1}
  ```

  `X_hat` ist der **öffentliche Schlüssel (`did:key`) des Täters**. Die Bindung ist **EUF-CMA-sicher**: Einen unschuldigen Dritten zu framen erfordert eine Schnorr-Fälschung unter dessen Schlüssel – praktisch unmöglich (Remediation AUDIT-01-F07). Degenerierte Fälle (`tau`-Gleichheit, identische Shards, nicht-kanonische Skalare, `c = 0`, neutrales Element, Torsion) werden als Firewall abgewiesen.

- **L1-Betrugsvorbeugung (R5):** Der private Zeuge `W = (R_sig, s_sig, M_R, m_s)` reist verschlüsselt im `RecipientPayload` (`trap_r_sig/trap_s_sig/trap_m_r/trap_m_s`). Der Empfänger verifiziert bei der Übergabe Signatur und Shard-Konsistenz (`verify_sst_witness`) und weist manipulierte Fallen sofort ab.

Damit sind Gossip-Fingerprints **selbstauthentifizierend**: Jeder Peer verifiziert `layer2_signature` gegen `HMC_TX_AUTH_V3` allein aus Fingerprint-Daten (`ds_tag`, `E`, `trap_r/s`), ohne Transaktionsketten anzufordern. Zwei verifizierte kollidierende Fingerprints genügen für eine definitive `did:key`-Attribution; ein einzelner gefälschter Off-line-Shard kann die Attribution nicht vereiteln (beliebiges konsistentes Paar genügt).

### Erkennung und Beweisführung (V3-Schema)

Ein Double-Spend liegt vor, wenn der Server einen Fingerprint für einen `ds_tag` erhält, für den bereits ein Eintrag mit abweichender `t_id` **oder** – bei gleicher `t_id` – mit divergenten signaturgebundenen Feldern (`trap_r/s`, `encrypted_timestamp`, `layer2_signature`, `privacy_guard_hash`) existiert (Guard-Äquivokation, HMSEC-SA04-08).

- **Alarm:** Der Server schlägt Alarm und sendet den existierenden Fingerprint als Beweis zurück.
- **Lokale Verifizierung:** Der Client verifiziert beide `layer2_signature`-Signaturen über `HMC_TX_AUTH_V3` und – bei Kollisionsverdacht – die SST-Shards via `extract_sst_identity` / `verify_stored_trap_shards_against_identity`. Zusätzlich entschlüsselt er beide Zeitstempel und vergleicht sie.

---

## 5. Peer-to-Peer-Verbreitung (Gossip-Protokoll)

Neben der zentralisierten Erkennung über einen Layer-2-Server ermöglicht die Architektur eine dezentrale, rein Peer-to-Peer-basierte Verbreitung von Fingerprints. Dies geschieht durch ein „Gossip-Protokoll“, bei dem Teilnehmer sich gegenseitig über Transaktionen informieren, die sie beobachtet haben.

Jedes Mal, wenn ein Wallet ein Transaktionsbündel an einen Empfänger sendet, legt es eine Sammlung von bis zu 150 Fingerprints bei, die es für relevant hält.

### Die intelligente Auswahl (Heuristik)

Die `select_fingerprints_for_bundle`-Methode wählt nicht zufällig aus, welche Fingerprints sie weiterleitet:

- **Priorisierung nach Relevanz (`depth`):** Jeder Fingerprint hat eine „Tiefe“ (`depth`), die angibt, wie viele Stationen (Hops) er bereits durchlaufen hat. Bevorzugt werden Fingerprints mit der niedrigsten `depth` (beginnend bei 0).
- **Vermeidung von Redundanz (`known_by_peers`):** Das Wallet merkt sich für jeden Fingerprint, welchen Peers es diesen bereits gesendet hat.
- **„Gieriges“ Füllen des Kontingents:** Das Protokoll versucht immer, das Kontingent von 150 Fingerprints zu füllen.

### Die Verarbeitung (Min-Merge-Regel)

Wenn ein Wallet ein Bündel mit Fingerprints empfängt:

1. Die `depth` jedes empfangenen Fingerprints wird um 1 erhöht.
2. Das Wallet vergleicht die neue `depth` mit dem lokal gespeicherten Wert.
3. Es wird immer der **niedrigere (bessere) Wert beibehalten**.

Zusätzlich gilt seit V3 ein **Ingress-Gate**: Nur Fingerprints mit gültiger `HMC_TX_AUTH_V3`-Signatur und Spend-Typ (`trap_r/s != "none"`) werden aufgenommen; Genesis-Fingerprints (`"none"/"none"`) und leere/ungültige Shards werden als „invalid“ markiert und nicht als Genesis fehlklassifiziert. Unvertraute Wire-Deadlines werden lokal auf `+180` Tage vereinheitlicht (HMSEC-SA06-15).

---

## 6. Konfliktlösung: Die geteilte Strategie (Offline vs. Layer 2)

### Szenario A: Reine Offline-Erkennung (Heuristik: „Der Frühere gewinnt“)

Dies ist der Standardfall, wenn ein Wallet einen Konflikt lokal feststellt (z. B. durch Austausch von Fingerprints mit einem Peer), ohne ein Server-Urteil zu haben.

- **Aktion des Wallets:**
  1. Das Wallet entschlüsselt die Zeitstempel beider widersprüchlicher Transaktionen.
  2. Der Zweig mit dem **früheren Zeitstempel** bleibt `Active`.
  3. Der Zweig mit dem **späteren Zeitstempel** wird auf `VoucherStatus::Quarantined` gesetzt.

Die Heuristik wird nur auf **lokal gehaltene** Zweige oder durch `HMC_TX_AUTH_V3` selbstauthentifizierte fremde Fingerprints angewendet; unauthentifizierte Gossip-Gerüchte können die Offline-Entscheidung nicht gewinnen.

### Szenario B: Layer-2-gestützte Lösung (Autoritatives Urteil)

Tritt ein, wenn das Wallet einen `ProofOfDoubleSpend` mit signiertem `Layer2Verdict` verarbeitet. **Das Urteil des Servers hat immer Vorrang.**

- **Aktion des Wallets:**
  1. Verifikation der Signatur des `Layer2Verdict`.
  2. Der laut Urteil **gültige** Zweig wird `Active` (oder reaktiviert).
  3. Der **ungültige** Zweig wird `Quarantined` und erhält eine Sperr-Transaktion (`t_type: "block"`).

### Fazit

Das System kombiniert eine robuste, interne Kettenlogik mit einem fortschrittlichen, datenschutzfreundlichen SST-Fingerprint-Mechanismus unter `HMC_TX_AUTH_V3`. Ein einzelner Shard ist anonym; zwei kollidierende Shards enttarnen den Täter autonom und EUF-CMA-gebunden als `did:key`. Das Protokoll operiert offline mit deterministischer Heuristik und schaltet nahtlos auf autoritative L2-Sicherheit um, sobald höherwertige Informationen verfügbar sind.
