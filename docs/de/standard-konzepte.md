# Standard-Konzepte (V3 Shared-Signature-Trap)

> **Gültigkeitsstand:** V3 SST (`HMC_TX_AUTH_V3`), `human_money_core` ≥ 2026-08-26. V2-Begriffe (`u`, `blinded_id`, `proof`, `HMC_TX_AUTH_V2`) sind obsolet und werden beim Laden hart abgewiesen.

## 1. Motivation: Vouchertypen und ihre „Verfassung“

Ein Gutschein-Standard (`standard.toml`) ist die Verfassung einer Community-Währung (z. B. Minuto, Regionalgeld, Zeitgutschein). Er trennt unveränderliche Konsensregeln (`[immutable]`, Logic-Hash-gebunden) von flexiblen Präsentationsdaten (`[mutable]`, signiert aber nicht Logic-Hash-relevant) – vgl. `spec/06_standard_definition.md`. Die kryptographische Durchsetzung von Double-Spending-Schutz, Identitätsbindung und Gossip-Authentifizierung erfolgt jedoch **immer** nach dem hier beschriebenen V3-Protokoll.

## 2. Double-Spend-Tag (ds_tag) – Präfixunabhängig an den Einmalschlüssel gebunden

**Definition (V3):**

```
ds_tag = hash(prev_hash || sender_ephemeral_pub)
```

- `hash` = SHA3-256 über **rohe 32-Byte**-Hashes, längenpräfixiert via `get_hash_from_slices`.
- `prev_hash` = Hash der Vorgängertransaktion (bzw. `hash(voucher_id || nonce)` für `init`).
- `sender_ephemeral_pub` = der in der Transaktion **enthüllte Einmalschlüssel** (32 Byte, Base58).

Der Tag hängt **ausschließlich** von den Input-Daten ab und ist **präfixunabhängig**. Unterschiedliche logische Präfixe (`creator:fY7@did:key:z...` vs. `mobile:abc@did:key:z...`) leiten bereits per HKDF unterschiedliche ephemere Schlüssel ab – das Präfix zusätzlich in den Tag aufzunehmen wäre redundant und würde Identity-Hopping (gleicher ephemerer Schlüssel unter anderem Präfix wiederverwendet) ermöglichen. Validierung in `voucher_validation/chain.rs` prüft exakt diese Rekonstruktion und weist Abweichungen als Kontext-Mismatch ab. Die `ds_tag`-Zeichenkette selbst wird vor Dekodierung auf maximal 64 Base58-Zeichen (32 Byte ≈ 44 Zeichen) begrenzt und als 32-Byte-Hash verifiziert.

Beim Split verzweigt ein Gutschein in zwei Anker (`receiver_ephemeral_pub_hash` und `change_ephemeral_pub_hash`); beide Zweige erhalten über ihre unterschiedlichen Einmalschlüssel automatisch unterschiedliche `ds_tag`s.

## 3. TrapData (V3 SST) – Shards statt `u`/`blinded_id`

Jede Spend-Transaktion trägt **nur** ihren Shard einer **gemeinsamen deterministischen Schnorr-Signatur** `sigma = (R_sig, s_sig)` über `mu = H("HMC_TRAP_SIG_V1" || ds_tag || E)` mit `E = sender_ephemeral_pub`:

```rust
pub struct TrapData {
    pub ds_tag: String, // Base58, 32 Byte, identisch zum Fingerprint-ds_tag
    pub trap_r: String, // R_i = R_sig + tau_i * M_R (Base58, komprimierter Edwards-Punkt, 32 Byte)
    pub trap_s: String, // s_i = s_sig + tau_i * m_s  mod q (Base58, kanonischer Skalar, 32 Byte)
}
```

- `tau_i = H("HMC_TAU_V1" || ds_tag || t_id_i) mod q` – spend-spezifisch, daher kollidieren zwei Forks desselben Inputs in unterschiedlichen `tau`.
- `M_R = hash_to_curve("HMC_MASK_R_V1" || x || E || ds_tag)`, `m_s = H("HMC_MASK_S_V1" || x || E || ds_tag)` – Maskierungswerte, **ausschließlich** aus dem langfristigen Schlüssel `x` des Senders abgeleitet.
- Genesis (`t_type == "init"`) trägt **kein** `trap_data`; jede nicht-triviale `trap_data` in `init` wird in `verify_transaction_basics` hart abgewiesen (nur `""`/`"none"` zulässig).

V2-Felder `u` (Challenge-Skalar), `blinded_id` (Punkt `V`) und `proof` (Schnorr-Proof) existieren nicht mehr. Persistierte Voucher- oder Fingerprint-Stores, die noch `u`/`blinded_id`/`proof` enthalten, werden beim Laden mit `InvalidFormat` abgewiesen (`storage/file_storage.rs: contains_legacy_trap_data`); die Bytes bleiben unberührt bis zur expliziten Migration.

Strukturelle Gültigkeit jedes Shard-Paares wird bei jeder nicht-`init`-Transaktion via `trap_manager::validate_shard_structure` erzwungen: Base58-dekodierbar, 32 Byte, `trap_r` strikt kanonisches Edwards-`y < p` und dekomprimierbar, `trap_s` kanonisch reduzierter Skalar. Die Längenprüfung (`> 64` Zeichen) erfolgt vor Allokation (DoS-Schutz).

## 4. TransactionFingerprint (V3) – Selbstauthentifizierender Instant-Proof

```rust
pub struct TransactionFingerprint {
    pub ds_tag: String,               // Base58, 32 Byte
    pub t_id: String,                 // Base58, 32 Byte
    pub encrypted_timestamp: u128,    // original_nanos ^ hash(prev_hash || t_id) (erste 128 Bit)
    pub layer2_signature: String,     // Base58, 64 Byte, Ed25519 über HMC_TX_AUTH_V3
    pub sender_ephemeral_pub: String, // Base58, 32 Byte
    pub deletable_at: String,         // RFC3339; Wire: "" (neutralisiert), lokal: now+180 Tage
    pub trap_r: String,               // Base58 Shard R_i ("none" nur für Genesis)
    pub trap_s: String,               // Base58 Shard s_i ("none" nur für Genesis)
    pub layer2_voucher_id: String,    // Hex für Spends, "none" für Genesis
    pub privacy_guard_hash: String,   // Base58 SHA3-256 des Guards oder ""
}
```

- **Spend-Fingerprints:** tragen echte Shards; `layer2_voucher_id` ist die Hex-ID des Vouchers.
- **Genesis-Fingerprints:** `trap_r == "none" && trap_s == "none"` (einzig zulässige Genesis-Markierung; leere Strings, `"invalid"` oder gemischte Belegungen gelten als Spend-typisiert und werden nicht als Genesis fehlklassifiziert). `layer2_voucher_id == "none"` und `challenge_ds_tag == t_id`.
- **Void-Marker:** Spend-Transaktionen, deren Shards leer oder `"none"` sind, erhalten in `create_fingerprint_for_transaction` den Marker `"invalid"` – sie können nie als Genesis masqueradieren (HMSEC-SA06-11) und bleiben in der Gossip-Pipeline sichtbar.
- **Wire-Hygiene:** Beim Export wird `deletable_at` zu `""` neutralisiert (Familien-Clustering vermeiden, HMSEC-SA06-15); beim Import wird lokal einheitlich `now + 180 Tage` vergeben. `is_init_fingerprint` und `verify_fingerprint_signature` bilden das Ingress-Gate – nur verifizierte Spend-Fingerprints werden aufgenommen.

## 5. HMC_TX_AUTH_V3 – Der einheitliche Digest

Domain-Tag `HMC_TX_AUTH_V3` bindet alle Felder **längenpräfixiert** (`get_raw_hash_from_slices`):

```
HMC_TX_AUTH_V3
|| layer2_voucher_id            // Hex (Spend) / "none" (Genesis)
|| challenge_ds_tag              // ds_tag (Spend) / t_id (Genesis)
|| t_id                         // 32 Byte
|| sender_ephemeral_pub          // 32 Byte
|| trap_r                       // Base58 ("none" für Genesis)
|| trap_s                       // Base58 ("none" für Genesis)
|| encrypted_timestamp          // 16 Byte LE u128
|| deletable_at                 // "" falls None (nur Genesis bindet Rohwert)
|| privacy_guard_hash           // "" falls kein Guard
```

Der Digest dient zugleich als **L1-Ownership-Proof** (Chain-Validierung), **L2-Lock-Proof** (Server verifiziert Lock-Requests) und **Gossip-Proof** (jeder Peer verifiziert Fingerprints ohne Kettennachforderung). Die frühere unpräfixierte Konkatenation (`HMC_TX_AUTH_V2`-Ära) ist damit behoben (AUDIT-01-F03). Zusätzlich bindet `privacy_guard_hash` Guard-Äquivokation (HMSEC-SA04-08) und `layer2_voucher_id` verhindert Cross-Voucher-Transplantation (audit_02_11).

## 6. Shared-Signature Trap (SST) – Lineare Rekonstruktion und EUF-CMA-Bindung

**Einzel-Shard-Anonymität:** Ein einzelner Shard `(R_i, s_i)` verbirgt den Signierer informationstheoretisch – 4 Unbekannte (`R_sig, s_sig, M_R, m_s`) stehen 3 Gleichungen gegenüber. Kein „P-pre“-Register-Mining kann ihn verknüpfen.

**Kollisions-Enttarnung (autonom, ohne Kettenanforderung):** Zwei kollidierende Fingerprints (gleicher `ds_tag`, verschiedene `t_id`) mit `tau_1 != tau_2`:

```
M_R   = (R1 - R2) / (tau1 - tau2)
m_s   = (s1 - s2) / (tau1 - tau2)
R_hat = R1 - tau1 * M_R
s_hat = s1 - tau1 * m_s
c     = H("HMC_TRAP_CHAL_V1" || mu || R_hat)
X_hat = (s_hat * G - R_hat) * c^{-1}
```

`X_hat` ist der **öffentliche Schlüssel des Täters**; komprimiert und zu `did:key:z...` kodiert ergibt er den `offender_id`. Die Attribution ist **EUF-CMA-gebunden**: Einen Unschuldigen zu framen erfordert, eine gültige Schnorr-Signatur unter dessen Schlüssel zu fälschen – praktisch unmöglich (Remediation AUDIT-01-F07). Das System extrahiert via `extract_sst_identity` bzw. verifiziert via `verify_sst_shards_consistency` / `verify_stored_trap_shards_against_identity`.

**Firewall für degenerierte Fälle:** identisches `tau`, identische Shards, nicht-kanonische Skalare, `c = 0`, neutrales Element, Torsion in `M_R` oder `X_hat` (HMSEC-02-08) sowie inkonsistente `n ≥ 3`-Shard-Linien werden abgewiesen. Für die Attribution genügt **ein** konsistentes Paar – ein einzelner vom Angreifer injizierter Off-line-Shard kann eine korrekte Attribution nicht vetoieren (AUDIT-01-F13).

**L1-Betrugsvorbeugung (R5):** Der private Zeuge `W = (R_sig, s_sig, M_R, m_s)` reist verschlüsselt im `RecipientPayload` (`trap_r_sig`, `trap_s_sig`, `trap_m_r`, `trap_m_s`). Der Empfänger prüft bei der Übergabe via `verify_sst_witness`:

1. `s_sig * G == R_sig + c * X_payer`
2. `R_i == R_sig + tau_i * M_R`
3. `s_i == s_sig + tau_i * m_s`

Fehlschläge führen zur sofortigen Abweisung der Zahlung – manipulierte Fallen werden gar nicht erst in die Kette aufgenommen.

## 7. Bezug zu Standard-Variablen

- `privacy_mode` (`public`/`stealth`/`flexible`) steuert nur die Sichtbarkeit von `sender_id`/`recipient_id` auf Layer 1; die SST-Falle und `ds_tag` funktionieren in allen Modi identisch, da sie auf dem ephemeren Schlüssel basieren.
- `allow_partial_transfers` / `allowed_t_types` regeln Teilbarkeit; die Falle unterscheidet Transfer- und Change-Zweige automatisch über deren unterschiedliche ephemere Schlüssel.
- Die Exklusivitätsregel `[immutable]` vs. `[mutable]` bleibt unverändert – SST-Parameter sind implizit Teil des Konsenses, da jede Änderung den `HMC_TX_AUTH_V3`-Digest brechen würde.

## 8. Migration von V2

- V2 nutzte `TrapData { ds_tag, u, blinded_id, proof }` und `HMC_TX_AUTH_V2`. Diese Felder werden nicht mehr serialisiert; Stores mit solchen Feldern werden hart abgewiesen.
- Bestehende V2-Signaturen/Fingerprints sind **ungültig**; fremde V2-Fingerprints werden beim Laden/Cleanup verworfen.
- Neue Implementierungen dürfen ausschließlich `trap_r`/`trap_s` und `HMC_TX_AUTH_V3` verwenden.

---

*Siehe auch:* `spec/04_kryptographie_und_mathematik.md` (mathematische Herleitung), `spec/03_protokoll_ablauf.md` (P2PKH-Verkettung), `spec/02_datenstrukturen.md` (Strukturdetails), `src/models/voucher.rs:115` und `src/services/trap_manager.rs:1` (kanonische Implementierung).
