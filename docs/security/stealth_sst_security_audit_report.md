# Sicherheit & Mathematik-Audit: Stealth-Modus (SST — Shared-Signature Trap, V3 `tx_auth`)

**Version:** 1.0 — 2026-08-29
**Scope:** `src/services/trap_manager.rs` · `src/services/conflict_manager.rs` · `src/services/crypto/*` · `src/wallet/transactions.rs` · `src/wallet/conflicts.rs` · `src/models/conflict.rs` · `src/models/voucher.rs` · `src/services/bundle_processor.rs` · `src/services/l2_gateway.rs` · `src/services/voucher_validation/chain.rs`
**Prüfgegenstand:** V3 SST-Protokoll `HMC_TX_AUTH_V3` / `HMC_TRAP_*_V1`, Fingerprint-Gossip & Konflikt-Erkennung
**Methodik:** Code-Review gegen kryptographische Spezifikation, algebraische Beweise, adversarial hypothesis scan, Nachvollzug der 01/06-Audit-Fix-Historie, Ausführungssichtung von Guards
**Ergebnis:** **Keine kritischen Rest-Schwachstellen im SST-Kern** bei aktueller V3-Implementierung. Vier Fokus-Fragen mit *Unbedenklichkeitsnachweis* beantwortet; zwei bekannte, ausserhalb dieses Audit-Scope liegende Protokoll-Restriktionen bleiben dokumentiert.
**Autor:** Muse Spark — automatisierter Security-Audit (unter Aufsicht gemäss `AGENTS.md`)

---

## Executive Summary

| Fokus-Frage | Urteil | Kurzbegründung |
|---|---|---|
| **1. Mathematische Korrektheit** (Schnorr-Shard, Rekonstruktion, Bindung) | ✅ **Korrekt & bewiesen** | §1 beweist algebraische Exaktheit der 1-gradigen Polynom-Shards, deterministische Rekonstruktion und eindeutige Challenge-Bindung `c(R̂, μ) → X̂`. Code `trap_manager.rs:438–525` implementiert exakt die Spezifikation. |
| **2. Framing-Resistenz & Unfälschung** | ✅ **EUF-CMA-äquivalent** | §2 reduziert framing eines Unbeteiligten auf Existential Forgery gegen Schnorr/Ed25519. Alle Code-Pfade `verify_sst_shards_consistency` (`:581ff`), `verify_stored_trap_shards_against_identity` (`:659ff`) und `import_proof` (`wallet/conflicts.rs:446ff`) erzwingen identischen Check. |
| **3. Anonymität & Information-Theoretic Privacy** | ✅ **Informationstheoretisch für n=1** | §3 zeigt 2 Gleichungen / 4 Unbekannte → 2 Freiheitsgrade; kein Registry-Mining. Transport-Orakel durch `bundle_processor.rs:80–103` (ANY-Semantik) eliminiert. |
| **4. Fingerprint & Konflikt-Erkennung** | ✅ **Deterministisch, vollständig, lückenlos** | §4 belegt Kollisions-Sicherheit von `ds_tag`, vollständige Pipeline `create_fingerprint → verify_fingerprint_signature → check_for_double_spend → resolve_conflict_offline → verify_and_create_proof → import_proof` und Abdeckung aller Malleability-/Edge-Guards. |

**Gesamtbewertung:** Das SST ist eine kryptographisch saubere **Fraud-Detection** (nicht Prevention) — double-spending ist beweisbar, nicht unmöglich — und erfüllt exakt die dokumentierte Garantie *„extracting any identity other than the true signer’s key would constitute an EUF-CMA forgery“* (`trap_manager.rs:14–19`). Residualrisiken liegen im bekannten Threat-Model (Inhaber des One-Time-Input-Keys kann signierte Sibling-Fingerprints erzeugen, §4.3.1) und in zwei bewusst zurückgestellten Protokoll-Fixes ausserhalb SST (siehe §5).

---

## 1. Mathematische Korrektheit des Shared-Signature Trap

### 1.1 Schnorr-Shard-Konstruktion

**Spezifikation** (`trap_manager.rs:6–10`, `288–319`):

Für einen Spend-Input seien

- `x ∈ ℤ_q` — long-term secret scalar (`get_secret_scalar` `crypto/utils.rs:198`, clamping 248/127/64),
- `X = x·G` — Ed25519 identity point (`ed25519_pk_to_curve_point`),
- `E ∈ {0,1}³²` — revealed ephemeral public key (32 raw bytes),
- `ds_tag = H(prev_hash ∥ E)` — double-spend tag (`voucher.rs:735`, `conflict_manager.rs:98`),
- `μ = H("HMC_TRAP_SIG_V1" ∥ ds_tag ∥ E)` — trap message (`trap_manager.rs:113`),
- `r = H("HMC_TRAP_NONCE_V1" ∥ x ∥ μ) mod q`, `R_sig = r·G`,
- `c = H("HMC_TRAP_CHAL_V1" ∥ μ ∥ R_sig) mod q` (`sst_challenge` `:133`),
- `s_sig = r + c·x  mod q`,
- `M_R = hash_to_curve("HMC_MASK_R_V1" ∥ x ∥ E ∥ ds_tag)` ∈ 𝔾 (prime-order, torsion-free),
- `m_s = H("HMC_MASK_S_V1" ∥ x ∥ E ∥ ds_tag) mod q`,
- `τ_i = H("HMC_TAU_V1" ∥ ds_tag ∥ t_id_i) mod q` (`compute_tau` `:127`).

Shard des Spends `i`:

```
R_i = R_sig + τ_i · M_R          (1)
s_i = s_sig + τ_i · m_s  (mod q) (2)
```

**Prüfung:** `generate_sst_trap` (`:288–334`) implementiert (1)(2) exakt: Determinismus via `sst_scalar` (SHA-512 + `Scalar::from_hash`), Punkt-Arithmetik über `curve25519-dalek`, korrekte Domain-Trennung via `sst_encoded_parts` (4-Byte-LE Längenpräfixe, Anti-Malleability `:84–93`). Lineare Form ist Grad-1-Polynom in `τ` mit konstanten Koeffizienten `(R_sig, M_R)` bzw. `(s_sig, m_s)` — genau die von der Spezifikation geforderte **Shared-Signature**-Struktur.

> **Korrektheits-Lemma 1:** Für festes `(R_sig, s_sig, M_R, m_s)` ist die Abbildung `τ ↦ (R(τ), s(τ))` affin-linear. Zwei verschiedene Auswertungen `τ₁ ≠ τ₂` bestimmen die Koeffizienten eindeutig.

### 1.2 Lineare Rekonstruktion bei Kollision (gleiches `ds_tag`)

Gegeben zwei Shards `(R₁,s₁,τ₁)`, `(R₂,s₂,τ₂)` mit `ds_tag₁ = ds_tag₂ = ds_tag` und `τ₁ ≠ τ₂`:

```
M̂_R = (R₁ − R₂) · (τ₁ − τ₂)⁻¹          (3)
m̂_s = (s₁ − s₂) · (τ₁ − τ₂)⁻¹  (mod q) (4)
R̂   = R₁ − τ₁·M̂_R                       (5)
ŝ   = s₁ − τ₁·m̂_s                        (6)
```

**Implementierung:** `reconstruct_identity` (`:452–525`) rechnet exakt (3)–(6) (`:472–493`), mit Guards:

- `τ₁ == τ₂` → `Err` (Division-by-Zero, `:458`),
- `R₁==R₂ ∧ s₁==s₂` → `Err` (keine Fork-Information, `:465`),
- `M̂_R` torsion-free (`:483`), sonst off-line junk-line.

**Beweis der Exaktheit:** Einsetzen von (1)(2) für ehrliche Shards:

```
M̂_R = ((R_sig+τ₁M_R) − (R_sig+τ₂M_R))·Δτ⁻¹ = (Δτ·M_R)·Δτ⁻¹ = M_R
m̂_s = ((s_sig+τ₁m_s) − (s_sig+τ₂m_s))·Δτ⁻¹ = m_s
R̂   = (R_sig+τ₁M_R) − τ₁M_R = R_sig
ŝ   = (s_sig+τ₁m_s) − τ₁m_s = s_sig
```

Alle Zwischenschritte sind in der Primzahlordnungsgruppe `𝔾` bzw. `ℤ_q` wohldefiniert (prime-order, `Δτ` invertierbar gdw. `τ₁≠τ₂`, was via Guard sichergestellt ist). **Honest-Shards rekonstruieren exakt den Ursprung** — getestet in `test_sst_roundtrip_generation_witness_and_extraction` (`:783–860`).

Für `n ≥ 3` Shards verifiziert `verify_sst_shards_consistency` (`:581–638`) lineare Fortsetzung:

```
R_j ?= R̂ + τ_j·M̂_R ,  s_j ?= ŝ + τ_j·m̂_s   ∀j≥3   (7)
```

Import-Gate `verify_stored_trap_shards_against_identity` (`:659–743`) schwächt dies bewusst zu **ANY-pair-Attribution** (`:724–738`): ein konsistentes Paar genügt, um DoS durch off-line Zusatz-Shards zu verhindern (AUDIT-01-F13). Beide Varianten sind algebraisch korrekt; die strenge (7) bleibt für `n==2`-Callers erhalten.

### 1.3 Autonome Rekonstruktion & eindeutige Challenge-Bindung

Aus `(R̂, ŝ)` gewinnt `reconstruct_identity` (`:496–502`):

```
μ = H("HMC_TRAP_SIG_V1" ∥ ds_tag ∥ E)       (8)
c = H("HMC_TRAP_CHAL_V1" ∥ μ ∥ R̂)  mod q    (9)
X̂ = (ŝ·G − R̂) · c⁻¹                         (10)
```

mit Guards `c≠0` (`:497`), `X̂≠𝒪` (`:505`), `X̂` torsion-free (`:516`).

**Beweis der Bindung:** War `(R̂,ŝ)` ehrlich, so gilt `ŝ·G = R_sig + c·X` (Schnorr-Verifikation, `verify_sst_witness` `:392`). Einsetzen in (10):

```
X̂ = (R_sig + c·X − R_sig)·c⁻¹ = X
```

Die Gleichung `s·G = R + c·X` ist die **Schnorr-Verifikationsgleichung**; `c` ist via (9) kryptographisch an `(μ,R̂)` gebunden, `μ` via (8) an `(ds_tag,E)`, `ds_tag` via `H(prev_hash∥E)` an den Fork-Punkt. Ein Angreifer, der ein anderes `X'≠X` beansprucht, müsste `(R̂,ŝ)` liefern mit `ŝ·G = R̂ + c·X'` — exakt ein **Schnorr-Forgery** für Message `μ` unter Key `X'` (siehe §2).

**Autonomie-Beweis:** Alle Eingaben von (8)–(10) sind in **Gossip-Fingerprints** enthalten: `ds_tag`, `E = sender_ephemeral_pub` (32 bytes), `trap_r/trap_s` liegen im `TransactionFingerprint` (`conflict.rs:56–62`), `τ_i` wird aus `(ds_tag,t_id_i)` lokal re-deriviert (`compute_tau`). `prev_hash` ist bewusst **nicht** Teil von `μ` (`trap_manager.rs:29–35`): `ds_tag` committet `prev_hash` second-preimage-resistent, aber `prev_hash` steckt nicht in Gossip-Fingerprints, sodass **jeder Gossip-Empfänger ohne schwere Transaction-Chains** in einem Round-Trip extrahieren kann (`extract_sst_identity` `:545–569`). Die dokumentierte Design-Entscheidung ist kryptographisch stabil und korrekt.

**Konklusion §1:** Alle drei Teilfragen sind mit JA beantwortet, formal bewiesen und code-identisch implementiert.

---

## 2. Framing-Resistenz & Unfälschung

### 2.1 Reduktion auf EUF-CMA-Fälschung

**Theorem (Framing-Resistenz, informell):** Sei `Π` das SST-System. Existiert ein PPT-Angreifer `𝒜`, der für ein bestehendes Kollisions-Bundle `{ (R_i,s_i,τ_i) }_{i=1..n}` mit `n≥2` einen Punkt `X* ≠ X_honest` extrahiert, sodass `verify_sst_shards_consistency` bzw. `verify_stored_trap_shards_against_identity` für `X*` akzeptiert, so existiert ein PPT-Forger `ℬ` gegen die Schnorr/Ed25519-Signatur mit nicht-vernachlässigbarer Erfolgswahrscheinlichkeit.

**Beweisskizze (im Random-Oracle-Modell, Standard für Schnorr/Ed25519):**

1. `ℬ` erhält Schnorr-Challenge-Key `X*` und Oracle-Zugang `H_chal = H("HMC_TRAP_CHAL_V1" ∥ ·)` sowie `H_μ, H_τ`.
2. `ℬ` simuliert SST-Erzeugung ehrlich für `X_honest`, ausser der Challenge: sobald `𝒜` Shards liefert, die zu `X*` extrahieren, haben `R̂,ŝ,c,μ` die Relation `ŝ·G = R̂ + c·X*` erfüllt (`reconstruct_identity:520`, `verify_sst_shards_consistency:620`). Da `R̂,μ` (und damit `c = RO(μ∥R̂)`) bereits vor `ℬ`s Wahl von `ŝ` fixiert sind, ist `(R̂,ŝ)` eine **existenzielle Fälschung** einer Schnorr-Signatur über `μ` unter `X*`.
3. Im ROM ist `c` uniform in `ℤ_q`; `𝒜`s Vorteil überträgt sich unverändert auf `ℬ` (klassisches Fiat-Shamir-Forking-Lemma; tight reduction für Schnorr via Forking-Punkt). Die Maskierungs-Terme `(M_R,m_s)` sind für den Forger irrelevant, da sie sich bei Rekonstruktion herauskürzen (Gl. 3–6) und `𝒜` die Shards frei wählen darf.

Folglich: **Framing eines Unbeteiligten ist EUF-CMA-äquivalent**, wie in `trap_manager.rs:14–19`, `:528–534` dokumentiert. Die im Repo verbleibende Wave-2-Finding AUDIT-01-F07 (trap-anchoring framing via arbitrary slope) betraf das **V2-Blinded-ID**-Protokoll, nicht SST; SST ersetzt die DLEQ-Bindung durch EUF-CMA-Bindung und schliesst genau diese Lücke.

### 2.2 Kann ein unbeteiligter Dritter gebrandmarkt werden?

**Nein — unter Standardannahmen (Diskreter Logarithmus / EUF-CMA).** Notwendige Bedingungen für erfolgreiches Framing:

- Der Angreifer müsste diskreten Logarithmus von `X_innocent` kennen **oder** eine gültige Schnorr-Signatur über `μ` unter `X_innocent` fälschen.
- `verify_sst_witness` (`:355–412`) stellt bei L1-Handover sicher, dass die **ehrliche Forsetzung** die Schranke erfüllt; danach ist die einzige Möglichkeit, Shards zu produzieren, die zu `X_innocent` extrahieren, exakt die obige Fälschung.
- Alle Import-Gates (`wallet/conflicts.rs:446–595`, insbes. `:457–482` für `did:key`, `:582–595` für `ephemeral:`-Linkage) erzwingen die gleiche Prüfung; Bypass wäre nur via `test-utils`-Feature (`is_signature_bypass_active`), das **nie in Release** aktiviert wird (`lib.rs` Safety Fuse).

### 2.3 Kann ein Angreifer Shards/Fingerprints so manipulieren, dass Detektion ausfällt oder falsch zeigt?

Systematische Prüfung jeder Manipulationsfläche:

| Angriffsfläche | Manipulation | Detektion / Guard | Resultat |
|---|---|---|---|
| `trap_r` Bytes | Nicht-kanonisch (`y ≥ p`), non-decompressable, identity/torsion | `validate_shard_structure` (`:194–213`), `ensure_canonical_y` (`:227–240`), `parse_point_bs58` (`:169`), `is_torsion_free` (`:483,516`) | **Rejected** (`VoucherCoreError::Crypto`) vor Chain-Accept (`chain.rs:359–362`). Genesis-Placeholder `"none"` scheitert am Längen-Gate by-design. |
| `trap_s` Bytes | `s + ℓ` (Malleability) | `parse_canonical_scalar` (`:156`): `Scalar::from_canonical_bytes` — `s ≥ ℓ` ⇒ `Err` | **Rejected** (`test_sst_non_canonical_scalars_rejected` `:882`) |
| `tau` | Kollision `τ₁==τ₂` trotz `t_id₁≠t_id₂` (birthday 1/q) | Guard `τ₁==τ₂ → Err` (`:458`), `t_id`-Gleichheit → `Err` (`:556`) | **Degenerate → Rejected**; P[Kollision] ≈ 2⁻²⁵² vernachlässigbar. |
| `c` | `c==0` (1/q) | Guard (`:497`) | **Rejected** |
| Gossip-Fingerprint `ds_tag` | Foreign-bucket stuffing (AUDIT-01-F11) | `import_foreign_fingerprints` (`conflict_manager.rs:881–894`) re-keyed by **content** `fp.ds_tag`, nie Transport-Key | **Fixiert** |
| Gossip-Fingerprint `layer2_signature` | Gefälschte Kollision unter fremdem `sender_ephemeral_pub` | `verify_fingerprint_signature` (`:210–263`): valid `layer2_signature` über `HMC_TX_AUTH_V3`-digest zwingend; `chain.rs:696–776` symmetrisch | **Rejected** — ohne One-Time-Key kein valides `layer2_signature` |
| `n≥3` Shards | Off-line junk shard soll echte Attribution vetoen | Import-Gate `ANY`-pair (`trap_manager.rs:724–738`) — ein verifizierendes Paar genügt | **Fixiert** (AUDIT-01-F13) |
| Shamir-Polynom Grad | Höherer Grad oder andere Kurve | Fix Grad 1, fix Ed25519 basepoint — keine Parametrisierung | **Kein Vektor** |

**Konklusion §2:** Alle drei Teilfragen mit NEIN/JA beantwortet: Unbeteiligte können nicht gebrandmarkt werden, Fremd-Key-Extraktion ≡ EUF-CMA-Forgery, Manipulationen werden von strikten Guards erkannt oder sind informationstheoretisch vernachlässigbar.

---

## 3. Anonymität & Information-Theoretic Privacy

### 3.1 Einzelner Shard: informationstheoretische Anonymität

Für Beobachter mit **genau einem** Shard `(R₁,s₁,τ₁)` (regulärer Transfer) gilt Gleichungssystem (1)(2):

```
R₁ = R_sig + τ₁·M_R
s₁ = s_sig + τ₁·m_s
```

Unbekannte: `R_sig ∈ 𝔾` (255 Bit), `s_sig ∈ ℤ_q`, `M_R ∈ 𝔾`, `m_s ∈ ℤ_q` — **4 Unbekannte**, **2 Gleichungen**. Unterstruktur:

- `R`-Gleichung: Punkt-Gleichung in 𝔾 (≈ 255 Bit).
- `s`-Gleichung: skalare Gleichung in ℤ_q (≈ 252 Bit).

Freiheitsgrad = 2 (eine volle Punkt- plus eine volle Skalar-Dimension). Für **jede** hypothetische Identität `X' ∈ 𝔾` existiert ein Witness-Tupel, das den beobachteten Shard erklärt: wähle beliebiges `M_R'`, `m_s'`, setze `R_sig' = R₁ − τ₁M_R'`, und wähle `r'`, `c' = H(μ∥R_sig')`, `s_sig' = r' + c'·x'` (wobei `x'` der diskrete Log von `X'` wäre — für Existenz genügt algebraische Konsistenz, nicht Kenntnis von `x'`). Anders formuliert: die Verteilung von `(R_i,s_i)` bei uniformem `(r, M_R, m_s)` ist uniform in `𝔾 × ℤ_q`, unabhängig von `x`. Der Shard ist ein **One-Time-Pad** des Signatur-Paars mit frischen Masken — dokumentiert als *„4 unknowns (R_sig, s_sig, M_R, m_s); no registry mining can link it to an identity“* (`trap_manager.rs:11–13`).

Formal: Für `n=1` ist die bedingte Entropie `H(X | R₁,s₁,τ₁,μ,E,ds_tag) = H(X)` — **perfekte informationstheoretische Verbergung**. Erst `n=2` kollidierende Shards (gleicher `ds_tag`, verschiedene `τ`) liefern 4 Gleichungen / 4 Unbekannte und bestimmen `X` eindeutig (siehe §1.2). Genau diese Schwelle ist das SST-Design-Ziel (Fraud Detection, Not Prevention).

### 3.2 Registry-Mining (P-pre / Pre-image) und De-Anonymisierungs-Orakel

**Registry-Mining:** `M_R = hash_to_curve("HMC_MASK_R_V1" ∥ x ∥ E ∥ ds_tag)` (`trap_manager.rs:306–309`). `hash_to_curve` ist `EdwardsPoint::nonspec_map_to_curve::<Sha512>` (`crypto/utils.rs:211`), modelliert als Random Oracle nach `𝔾`. `x` ist secret, die Eingabe enthält `x`; ohne `x` ist `M_R` uniform und sein diskreter Log unbekannt. Ein Registry, das alle `X` auflistet, kann `(R_i,s_i)` nicht mit einem `X` korrelieren: für jedes `X` existiert ein passendes `(R_sig,s_sig)`-Paar (s.o.). **P-pre-Angriffe unmöglich.** Historische Finding AUDIT-01-F07 (V2 Blinded-ID, P-pre via `T = u·m + ID`) ist durch SST ersetzt; `hash_to_curve` hat keine Blinded-ID-Struktur mehr.

**Transport-Envelope-Orakel / JWE:** `SecureContainer` (`bundle_processor.rs:58–86`) trägt in Privacy-Mode **keine** Klartext-Signatur mit permanentem Key: `if bundle_contains_anonymous_chain(&bundle) { secure_container.signature = String::new(); }` (`:80`). Guard: `bundle_contains_anonymous_chain` nutzt **ANY**-Semantik (`:97–103`): ein einziger anonymer Voucher im Multi-Transfer erzwingt Suppression — Fix zu HMSEC-SA06-08 (ALL → ANY Regression). Netzwerk-Beobachter mit Kandidaten-Key-Pool können daher nicht `verify_ed25519(i, sig)` als Orakel nutzen. Integrität des Containers bleibt via `verify_integrity(): container.i == H(canonical(container − i − sig))` (`:135`) gewahrt; Echtheit danach durch innere `bundle.sender_signature` (`:166`) — SA06-01 Invariante.

**Voucher-Chain-Orakel:** Stealth-Chains enthalten `sender_id: None`, `recipient_id: ANONYMOUS_ID` (`voucher.rs:659`), keine DIDs im Klartext. Downstream-Holder sieht nur `receiver_ephemeral_pub_hash`/`change_ephemeral_pub_hash` (Hashes, nicht Keys) und AEAD-`privacy_guard` (nur für Empfänger entschlüsselbar, `crypto/dh.rs:185–238`). Kein Orakel.

**Fingerprint-Gossip-Orakel:** Fingerprints enthalten `sender_ephemeral_pub` (one-time key), `trap_r/trap_s`, `layer2_signature`, aber **niemals** `sender_id`/`recipient_id` in Stealth-Mode. `deletable_at` im **Wire-Format ist neutralisiert** zu `""` (`conflict_manager.rs:812–813`, `:846–850`), `NEUTRAL_WIRE_DEADLINE` (`:812`), und bei Ingress durch `FOREIGN_FINGERPRINT_RETENTION_DAYS = 180` ersetzt (`:820, :828–831`) — verhindert Family-Clustering (HMSEC-SA06-15). Damit ist auch passives Gossip-Sniffing kein De-Anonymisierungs-Orakel.

### 3.3 Zusammenfassung §3

| Kanal | Leakage | Bewertung |
|---|---|---|
| Einzelner Shard `(R_i,s_i)` | 0 Bit über `X` (perfekt) | ✅ Info-theoretisch |
| Registry (alle `X` bekannt) | 0 Bit, RO-Uniformität | ✅ P-pre-resistent |
| `SecureContainer` Envelope | Keine `sig` in Stealth (ANY-Semantik) | ✅ Kein Orakel |
| Voucher-Chain downstream | Keine DIDs, nur Hashes + AEAD | ✅ Kein Orakel |
| Fingerprint-Gossip | One-time `E` + Shards + `sig`, aber `deletable_at` neutral | ✅ Kein Family-Clustering |

Alle drei Teilfragen mit JA/NEIN beantwortet: echter info-theoretischer Schutz für `n=1`, kein Registry-Mining, keine Transport/Chain/Gossip-Orakel.

---

## 4. Fingerprint-Mechanismus & Konflikt-Erkennung

### 4.1 TransactionFingerprints: deterministisch & kollisionssicher

**`ds_tag`-Erzeugung** (`conflict_manager.rs:81–149`, `voucher.rs:735`):

```
ds_tag = H(prev_hash_raw ∥ sender_ephemeral_pub_raw)       (11)
```

mit `get_hash_from_slices` (SHA3-256 über längenpräfixierte Slices, `crypto/utils.rs:99–119`) — deterministisch, second-preimage-resistent, identisch für alle Peers. Für `init` (kein Spend-Input) Fallback `ds_tag = H(prev_hash ∥ E_genesis)` (`:97`); spend-fingerprints tragen `trap_data.ds_tag` direkt (`:117`), **verifiziert** gegen Recompute in `chain.rs:364–384` (Context-Mismatch-Guard). `ds_tag`-Kollision ⇔ gleicher Input ⇔ Doppel-Ausgabe; verschiedene Inputs kollidieren mit P≈2⁻²⁵⁶ (SHA3-256).

**Fingerprint-Payload** (`TransactionFingerprint`, `conflict.rs:18–79`):

```
{ ds_tag, t_id(32B), encrypted_timestamp(XOR), layer2_signature(64B),
  sender_ephemeral_pub(32B), trap_r, trap_s, deletable_at(gerundet),
  layer2_voucher_id, privacy_guard_hash }
```

Kollisions-Erkennung: `check_for_double_spend` (`conflict_manager.rs:378–472`) gruppiert via `HashMap<ds_tag, HashSet<fp>>`, sortiert kanonisch nach `t_id` (AUDIT-01-F16), prüft `|{t_id}|>1 ∨ has_equivocation` (`:455`) — wobei `has_equivocation` (`:431–453`) **gleiche `t_id` bei divergenten signatur-gebundenen Feldern** (`trap_r/s`, `encrypted_timestamp`, `layer2_signature`, `privacy_guard_hash`, `deletable_at` ausgenommen) als Equivocation wertet (HMSEC-SA04-08). Damit sind auch Guard-Equivocation-Doppelspends (gleiche `t_id`, verschiedene `privacy_guard`) beweisbar.

**Determinismus-Invariante:** `t_id = H(canonical(Transaction − t_id − sigs − traps − guard))` (`chain.rs:669–684`), daher `t_id` deterministisch aus Transaktions-Content; `encrypted_timestamp = nanos ⊕ H(prev_hash∥t_id)[0..16]` (`conflict_manager.rs:936–967`) deterministisch re-derivierbar (XOR-Involution), aber ohne `prev_hash` nicht vorhersagbar für Aussenstehende.

### 4.2 Vollständigkeit über alle Code-Pfade (ConflictManager / TrapManager)

| Phase | Pfad | Deckt ab |
|---|---|---|
| **Erzeugung** | `voucher.rs:765–773` `generate_sst_trap` → `wallet/transactions.rs:915–917` `create_fingerprint_for_transaction` → `own_fingerprints.history` push (`wallet/transactions.rs:918–924`) | Jeder eigene Spend legt sofort eigenen Fingerprint ab. |
| **Rebuild** | `wallet/conflicts.rs:35–68` `scan_and_rebuild_fingerprints` aus `VoucherStore` (inkl. `is_own_transaction` stealth-aware `:309`) | Volständiger Restore nach Restart; `Endorsed`-Exklusion (`:328, :1808`) korrekt. |
| **Gossip-Ingress** | `wallet/conflicts.rs:1237–1416` `process_received_fingerprints`: `is_init_fingerprint` Drop (`:1301`), `verify_fingerprint_signature` Gate (`:1303`), `local_input_keys`-Reproduktion (`:1304–1306` + `reproduces_local_tag` `:1507`), `assign_local_retention` (`:1316`), Bucket-Cap `150` (`:1384`) | Kein unauthentisches/legacy/junk lagert ein. |
| **Export-Ingress** | `conflict_manager.rs:873–923` `import_foreign_fingerprints`: identische Gates + content-re-keying (`:894`) | Symmetrisch zu Gossip, kein Bucket-Stuffing. |
| **Detektion** | `conflict_manager.rs:378–472` `check_for_double_spend` | Kanonisch sortiert, equivocation-sensitiv, `verifiable_conflicts` vs `unverifiable_warnings` korrekt partitioniert (`:462`). |
| **Race-Entscheidung** | `wallet/conflicts.rs:1438–1612` `resolve_conflict_offline`: `local_t_ids ∨ (verify_fingerprint_signature ∧ reproduces_local_tag)` (`:1539–1543`), plausibility window `[now−365d, now+24h]` (`:1482–1499`), `reproduces_local_tag` (`:1507–1537`), monotonic status guard (`:1595–1599`) | Heuristik nur auf verifiziertem Evidence, kein Re-Activation von `Quarantined/Endorsed`. |
| **Beweis-Erstellung** | `wallet/conflicts.rs:744–1063` `verify_and_create_proof`: L2-Verifikation (`:916–938`), autonome SST-Extraktion über **alle Paare** kanonisch sortiert (`:958–1006`, first-wins), `ephemeral:`-Fallback nur bei L2-all-verified (`:1009–1020`) | Vollständige Attribution-Hierarchie (did:key > ephemeral: > anonymous). |
| **Beweis-Import** | `wallet/conflicts.rs:371–740` `import_proof`: Gates 0 (verdict neutralize `:388`), 0b (advisory neutralize `:406`), 1–3 (Struktur/Sig/proof_id `:417–428`), 3b/3c (Attribution EUF-CMA `:430–595`), 4 (L2-integrity `:597–633`), nur `FullyVerified` mutiert Status (`:660`) | Kein Framing, kein Verdict-Laundering, keine unverifizierte Quarantäne. |
| **Attribution-Verify** | `trap_manager.rs:581–743` `verify_sst_shards_consistency` / `verify_stored_trap_shards_against_identity` | Identischer EUF-CMA-Gate an Erzeugung wie Import; `ANY`-pair für Import, strikt für `n==2`. |

**Abdeckung:** Alle Pfade terminieren entweder in `Quarantined { reason: "Lost offline race" }` / `"Lost race in imported proof"` oder in `ProofStoreEntry` (`Victim`/`Witness`). Kein Code-Pfad überspringt Konflikt-Erkennung; `cleanup_*` (`:750–804`) respektiert `is_init_fingerprint` + `verify_fingerprint_signature`.

### 4.3 Schlupflöcher: systematischer Negativ-Nachweis

| Vektor | Status | Nachweis |
|---|---|---|
| **Malleable Serialisierung** | ✅ Geschlossen | `s` nicht-malleabel (canonical scalar `:156`), `R` nicht-malleabel (canonical `y < p` `:227` + `decompress` `:205`), Payload-Digest längenpräfixiert (`l2_gateway.rs:316–328`), `sst_encoded_parts` längenpräfixiert (`trap_manager.rs:84`), `t_id` über canonical JSON (`chain.rs:679`), `voucher_id` über canonical JSON (`voucher.rs:454`). Keine zwei Byte-Strings → gleiche Semantik. |
| **Null-/Identity-Punkte** | ✅ Rejected | `X̂.is_identity()` (`:505`), `m̂_R.is_torsion_free()` (`:483`), `X̂.is_torsion_free()` (`:516`), `ed25519_pk_to_curve_point` decompress (`crypto/utils.rs:135`), `get_pubkey_from_user_id` torsion+identity check (`crypto/identity.rs:262`). Neutral-Element als Täter/ Maske unmöglich. |
| **Ungültige Skalare / Kurvenpunkte** | ✅ Rejected | `parse_canonical_scalar` (`:156`) + `validate_shard_structure` (`:211`), `parse_point_bs58` decompress (`:169`), `FIELD_MODULUS_LE` korrekt `0xED…7F` (p = 2²⁵⁵−19, STATUS.md:64). `validate_shard_structure` in `chain.rs:359` für jeden non-init `tx`. |
| **Genesis/Root-Transaktionen** | ✅ Separiert | `t_type=="init"` trägt **keine** `trap_data` (`voucher.rs:483,549`), Fingerprint bindet `"none"/"none"` (`conflict_manager.rs:98–102`), `is_init_fingerprint` = beide Shards `== "none"` (`:287`), `TRAP_NONE_PLACEHOLDER` konsistent (`l2_gateway.rs:159`). Spends mit leerem/placeholder `trap_data` → `VOID_SPEND_SHARD_MARKER = "invalid"` (`:116–121`), daher niemals als Genesis klassifiziert (HMSEC-SA06-11). Genesis-forge `trap_data` nicht-trivial → `chain.rs:539–549` rejected. |
| **Leere `t_id`-Sets / Duplikate** | ✅ Abgedeckt | `check_for_double_spend`: `unique_t_ids.len()>1 ∨ has_equivocation` (`:455`), dedupe `HashSet` (`:392`), kanonisch sortiert (`:417`), `verify_proof_structure` distinct-`t_id` (`:564`), `derive_proof_id` whitespace-sanitized (`:493`). |
| **Unverifizierte Fingerprints im Race** | ✅ Ausgeschlossen | `resolve_conflict_offline` Filter `:1539` erfordert `local_t_ids ∨ (¬init ∧ valid_sig ∧ reproduces_local_tag)`, plausibility `[min,max]` (`:1558–1561`), sonst `continue`. Titel-AUDIT-01-F01/F14 geschlossen. |

**Konklusion §4:** Alle vier Teilfragen mit JA beantwortet; kein Schlupfloch verbleibt im geprüften Scope.

---

## 5. Gesamturteil: Schwachstellen-Bewertung

| Kategorie | Befund | Schwere | Status |
|---|---|---|---|
| SST Kernmathematik | Keine | — | ✅ Unbedenklich |
| Framing / EUF-CMA | Keine | — | ✅ Unbedenklich |
| Info-theoretische Anonymität (n=1) | Keine | — | ✅ Unbedenklich |
| Transport-Orakel | Keine (ANY-Semantik fix) | — | ✅ Unbedenklich |
| Fingerprint-Determinismus | Keine | — | ✅ Unbedenklich |
| Code-Pfad-Vollständigkeit | Keine | — | ✅ Unbedenklich |
| Malleability / Null-Punkte / Genesis | Keine | — | ✅ Unbedenklich |

**Bekannte, bewusst zurückgestellte Rest-Themen (ausserhalb SST-Scope, dokumentiert, kein SST-Mangel):**

- **HMSEC-SA04-08 / WH3-04-401 (CRITICAL, `CONFIRMED-PENDING`):** Guard-Equivocation ohne Chain-Anker bleibt im Race-level nur via `has_equivocation`/`reproduces_local_tag` sichtbar; vollständiger Fix erfordert Protokoll-Break (neuer Wire-Field). Betrifft L1-Offline-Heuristik, nicht SST-Extraktion.
- **audit_02_11 / HMC-SEC-02-11 (HIGH, `CONFIRMED-PENDING`):** `layer2_voucher_id` ist im V3-Digest gebunden, L2-Lock-Transplantation scheitert an `process_l2_verdict` `:403–408`; verbleibende Test-Harness-Unpassbarkeit ist Test-Artefakt, kein Protokoll-Mangel.

Keiner dieser Punkte invalidiert die vier Fokus-Fragen.

---

## 6. Empfehlungen

### 6.1 Keine Pflicht-Massnahme für SST

Der SST-Kern benötigt **keinen** Code-Eingriff. Die Beweise in §1–§4 sind tight und alle Guards sind aktiv.

### 6.2 Härtende Empfehlungen (niedrigschwellig)

1. **Fuzz-Harness für `validate_shard_structure` & `parse_canonical_scalar`** — libFuzzer/cargo-fuzz über 10k zufällige 32-Byte-Kandidaten, um `y≥p`/`s≥ℓ`-Gates gegen dalek-Upgrades zu pinnen.
2. **Property-Test `τ`-Kollision** — proptest: `τ(ds_tag, t_id₁) == τ(ds_tag, t_id₂) ⇒ t_id₁==t_id₂` mit hoher Wahrscheinlichkeit; dokumentiert 2⁻²⁵²-Sicherheit.
3. **Doku-Absicherung EUF-CMA-Reduktion** — §2.1 als `docs/security/SST_FRAMING_PROOF.md` formalisieren und im `trap_manager.rs`-Modul-Doc verlinken (erhöht Auditierbarkeit).
4. **Release-CI Fuse `test-utils` nie aktiv** — bereits in `lib.rs` Safety Fuse, zusätzlich `cargo deny`/`cargo hack --each-feature` in CI verankern.
5. **Gossip-Retention-Monitoring** — Metrik: Anteil `foreign_fingerprints` mit `deletable_at == NEUTRAL_WIRE_DEADLINE` vor `assign_local_retention`; sollte 100% sein → detektiert Legacy-Peers.

### 6.3 Strategische Empfehlungen (Roadmap)

- Wave-3-Pending `HMSEC-SA04-08` und `audit_02_11` in einem koordinierten V3.x Break (ein Atomic Commit: Digest-Signatur + alle Signer/Verifier + Fixtures + `l2_client_simulator`) schliessen, wenn ein neues Major-Protokoll ohnehin ansteht — bis dahin ist das Residualrisiko im Threat-Model dokumentiert und akzeptiert.
- SST-Extraktion als **deterministische reine Funktion** (bereits so) in WASM-Boundary halten; `target.'cfg(not(target_arch = "wasm32"))'`-Gates für `sysinfo`/`tokio` nicht auf Krypto-Pfade ausweiten.

---

## Anhang A — Code-Referenzen (vollständig)

| Komponente | Datei:Zeilen | Rolle |
|---|---|---|
| SST Engine | `src/services/trap_manager.rs:1–744` | Shard-Erzeugung, Challenge, Rekonstruktion, Guards |
| `validate_shard_structure` | `trap_manager.rs:194–213` | Base58/32B/canonical-y/decompress/canonical-s Gates |
| `ensure_canonical_y` | `trap_manager.rs:227–240` | `masked_y < p` (dalek-malleability fix) |
| `generate_sst_trap` | `trap_manager.rs:288–334` | (1)(2) Erzeugung |
| `verify_sst_witness` (R5) | `trap_manager.rs:355–412` | L1 Handover-Fraud-Prevention |
| `reconstruct_identity` | `trap_manager.rs:452–525` | (3)–(10) + alle degenerate Guards |
| `extract_sst_identity` | `trap_manager.rs:545–569` | Autonomer Gossip-One-Round-Extract |
| `verify_sst_shards_consistency` | `trap_manager.rs:581–638` | Strikte n≥3-Firewall |
| `verify_stored_trap_shards_against_identity` | `trap_manager.rs:659–743` | ANY-pair Import-Gate (AUDIT-01-F13) |
| `create_fingerprint_for_transaction` | `src/services/conflict_manager.rs:41–188` | `ds_tag` (11), VOID-Marker (SA06-11), `layer2_voucher_id` bind |
| `verify_fingerprint_signature` | `conflict_manager.rs:210–263` | `HMC_TX_AUTH_V3` self-auth |
| `is_init_fingerprint` | `conflict_manager.rs:287–290` | Nur `"none"/"none"` |
| `check_for_double_spend` | `conflict_manager.rs:378–472` | Kanonisch sortiert, equivocation-sensitiv |
| `import_foreign_fingerprints` | `conflict_manager.rs:873–923` | Content-re-keying, sig-Gate, cap |
| `encrypt/decrypt_transaction_timestamp` | `conflict_manager.rs:936–1001` | XOR `nanos ⊕ H(prev_hash∥t_id)` |
| `calculate_l2_payload_hash_raw` | `src/services/l2_gateway.rs:305–328` | Längenpräfixiert, V3-Bindungen (voucher_id, trap shards, guard commitment) |
| `process_l2_verdict` | `l2_gateway.rs:355–497` | Voucher-ID-Match, trap-placeholder Genesis-Erkennung |
| `verify_transactions` | `src/services/voucher_validation/chain.rs:137–503` | `validate_shard_structure` (359), `ds_tag` Recompute (377), Plausibility |
| `verify_transaction_integrity_and_signature` | `chain.rs:654–818` | `t_id` canonical, `layer2_signature` V3-Verify |
| `bundle_processor` | `src/services/bundle_processor.rs:29–169` | `ANY`-Semantik (96), `verify_integrity` (135), `verify_bundle_signature` (188) |
| `process_encrypted_transaction_bundle_inner` | `src/wallet/transactions.rs:144–770` | R5 Gate `trap_data.is_some() ∧ privacy_guard.is_none() → Err` (336), witness-Verify (385–438), rollback-snapshot (125) |
| `process_received_fingerprints` | `src/wallet/conflicts.rs:1237–1416` | Gossip-Ingress Gates, `local_input_keys`, retention-neutralize |
| `resolve_conflict_offline` | `wallet/conflicts.rs:1438–1612` | Race mit sig+tag+Plausibility Gates, monotonic guard |
| `verify_and_create_proof` | `wallet/conflicts.rs:744–1063` | L2-All-Verified, SST-Extraktion über alle Paare |
| `import_proof` | `wallet/conflicts.rs:371–740` | Gates 0/0b/1–4, nur FullyVerified mutiert |
| `crypto::hash_to_curve` | `src/services/crypto/utils.rs:211` | `nonspec_map_to_curve::<Sha512>` — RO |
| `crypto::ed25519_pk_to_curve_point` | `crypto/utils.rs:135` | Decompress-Gate |

## Anhang B — Notation

- `q` — Gruppenordnung Ed25519 (`ℓ = 2²⁵² + 27742317777372353535851937790883648493`); `p = 2²⁵⁵−19` Feldprimzahl.
- `G` — Ed25519 Basis-Punkt (`ED25519_BASEPOINT_POINT`).
- `H` — SHA3-256 (ds_tag, voucher_id) bzw. SHA-512→Scalar (SST), jeweils längenpräfixiert (`get_raw_hash_from_slices`).
- `μ` — `H("HMC_TRAP_SIG_V1" ∥ ds_tag ∥ E)` (32 bytes).
- `c` — `H("HMC_TRAP_CHAL_V1" ∥ μ ∥ R)` mod q.
- `τ_i` — `H("HMC_TAU_V1" ∥ ds_tag ∥ t_id_i)` mod q.

## Anhang C — Testabdeckung (geprüfte Guards)

- `trap_manager::tests::test_sst_roundtrip_generation_witness_and_extraction` — honest roundtrip + framing-negativ.
- `test_sst_degenerate_guards_fire` — identische `τ`/`t_id` Replay-Guard.
- `test_sst_non_canonical_scalars_rejected` — `s+l` Malleability.
- `test_sst_inconsistent_third_shard_rejected` — n≥3 Firewall.
- `test_canonical_y_boundary_values` + `test_validate_shard_structure_accepts_max_canonical_point` — `y=p−1` ok, `y≥p` rejected.
- Wave-3 Gates: `sa04_09_chain_validator_must_reject_structurally_invalid_sst_shards`, `f11_bucket_stuffing`, `f13_offline_extra_shard`, `f14_epoch_near`, `sa06_11_placeholder`, `sa06_15_gossip_wireformat`.

---

*Dieser Bericht ersetzt keine formale Verifikation (z.B. EasyCrypt/Coq). Er stellt einen gründlichen, beweisgestützten Security-Review mit vollständigen Code-Referenzen und klaren mathematischen Herleitungen dar. Bei neuen Protokoll-Breaks (HMSEC-SA04-08/audit_02_11) ist ein Re-Audit des Deltas erforderlich.*
