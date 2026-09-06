# Appendix S4/S5 — Archiv der extern eingereichten Analysen (2026-08-25)

> Archiviert als Quellenmaterial; leichte Kürzungen um Redundanzen, alle Konstruktionsmathematik und Urteile unverändert.

---

## Teil A (S4): "Cryptographic Design of Autonomous Framing-Resistant Identity Extraction for P2P Offline Vouchers" — Empfehlung: Candidate E

### Kontext & Axiom
Offline-P2P-e-cash über Ristretto255 (q ≈ 2²⁵²). Akteure: Langzeit-(x,X) = did:key; Eingabe-Ephemeral (e,E); `ds_tag=H(prev_hash∥E)`; Double-Spend ⟺ gleicher ds_tag, verschiedene t_id.

**Fundamental Theorem of Point-Based Malleability:** Jede affine Punkttransformation `V_i = c_i·M + X` ist framable: Beobachtung eines legitimen Shard genügt (`M ← c₁⁻¹(V₁−X_v)`), um `V₂ = c₂·M + X_v` zu schmieden; oder komplett freie Assemblierung mit M_fake. **Axiom:** Traps müssen im Skalarfeld operieren; X muss so verborgen bleiben, dass Blinding nur via algebraische Intersection zweier Shards auflösbar ist.

### Candidate A: Independent Two-Show Schnorr Trap
`r=H(dom‖x‖ds_tag)` deterministisch ⇒ R₁=R₂=R; `c_i=H(dom‖ds_tag‖t_id_i‖R)`; `z_i=r+c_i·x`. Extraktion `x*=(z₁−z₂)(c₁−c₂)⁻¹` → **extrahiert den geheimen Skalar x** ("identity burning", nuclear option). 64 B. HVZK-Simulator existiert. Framing: z₂ = z₁−x_v(c₁−c₂) benötigt x_v → DL-hard.

### Candidate B: 2-of-2 Additive Splitting
c = H(R₁+R₂‖μ) erfordert R₂ bei Erzeugung von z₁ — **Causality Paradox**: offline/asynchron nicht vorhersehbar → verworfen.

### Candidate C: BLS Multiplicative Sharing
σ=σ₁+σ₂; Verifikation via Pairing e(σ,G₂)=e(H₁(ds_tag),X). σ_i uniform (perfektes R1), aber **keine deterministische Extraktion von X** (Pairing-Inversion hard → Brute-Force über Registry). Pairing-Curves widersprechen dalek-Constraint → verworfen.

### Candidate D: Feldman VSS + R5-Semantic-Limit
Polynom f(y)=x+a·y; Shards s_i=f(H(t_id_i)); C₀=X, C₁=a·G. Interpolation rekonstruiert x.
**Theorem (Simulator-Limit):** Semantische Verifizierbarkeit eines ZK-Traps („öffnet zu gültiger Identität") ohne Identity-Oracle ist unmöglich: ZK ⇒ Simulator/garbage-keypair kann perfektes π_fake liefern; Verifier ohne Anker an X kann ehrliches Trap nicht von Wegwerf-Trap unterscheiden. R5 impliziert maximal strukturelle soundness. Auflösung: out-of-band am L1-Handover (Payee sieht X direkt).

### Candidate E: Ephemeral-Bound Encrypted Disclosure (Empfehlung)
```
k    = H_q(domain_blind ∥ x ∥ ds_tag)          // blinding scalar
K    = k·G                                      // L1-Anker, NUR an Payee, nie gossip
c_i  = H_q(domain_trap ∥ ds_tag ∥ t_id_i)
s_i  = x + k·c_i   (mod q)                      // EINZIGER Gossip-Zusatz: 32 Byte!
```
Extraktion: `k* = (s₁−s₂)(c₁−c₂)^{-1}`, dann `x* = s₁ − k*·c₁`, `X* = x*·G`.
R1: informationstheoretisch (Zeile mit zwei Unbekannten x,k; für jedes x′ existiert passendes k′).
R2: zwei Skalar-Subtraktionen + Inversion — deterministisch.
R3 [im Original: „benötigt k"] — siehe Korrektur in AUSWERTUNG §6.5: korrekt ist Exponent-Hiding (Ziel x_V nur als Punkt öffentlich; skalare Zielgleichung ohne Zahlwert unlösbar; gemischte authentische Shards → affines Gemisch ≠ x_V).
R5: Payee prüft `s_i·G ≟ X + c_i·K`.
R6: ds_tag kapselt E; separater Ephemeral-Key ändert ds_tag → neue Input-Verifikation scheitert.

**Matrix (Original):** E gewinnt alle sechs Kriterien (32 B „theoretical minimum payload"); Empfehlung: E für Produktion.

---

## Teil B (S5): Design & Analysis mit drei Konstruktionen — Empfehlung: Construction 2

### Preliminaries
Framing-Imunität erfordert, dass R2 einen **non-repudiable proof of guilt** extrahiert — eine gültige Signatur von X, die sich an E/ds_tag bindet. Seed (b) (combined challenge) ist mit zusteloser Offline-Erzeugung inkompatibel.

### Construction 1: Standard Schnorr Trapdoor (= Direkt-Shard)
`(R_i=r_i·G, z_i=r_i+c_i·x)`, `r_i=H(x‖ds_tag‖t_id_i)`, `c_i=H(dom‖E‖ds_tag‖t_id_i‖R_i)`; layer2 signiert beide Felder; 64 B.
R2 ✔ `X̂=(c₁−c₂)^{-1}[(z₁−z₂)G−(R₁−R₂)]`. R3 ✔ (gültige Schnorr-Gleichung unter X; Fälschung = DL). R5 ✔ nativ `z_iG≟R_i+c_iX`. **R1 ✘ FAILS**: c_i öffentlich rekompunierbar → Membership-Test gegen Registry ("perfectly simulatable, but trivially linkable").

### Construction 2: Secret-Shared Signature („Untestable Trapdoor") — EMPFEHLUNG
Setup (nicht gossipiert): Schnorr-Signatur von X auf E: `R_sig=r·G` mit `r=H(x‖E‖"sig")`; `c=H(dom‖E‖R_sig)`; `s_sig=r+c·x`.
Masken: `M_R=H_point(x‖E‖"mask_R")`, `m_s=H_scalar(x‖E‖"mask_s")`.
Shard i (gossipiert, 64 B): `R_i=R_sig+t_id_i·M_R`, `s_i=s_sig+t_id_i·m_s`.
Öffnung: `M_R=(t₁−t₂)^{-1}(R₁−R₂)`, `m_s` analog; `R_sig=R₁−t₁M_R`, `s_sig=s₁−t₁m_s`; `c=H(dom‖E‖R_sig)`; `X=c^{-1}(s_sigG−R_sig)`.
R1 **PERFECT**: uniform maskierte Punkte/Skalare; für jedes X_guess existiert erklärendes (M_R,m_s); exakt 0 Shannon-Bits; kein Membership-Test möglich.
R3: Output ist gültige Schnorr-Signatur von X auf E → Fälschung reduziert auf DL/EUF-CMA.
R5: Sender übergibt `(R_sig,s_sig,M_R,m_s)` off-chain an Empfänger; dieser verifiziert Signatur + Zeilenzugehörigkeit der Shards. 0 Gossip-Bytes.

### Construction 3: Ephemeral Extraction + Encrypted Confession
Erzwinge Nonce-Wiederverwendung der layer2-Signaturen (`k=H(x‖E‖"nonce")`, `R_fix=k·G` identisch über Spends) → Kollision leakt `e=(s₁−s₂)/(c₁−c₂)`; Confession `P=(X‖R_sig‖s_sig)` (96 B) XOR-verschlüsselt unter `K_enc=H_kdf(e‖ds_tag)`; Felder `R_fix(32)+s_i(32)+C(96)=160 B ≤192`.
R1 perfekt (e verborgen bis Kollision). R2 autonom nach e-Leak. R3: CT garantiert gültige Signatur von X auf E. R5 △: Off-chain-NIZK nötig (Bulletproof/DLEQ-Kette), dass R_fix deterministisch und C wohlgeformt.

### Degenerate Cases (alle)
c₁=c₂ ⇔ t_id-Kollision (RO-negligible; t_id sollte Empfänger-Pubkey inkorporieren); Kofaktor via Ristretto255 eliminiert; Mutation durch layer2-Signatur-Coverage verhindert; n≥3: beliebige 2 von n Shards rekonstruieren.

### Fundamental Theorem: R1 vs R5 Joint Satisfiability
**Conditional Impossibility:** Ist R5 *solely* über broadcast F erfüllt, existiert öffentliches V(X,F); jeder Drittpartei kann V(X_guess,F) auswerten → strikte R1 und in-band-R5 schließen sich gegenseitig aus.
**Resolution:** gemeinsam erfüllbar iff R5 den P2P-Charakter nutzt: Hilfsdaten W (Masken bzw. NIZK) über **off-chain privaten Kanal** an Empfänger; dieser evaluiert V(X,F,W); nur F wird gossipiert → perfektes R1 + erfülltes R5.

### Ranking (Original)
1. **Construction 2 — RECOMMENDED FOR PRODUCTION** (64 B, perfektes R1, absolute Framing-Immunität durch Standard-Schnorr-Ausgang, keine NIZKs).
2. Construction 3 (konzeptionell sauber, aber 160 B + off-chain-NIZK).
3. Construction 1 (einfachste Implementierung; nur wenn Registry-Anonymität unnötig).
