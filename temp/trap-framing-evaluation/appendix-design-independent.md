# Appendix S3 — Unabhängiger Design-Entwurf (Subagent, 2026-08-25)

> Rohbericht (gekürzt um Wiederholungen; vollständige Fassung in der Session-Historie). Zentrale Originaleiträge: Trilemma-Theorem, Konstruktion A′, E1 als Lehrstück.

## 0. Zentrale Randbedingung

Beide kollidierenden Fingerprints entstehen unabhängig, offline, evtl. Monate auseinander — gemeinsame Geheimnisse nur `(x, ds_tag)`. Alles, was beide Shards zur Erzeugungszeit benötigt (z.B. `c=H(R₁‖R₂‖μ)`), ist unbrauchbar. Jede Verifikations-Eingabe muss öffentlicher Fingerprint-Feldinhalt sein.

## 1. Trilemma-Theorem

**Autonomy ∧ Frame-Immunity ∧ Single-Fingerprint-Unlinkability — pick 2** (für affine Open + offline witnesses):

1. Kein effizientes öffentliches Einzel-Shard-Prädikat `ShardCheck(fp,X)` ⇒ `Open(fp1,fp2)=X_v` ist lösbares lineares System ⇒ **R3 failt**.
2. Existiert solch ein deterministisches Prädikat mit Vollständigkeit 1 ⇒ es IST ein perfekter Membership-Test gegen jede enumerierbare Registry ⇒ **R1-strikt failt**.

Korollar: R1-strikt ∧ R5 nicht gemeinsam erfüllbar in-band. Ship-fähige Kombination: R1′ (Test existiert, aber nur gegen konkret enumerierte Kandidaten gefährlich) + R5 interaktiv. „Zero-knowledge can hide the *witness*, but a published verifiable trap is a *statement*, and statements about X are always decidable against a guessed X."

Wichtige Unterscheidung: **simulatable ≠ unlinkable.** Ein Schnorr-Transcript ist HVZK-simulierbar für gewähltes X′, aber ein gegebenes Transcript pinnt sein X über die Verifikationsgleichung — genau 1 perfektes Prädikat-Bit pro geratenem Schlüssel.

## 3. Construction A′ — Two-Show Response, Recipient-Challenged, Derived Nonces (Empfehlung des Agenten)

Felder: `R_i = r_i·G`, `z_i = r_i + c_i·x`, `ρ_i` (Empfänger-Challenge), sig_e über alles.
`c_i = H("hmc-trap-a1" ‖ ds_tag ‖ t_id_i ‖ enc(R_i) ‖ enc(ρ_i))`; `r_i = SHA-512(ed25519_prefix(x)‖ds_tag‖t_id_i) mod q`.

Erzeugung: Sender schickt R_i → Empfänger antwortet frisch ρ_i → Sender liefert (z_i,ρ_i) → Empfänger prüft `z_i·G ?= R_i + c_i·X_payer` (echte Schnorr-Identifikation, Special Soundness ohne ROM).

Öffnung: `X* = (c_i−c_j)^{-1}·[(z_i−z_j)·G − (R_i−R_j)]`, dann ∀m: `z_m·G ?= R_m + c_m·X*` (Pflicht).

Bytes: 96 B raw / ≈150 B JSON (ρ auf 16 B kürzbar → ≈131 B).

R1: nur R1′ (P-pre testbar). R3: Framing-Pfade = DL oder RO-Fixed-Point (`R^{(k+1)} = zG − H(··‖R^{(k)})·X_v`, Random Walk, Θ(q)); Formalbound via Forking Lemma `≤ 2q_H/q`. carried-not-recomputed cᵢ ⇒ Framing kostenlos (V-1). Phantom-Spends → Selbst-Doxxing des Angreifers.

Degenerate Cases: c_i=c_j-Guard; r-reuse across inputs katastrophal/global (HNP); Ristretto255 statt Raw-Edwards; n≥3 pairwise-init + verify-all.

## 4. Construction B′ — Shared Deterministic Challenge

`c = H("hmc-trap-b1" ‖ ds_tag ‖ ρ)`; shard i: `(R_i, z_i=r_i+c·x)`; Öffnung `X*=(n·c)^{-1}(Σz_iG − ΣR_i)`.
Seed-(b)-Original (`c=H(R₁‖R₂‖μ)`) disqualified: nicht stateless erzeugbar (Kausalität).
Verdict: viable runner-up, strikt dominiert von A′ (korrelierte Challenges, n-sensitivere Öffnung).

## 5. Construction C — Pseudonym-Shard `p=H(x‖ds_tag)`

Extraktion → Pseudonym P=p·G; R1 fast strikt (Pseudonym-Raum unenumerierbar), aber R2-strikt failt: Eskalation P→X nie autonom. Encrypted-Confession-Paradox: K=H(P) von allen ableitbar (→ sofortige Offenlegung); K=H(p) von niemandem (→ keine Öffnung). Strukturell inkompetent für R2; nützlich als Privacy-Fallback-Modus.

## 6. Construction D — Camenisch–Shoup VE: Feasibility Kill

≥2048-bit Moduli, CT ≈ 1 kB + NIZK mehrere hundert B + Committee-Key ≥512 B/decrypter. ≥5–10× over budget. Reductio: self-certifying shards sind der einzige effiziente Weg.

## 7. Construction E1/E2

**E1 FI-bound Pedersen Share:** `C_i = X + γ_i·H_pt`, Öffnung `(ΣC_i − (Σγ_i)H_pt)/n`. R1-strikt perfekt (perfect hiding) UND R3 gratis gebrochen: Angreifer assembliert `C_i := X_v + γ_iH_pt` direkt — Kommitment-Konstruktion ist dlog-frei. **Pedagogisch wertvoll:** isoliert, warum Response-Form funktioniert (Maske in Skalargleichung → Fremdziel braucht x_v) vs Kommitment-Form (Maske in Assembly-Rezept → braucht nichts).

**E2 Adaptor/DLEQ-Chain:** `z_i = r_i + c_i·x + τ_i·e` → Zeugen sehen {x,e} mit zwei Gleichungen + Nonce-Unbekannte → unterbestimmt; e-Freigabe bräuchte disc(E)=DL. Toter Zweig.

## 8. Ranking

A′ > B′ > E1 > C > D. Ship A′ (unter der Prämisse des Agenten, dass R1-strikt aufgeben akzeptabel ist).

## 9. Finale Antwort (wörtlich)

> **Is R1-strict jointly satisfiable with R5? No — provably, for any scheme with affine/public extraction and offline witnesses.** Escape hatches cost 5–50× the budget. The trilemma admits only two legs at this budget. Ship the weakened conjunction R1′ ∧ R5: the test exists, but is only as dangerous as the adversary's ability to enumerate candidate did:keys — a systemic privacy parameter (per-context subkeys, key rotation), not a cryptographic one.

Residual risks: Shor, malicious nonce bias (self-harming), gossip-layer enumeration (governance), canonicalization defects, adjudication nodes skipping cᵢ-recomputation (die einzelne sicherheitskritischste Implementierungsinvariante).
