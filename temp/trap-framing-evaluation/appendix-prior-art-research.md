# Appendix S1 — Prior-Art-Recherche (Subagent, 2026-08-25)

> Rohbericht des Recherche-Unteragenten. [V] = aus Quellen verifiziert, [I] = Inferenz/Synthese.

## Annotated Bibliography

**Chaum–Fiat–Naor, "Untraceable Electronic Cash," CRYPTO'88** — [PDF](https://www.cise.ufl.edu/~nemo/anonymity/papers/chaum_fiat_naor_ecash.pdf); walkthrough: [Finney](https://fennetic.net/pub/finney.org/~hal/chcash2.html)
Cut-and-choose RSA cash: coin = Π g(xᵢ,yᵢ)^{1/3}, with xᵢ=f(aᵢ), yᵢ=f(aᵢ ⊕ ⟨info⟩). Each spend reveals, per index i, either aᵢ or aᵢ⊕⟨info⟩ (merchant's random bit challenge); **two colliding spends XOR-reveal the account identity** with prob. 1−2^{−k/2}. **[V]** Maps: reveal-on-collision ✓ (probabilistic), framing ✓ (bank cut-and-chooses candidates so ⟨info⟩ is genuine), single-output ZK ✗, ≤192B ✗✗. Requires **bank** — not issuerless. **[V]**

**Brands, "Untraceable Off-line Cash in Wallets with Observers," CRYPTO'93** — [PDF](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM219/2009/Brands.Untraceable_off-line_cash.1993.pdf); algebra walk-through: [Grabbe 1997](https://www.orlingrabbe.com/stefbrdc.htm)
Restricted-blind-Schnorr cash. Payment (exact equations, **[V]**): payer sends (A,B,sign(A,B)); verifier challenge d=H₀(A,B,IS,time); payer answers **r₁=d·u₁s+x₁, r₂=d·s+x₂ (mod q)**; check g^{r₁}g^{r₂}=A^dB. Double-show with d≠d′ on the *same* coin:
**(r₁−r₁′)/(r₂−r₂′) = u₁ mod q** — "two points determine a line; the slope is the user's secret key." **[V]**
Framing fails because u₁ = log_{g₁}(I) where I is the **issuer-certified** account key bound into the coin by restrictive blinding; producing two valid response sets on one coin proves knowledge of u₁ (special soundness). Brands also offers "unconditional protection against framing" as an extension **[V]**. Caveat: Brands' blind-signature unforgeability lacks a clean RO proof ([eprint 2012/197](https://eprint.iacr.org/2012/197.pdf)) **[V]**. Requires issuer at withdrawal. **[V]**

**Franklin–Yung, ICALP'93 / Frankel–Tsiounis–Yung ASIACRYPT'96 ("Indirect Discourse Proofs")** — [refs](https://research.google/pubs/secure-and-efficient-off-line-digital-money-extended-abstract/)
Fair e-cash: identity **verifiably encrypted to a trustee** inside each coin; double-spend hands the bank two shares enabling decryption. Same family as PVSS-share e-cash (payment returns polynomial share q(ch)=id+a·ch+b·ch²; two challenges interpolate id). Autonomous reveal ✗ (trustee needed); sizes ✗. Issuer mandatory.

**Fujisaki–Suzuki, "Traceable Ring Signature," PKC'07** — [eprint 2006/389](https://eprint.iacr.org/2006/389)
Ring signature with tag L=(issue, pk_N); Trace on two signatures w.r.t. same issue: different messages → **outputs signer's pk**; formalizes **exculpability** (= our framing-immunity requirement) **[V]**. **No issuer, no group manager** — P2P-compatible **[V]**. Size O(N) group elements (~96B·N on Curve25519) — blows 192B budget unless rings are tiny.

**Liu et al., "TRS Revisited," 2025** — [eprint 2025/1807](https://eprint.iacr.org/2025/1807); **One-time TRS**, [eprint 2021/1054](https://eprint.iacr.org/2021/1054.pdf)
Modern TRS: per-event pseudo-identity pid₁=F_sk(e‖1), pid₂=F_sk(e‖2)+m·pk → **O(1) tracing: pk=(pid₂−pid₂′)/(m−m′)** — literally the slope-extraction algebra, issuerless, extended exculpability proofs **[V]**. Bulletproofs instantiation still >192B for meaningful rings **[V]**.

**CryptoNote/Monero key images (bLSAG/CLSAG)** — [MRL-0003](https://www.getmonero.org/resources/research-lab/pubs/MRL-0003.pdf)
I = x·H_p(P): collision **detection only**, never identifies offender ("It will not identify the misbehaving user") **[V]**. The weaker sibling of our requirement.

**Adaptor signatures** — Aumayr et al. ASIACRYPT'21; Gerhart et al., [eprint 2024/1809](https://eprint.iacr.org/2024/1809); Dai et al., [eprint 2022/1687](https://eprint.iacr.org/2022/1687)
Pre-signature σ̃ hides σ; adapting adds witness t; **Extract(t) = σ − σ̃** — "pre-signed disclosure" **[V]**. Gerhart et al.: schemes where any pair of pre-signatures on same message reveal the full signature exist (recognized construction pattern). Dai et al. formally define **unlinkability of adaptor outputs against key-guessing** — nearest formal treatment of our membership-test concern **[V]**. Size fits budget **[V/I]**.

**Threshold Schnorr: FROST (RFC 9591), MuSig2 (BIP327), MuSig-DN** — [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
Share sᵢ = hiding + binding·ρ + λᵢ·skᵢ·c combine into one signature **[V]**. Hazards: deterministic nonces permit complete key recovery in multi-party settings; MuSig-DN exists because RFC-6979-style derandomization breaks under adversarial context; partial-nonce-pair reuse enables forgery **[V]**.

**Nonce-bias literature** — Tibouchi ECC'17 ([slides](https://ecc2017.cs.ru.nl/slides/ecc2017-tibouchi.pdf)), LadderLeak lineage
Biased/non-uniform Schnorr nonces → lattice/Bleichenbacher-FFT attacks; the latter tolerates arbitrarily small bias given enough signatures **[V]**.

**Camenisch–Shoup verifiable encryption, CRYPTO'03** — [paper](https://www.shoup.net/papers/verenc.pdf)
Paillier/DCR-based VE of DLs; ciphertexts ≥256B plus Σ-proofs (KB-scale); DL-segmented ElGamal+Bulletproofs alternatives also KB-scale. Does not fit ≤192B. **[V/I]**

**BLS verifiably encrypted signatures** — BGLS [aggreg.pdf](https://crypto.stanford.edu/~dabo/papers/aggreg.pdf)
VES ~48-96B + adjudicator infra — but trusted adjudicator + pairing-friendly curves required. **[V/I]**

**Near-miss systems (2020-2026):** IBM CBDC offline payments ([eprint 2024/1746](https://eprint.iacr.org/2024/1746)): auditors decrypt payer IDs, framing fixed via payee-supplied randomness **[V]**; Digital-euro thesis ([arXiv 2407.13776](https://arxiv.org/html/2407.13776)) needs TTP **[V]**; Transferable e-cash w/o TTP ([eprint 2020/1400](https://eprint.iacr.org/2020/1400)) — issuer still mints **[V]**; Bloom-filter ad-hoc double-spend gossip ([SN CS 2026](https://link.springer.com/article/10.1007/s42979-026-05259-z)) — detection only **[V]**.

## Key Formulas

| # | Formula | Source |
|---|---------|--------|
| 1 | CFN: yᵢ = f(aᵢ ⊕ ⟨info⟩); two shows ⇒ ⟨info⟩ = aᵢ ⊕ (aᵢ⊕⟨info⟩) | CFN'88 |
| 2 | Brands payment: r₁ = d·u₁·s + x₁, r₂ = d·s + x₂ | Brands'93 |
| 3 | Brands double-show: **u₁ = (r₁−r₁′)/(r₂−r₂′)** | Grabbe/Brands |
| 4 | Generic extraction: **sk = ((z₁−z₂)G − (R₁−R₂))·(c₁−c₂)^{−1}** | Bellare–Dai [2020/416](https://eprint.iacr.org/2020/416.pdf); [Tomescu](https://alinush.github.io/schnorr) |
| 5 | FS07/'25 trace: pk = (pid₂−pid₂′)(m−m′)^{−1} | eprint 2025/1807 |
| 6 | Membership test: z·G ?= R + c·X_candidate | Tomescu **[V]** |
| 7 | Adaptor: t = σ − σ̃ | 2024/1809 |

## Direct Hits?

**None exist.** No published system combines all four properties: *issuerless* + *collision-triggered public-key disclosure* + *framing immunity* + *≤192B* (Suchstand 2026-08). Every classical solution anchors identity in an issuer-certified account value or trustee-held encryption; every issuerless mechanism detects-but-doesn't-attribute or exceeds the byte budget.

## Verdict Snippet

Closest primitive family: **traceable one-show credentials à la FS07 in the degenerate "ring-of-one" case** — algebraically identical to Brands'/CFN two-show identification transplanted to an issuerless setting, with the issuer's certification role replaced by creation-time binding at L1 handover. Main flagged risk: static transcripts leak membership tests against candidate key dictionaries.
