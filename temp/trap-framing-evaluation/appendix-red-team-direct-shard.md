# Appendix S2 — Red-Team-Bericht: Direktes Shard-Schema (Subagent, 2026-08-25)

> Rohbericht des Adversarial-Agents gegen das "Collision-Triggered Two-Show Attribution Trap" `(R_i, z_i=r_i+c_i·x)`. Diese Befunde wurden in der Auswertung auf alle Kandidaten gemappt; Schweregrade teils relativiert ([KORREKTUR-S2] in AUSWERTUNG.md).

## 0. Notation & Kernfakt

Extraktion: `z₁ − z₂ = (r₁ − r₂) + (c₁ − c₂)·x` ⟹ `X* = [(z₁−z₂)·G − (R₁−R₂)] · (c₁−c₂)⁻¹`

**Key inversion:** für **jeden** Zielpunkt T ist die Paar-Constraint `Δz·G − ΔR = Δc·T` erfüllbar durch `R₁ := Δz·G − Δc·T + R₂` — ohne dlog(T). Einzig die Hash-Rekomputation `cᵢ ≟ H("chal" ‖ μᵢ ‖ Rᵢ)` erzeugt einen Fixed Point mit Kosten ~2^|c|. **Challenge width = framing security.**

## 1. Verdict-Tabelle

| # | Claim | Verdict | Decisive attack |
|---|-------|---------|-----------------|
| P1 | Single-fingerprint ZK | **BROKEN in deployment** | V-2 dictionary linkability: `z·G ≟ R + c·X_suspect` ist öffentlicher O(1)-Test pro Kandidaten-did:key |
| P2 | Autonomous opening | **BROKEN vs adversaries, holds vs honest mistakes** | V-3 identical-shard/torsion evasion → X* = ∯ |
| P3 | Framing immunity | **CONDITIONAL — broken as specified** | V-1 rogue-key pair forgery (Spec ließ Witness-cᵢ-Rekomputation weg) |
| P4 | Compactness | HOLDS | 64 B core |
| P5 | Creation-time verification | CONDITIONAL | Sound iff V-1-Fix + subgroup checks |
| P6 | Robustness | PARTIAL | V-4 nonce reuse = silent global doxxing + HNP |

## 2. Vulnerabilities

### V-1 — CRITICAL: Framing via unverifizierte Challenge-Derivation
Ohne Witness-seitige Rekompuation von cᵢ: wähle beliebige c₁≠c₂, z₁,z₂,R₂ und setze `R₁ := (z₁−z₂)·G − (c₁−c₂)·X_v + R₂` → Extraktion exakt X_v, beide layer2-Signaturen gültig (eigener e), echter Double-Spend des eigenen Vouchers. Variante mit gestohlenem authentischen Opfer-Shard analog. **Fix:** verpflichtende Rekompuation `cᵢ ≟ H(...)` → Forgery wird RO-Fixed-Point ≈ 2^250.

### V-2 — HIGH: Dictionary-Linkability (P1 failt gegen enumerierte Identitäten)
Ehrliches Transcript erfüllt `z·G = R + c·X_true`; für jeden Kandidaten X_s ist der Test öffentlich (1 Skalarmult). Gegen enumerierbare did:key-Registry: perfekte Diskriminierung → permanente globale Deanonymisierung normaler Zahlungen. OTP/Simulierbarkeitsargument gilt nur gegen Beobachter **ohne** Kandidatenschlüssel. Fixes: (a) Pseudonym-Shards, (b) verifiable encryption, (c) Privacy-Claim explizit absenken.

### V-3 — HIGH: Voluntary evasion
Betrüger publiziert identische (R,z) in beiden Fingerprints → Δz=ΔR=0 → X* = ∯/undefiniert → „unattributable-malicious" statt Namensnennung. Mit Raw Ed25519 zusätzlich Torsion T an R₂ → X* verlässt Prime-Order-Gruppe (CryptoNote-Key-Image-Präzedenz). **Mitigation (partiell):** identische Shard-Paare als eigene `evasion-attempt`-Klasse; Post-Shard-Checks `zᵢ·G ≟ Rᵢ + cᵢ·X*`; Ristretto255 erzwingen. Evasion bleibt freiwillig — kann nicht erzwungen werden.

### V-4 — HIGH: Nonce reuse / bias
r₁=r₂ über zwei beliebige Inputs ⇒ `z₁−z₂=(c₁−c₂)x` → jeder Beobachter rekonstruiert x global, ohne Double-Spend. Bereits Bias/Partial-Leakage ⇒ Hidden Number Problem (Lattice/Fourier; LadderLeak: <1 bit Leakage ausreichend). Deterministisches `r=H(x‖μ)` sicher iff Domänenseparation exakt und μ alles Eindeutige enthält.

### V-5 — MEDIUM: Burner-key laundering / rogue registration
Ehrliche Shards unter frisch registriertem X_m → Attribution nennt Wegwerfidentität. Rogue-Key-Lektion: ohne PoP beweist Extraktion nur „Inhaber des Trap-Keys". Governance: PoP bei Registrierung, Key-Age, Stakes.

### V-6 — MEDIUM: n ≥ 3 Inconsistency poisoning
Crafted Multi-Shows erlauben widersprüchliche Paar-Extraktionen → Vertrauensgift. Regel: kanonisch sortierte Shardliste, Einstimmigkeit aller Paare, sonst `malicious-inconsistent`.

### V-7 — MEDIUM: Anchor-Hazards (Pedersen C)
β-reuse ⇒ `C₁−C₂ = ∯` = Gratis-Linkage-Oracle; Receipt-Leakage = Consent-Act dokumentieren; Subgroup-Konsistenz (Torsion erlaubt 8-fache Equivocation); C muss unter layer2-Signatur stehen.

### V-8 — LOW/MEDIUM: Evidence lifetime
Timing von Show #2 kurz nach deletable_at von Show #1 ⇒ Attribution verfällt. Regel: ds_tag-Index bis `max(deletable_at)+Grace`.

### V-9 — INFO
~6% relative c-bias bei mod-q-Trunkierung harmlos (sauberer: ≥512-bit Hash); kanonische Skalare erzwingen (sonst Dual-Encoding z/z+q); Cross-Protokoll-Nonce-Hygiene; Quantum: keine neue Exposition.

## 3. Challenge-Varianten

- **Shared c=H(R₁‖R₂‖…):** stitch-proof & kompakter, aber asymmetrisch (Fp #1 kann vor Spend #2 nicht vollständig sein) — verletzt zustelose Erzeugung.
- **Independent cᵢ=H(μᵢ‖Rᵢ):** stateless/symmetrisch; Replay-Schutz NUR wenn Witnesses rekompunieren.
- **Best of both:** paar-kontextgebundene Challenges `cᵢ = H(μ₁‖μ₂‖R₁‖R₂‖i)` mit kanonischer Sortierung — committet jeden Shard an den Partner.

## 4. Normative MUSTs (MUST-Liste)

1. ristretto255 überall; sonst non-canonical/identity/[ℓ]P≠∯-Rejects.
2. Kanonische Little-Endian-Skalare; z ≥ q reject; Challenge ≥250 bit Entropie.
3. Witness-Pipeline: (a) layer2-Sig über exakte Bytes; (b) μᵢ rekompunieren; (c) cᵢ rekompunieren+vergleichen; (d) Subgroup/Kanonität; (e) erst dann Extraktion. Failure ⇒ `invalid-shard`.
4. Signatur-Coverage: ds_tag, t_id, timestamps, E, Rᵢ, zᵢ, optionales Cᵢ + Versionstag.
5. Nonces fresh/uniform oder deterministisch domänensepariert; NEVER reuse; fail-closed bei lokalem Reuse-Detekt.
6. Preconditions: equal ds_tag; distinct t_id; identical shards = evasion-class; c₁≠c₂.
7. Post-extraction: X* canonical/prime-order/non-identity; Re-Verify je Shard; n≥3 unanimity.
8. β fresh/single-use; (β,C) sensitiv.
9. Versionierte Domänenseparation für jede Hash-Rolle.
10. Registry-PoP; nur prime-order Keys.
11. Retention-Regel (V-8).
12. Negative Testvektoren (proptest): non-canonical, low-order, identical shards, replayed foreign shards, c-mismatch, c₁=c₂, n-way inconsistency, Framing nach V-1.

## 5. Empfohlene Alternativen

(a) **Trap streichen, beweisbares Artefakt bestrafen** (ephemeral-Attribution + UTXO-Lineage-Blacklist/Bounty) — löscht V-1..V-4, deckungsgleich mit „fraud detection, not prevention".
(b) **Verifiable encryption**, falls nicht-evadable Attribution Hard-Requirement ist (Camenisch–Shoup, ~300–600 B) — einzige Konstruktion, die P2 gegen Angreifer wahr macht.
(c) **Harden + Pseudonym-Mode** als Mittelweg.
