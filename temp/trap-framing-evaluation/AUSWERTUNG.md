# Auswertung — Autonome & fälschungssichere Täter-Enttarnung via Lightweight-Gossip

**Stand:** 2026-08-25 · **Status:** Analyse abgeschlossen, Implementierung offen
**Anlass:** Framing-Gefahr bei der did:key-Enttarnung aus kollidierenden `TransactionFingerprint`s (vgl. Audit-Befund H-01-01, `temp/security-hypotheses/module-01.md`: „Trap-Anchoring-Framing — beliebiger Slope m").

---

## 0. Methodik & Quellen

Diese Auswertung synthetisiert **fünf unabhängige Analysen** plus eigene Verifikation:

| # | Quelle | Inhalt |
|---|--------|--------|
| S1 | Subagent: Prior-Art-Recherche (`appendix-prior-art-research.md`) | Chaum–Fiat–Naor, Brands, Franklin–Yung, Traceable Ring Signatures, Adaptor Signatures, FROST/MuSig2, Nonce-Bias-Literatur |
| S2 | Subagent: Red-Team gegen direktes Shard-Schema (`appendix-red-team-direct-shard.md`) | 9 Schwachstellen (V-1…V-9) inkl. kritischer Framing-Umgehung ohne Challenge-Rekomputation |
| S3 | Subagent: unabhängiger Lösungsentwurf (`appendix-design-independent.md`) | Trilemma-Theorem, Konstruktionen A′/B′/C/D/E1/E2 |
| S4 | Externe Analyse #1 (`appendix-external-analyses.md`, Teil A) | Candidate A–E; Empfehlung „Ephemeral-Bound Encrypted Disclosure" (32 B, extrahiert Skalar x) |
| S5 | Externe Analyse #2 (`appendix-external-analyses.md`, Teil B) | Constructions 1–3; Empfehlung „Secret-Shared Signature" (64 B); Unmöglichkeitsbeweis R1∧R5-in-band |

Alle Konstruktionen wurden anschließend manuell gegengeprüft (Abschnitte 6–7). Zwei Korrekturen gegenüber den Quellen sind markiert: **[KORREKTUR-S4]** (Framing-Begründung Candidate E) und **[KORREKTUR-S2]** (Schweregradeinordnung V-1/V-3).

---

## 1. Ergebnis in einem Satz

**Beweist (konstruktiv):** Die Anforderungen R1–R5 sind auf Ed25519/Ristretto255 mit ≤ 192 Byte Overhead **gemeinsam erfüllbar** — empfohlen wird der *Shared-Signature Trap* (SST, Abschnitt 5) mit **64 Byte** Gossip-Overhead, informationstheoretischer Anonymität pro Einzelfingerprint und EUF-CMA-reduzierter Framing-Immunität.
**Beweist (Unmöglichkeit):** R1-strikt (kein effizienter Kandidaten-Schlüssel-Test) und **in-band**-R5 (öffentliche Prüfbarkeit am Einzelfingerprint) sind unvereinbar; auflösbar genau dadurch, dass R5 — wie in der Aufgabenstellung definiert — über den **privaten L1-Übergabekanal** erfolgt (Abschnitt 6.4).

---

## 2. Drei Prädikate — die zentrale begriffliche Klärung

Die Verwirrung mehrerer Vorstudien (inkl. des Status quo) lässt sich auflösen, indem man **zwei verschiedene Verifikationsprädikate** saubertrennt:

| Prädikat | Wirkung | Erwünscht? |
|---|---|---|
| **P-pre:** `V(F_einzeln, X_guess) → {0,1}` — Einzelfingerprint testbar gegen Kandidaten-Schlüssel | Dictionary-/Registry-Angriff: jeder Beobachter kann jeden Fingerprint gegen enumerierte did:keys testen | **Nein** (zerstört R1) |
| **P-post:** `Verify(Extract(F_1,F_2), X) → {0,1}` — rekonstruierter Beweis erst nach Kollision prüfbar | Framing-Schutz: Fälschung des Beweises unter fremdem X = Signaturfälschung | **Ja** (ist R3) |

**Warum der Status quo beides verfehlt:** Die Baseline `V_i = u_i·M + X` hat weder P-pre (gut! zwei Unbekannte m,x → unterbestimmt → perfekte Anonymität) noch P-post (fatal! Der extrahierte Punkt X ist *selbst* der „Beweis"; es existiert kein separates Prüfobjekt → beliebige Slopes framden frei, exakt H-01-01).

**Designprinzip (aus S2/S3/S5 konsistent):**
> Framing-Immunität erfordert, dass die Zielidentität im Constraint-System des Angreifers **ausschließlich im Exponenten** auftritt (Skalar-Response-Form `z = r + c·x` bzw. geteilte Signatur), niemals als direkt manipulierbarer Gruppenpunkt (Kommitment-Form `V = u·M + X`).
> Anonymität erfordert, dass der Einzelfingerprint **unterbestimmt** bleibt (≥ 2 Geheimnisse pro Gleichung), damit P-pre nicht existiert.

Der Shared-Signature Trap erfüllt beide Bedingungen gleichzeitig: P-pre unmöglich (Zeile mit 4 Unbekannten), P-post vorhanden (vollständige Schnorr-Signatur als Rekonstrukt).

---

## 3. Das Trilemma (formal, konsolidiert aus S3 §9 und S5 Teil B)

**Theorem (Trilemma).** Sei die Extraktionsfunktion `Open` affin in den Fingerprint-Feldern (für alle budgetfähigen algebraischen Kandidaten erfüllt) und seien Zeugen offline. Dann gelten paarweise nicht alle drei:

1. **Autonome Extraktion** (R2),
2. **Framing-Immunität** (R3) gegen einen Angreifer, der beide Shards kontrolliert,
3. **Strikte Einzel-Unlinkability** (R1-strikt: kein effizientes P-pre).

*Beweisskizze:* Fehlt jedes öffentliche Einzel-Prädikat, ist `Open(F_1,F_2)=X_Ziel` ein kleines lineares System mit freien Variablen → R3 bricht (außer die Zielidentität kommt nur im Exponenten vor, siehe Abschnitt 2 — genau das ist der Konstruktionsausweg). Existiert das Einzel-Prädikat mit Vollständigkeit 1 auf ehrlichen Shards, ist es zugleich ein perfekter Membership-Test gegen enumerierbare Registries → R1-strikt bricht. ∎

**Auflösung:** R5 wird — der Aufgabenstellung folgend („Empfänger muss **bei der Übergabe (L1)** sicherstellen") — **out-of-band** über den physischen Transaktionskontakt realisiert. Damit bleiben alle fünf Anforderungen erfüllbar: R1-strikt im Gossip, R5 privat zwischen Sender und Empfänger.

---

## 4. Konstruktionsübersicht

| Konstruktion | Overhead | R1 (Einzelfp.) | R2 autonom | R3 framing-fest | R5 (L1) | Urteil |
|---|---|---|---|---|---|---|
| Baseline `V=u·M+X` (Status quo) | 64 B | ✔ perfekt | ✔ | ✘ **framable** (H-01-01) | ✘ | zu ersetzen |
| Direkt-Shard `(R,z)` (S2/S5-C1/S3-A′) | 64–96 B | ◑ computational, **P-pre-testbar** | ✔ | ✔ (mit MUST-Pflichten) | ✔ nativ `zG≟R+cX` | Fallback (einfachste Implementierung) |
| **Shared-Signature Trap (S5-C2, gehärtet)** | **64 B** | ✔✔ **perfekt (info-th.)** | ✔ | ✔ EUF-CMA | ✔ via private W | **EMPFEHLUNG** |
| Candidate E `s=x+k·c` (S4) | **32 B** | ✔ perfekt | ✔ | ✔ (aber: brennt **x**, siehe 6.5) | ✔ via privates K | Alternative (Sanktions-Hardmode) |
| Encrypted Confession (S5-C3) | 160 B | ✔ perfekt | ✔ | ✔ | △ NIZK nötig | machbar, Komplexität/Risiko hoch |
| 2-of-2 kombinierte Signatur `c=H(R₁‖R₂)` | – | – | ✘ Kausalitätsparadox (R₂ unbekannt bei Spend #1) | – | – | verworfen (alle Quellen) |
| BLS multiplikativ gesplittet | 96 B | ✔ | ✘ keine determinische Extraktion (Paaring-Inversion) | ✔ | △ | verworfen (neue Curve-Dep) |
| Feldman-VSS einer Signatur (roh) | >128 B | ✔ | ✔ | △ | ✘ semantische Vorab-Prüfung grundsätzlich unmöglich | geht in SST auf |
| Verifiable Encryption (Camenisch–Shoup) | ≥ 1 kB | ✔ | ✔ (Committee) | ✔ | ✔ | ≫ Budget, verworfen |

---

## 5. Empfohlenes Finaldesign: **Shared-Signature Trap (SST)**

Grundlage: S5 Construction 2, gehärtet mit den normativen Pflichten aus S2 (Abschnitt 7) und der Signaturbindung aus der eigenen Gegenprüfung. Gruppe: **ristretto255** (primer Ordnung q ≈ 2²⁵², kofaktorfrei), Basispunkt G, Hashes SHA-512 mit Domänenseparation, Skalare kanonisch Little-Endian mod q.

Notation: Langzeitschlüssel `(x, X = x·G)` (= did:key), Eingabe-Ephemeralschlüssel `(e, E = e·G)`, `ds_tag = H(prev_hash ‖ E)`, Transaktions-IDs `t_id_i`.

### 5.1 Trap-Erzeugung (bei jeder Transaktionserstellung)

Der Sender erzeugt **einmal pro Voucher-Eingabe** ein vollständiges, gültiges Schnorr-Signaturpaar σ und teilt es per Grad-1-Polynomial über die Spend-Instanzen:

```
μ      = H("HMC_TRAP_SIG_V1" ‖ ds_tag ‖ enc(E) ‖ prev_hash)     // Bindung an Input + ephemeral key
r      = SHA-512("HMC_TRAP_NONCE_V1" ‖ enc(x) ‖ μ) mod q         // deterministisch, nie RNG-abhängig
R_sig  = r · G
c      = H("HMC_TRAP_CHAL_V1" ‖ μ ‖ enc(R_sig)) mod q            // volle Breite, ≥250 bit Entropie
s_sig  = r + c·x  (mod q)
                                        // (R_sig, s_sig) ist eine reguläre Schnorr-Signatur von x über μ

M_R    = hash_to_ristretto("HMC_MASK_R_V1" ‖ enc(x) ‖ enc(E) ‖ ds_tag)   // Steigung (Punkt-Komponente)
m_s    = H("HMC_MASK_S_V1"  ‖ enc(x) ‖ enc(E) ‖ ds_tag) mod q            // Steigung (Skalar-Komponente)
```

Pro Spend-Instanz i:

```
τ_i    = H("HMC_TAU_V1" ‖ ds_tag ‖ t_id_i) mod q                 // Auswertestelle, öffentlich ableitbar
R_i    = R_sig + τ_i · M_R        (Punktaddition in ristretto255)
s_i    = s_sig + τ_i · m_s        (mod q)
```

Eigenschaften der Erzeugung: deterministisch (keine RNG-Fehlerklasse), zustelos pro Spend (beide Spends nutzen dasselbe σ, dieselben Steigungen — Kausalitätsproblem von Construction B entfällt), `τ_1 ≠ τ_2` folgt aus `t_id_1 ≠ t_id_2` (RO; trotzdem guarden).

### 5.2 Was genau im `TransactionFingerprint` steht

```rust
pub struct TransactionFingerprint {
    // --- Bestand (unverändert) ---
    pub ds_tag: String,
    pub t_id: String,
    pub encrypted_timestamp: u128,
    pub deletable_at: String,
    pub sender_ephemeral_pub: String,     // E
    pub layer2_signature: String,         // Ed25519 unter e über den KANONISCHEN Digest ALLER Felder
    // --- NEU (ersetzen u/blinded_id; serde(default) für Migration, Versionstag im Digest) ---
    #[serde(default)] pub trap_r: [u8; 32],   // R_i  (32 B)
    #[serde(default)] pub trap_s: [u8; 32],   // s_i  (32 B)
}
```

**Overhead im Gossip: 64 Byte** (Budget ≤ 192 B, Reserve 128 B). Die layer2-Signatur **muss** `trap_r`, `trap_s` und einen Format-Versionstag abdecken → Drittparteien können nichts mutieren, Splicing über Inputs bricht die Signatur. `u`/`blinded_id` entfallen (Migration: Felder deprecated, Extraktionslogik versioniert schalten).

### 5.3 Verifikation des direkten Empfängers (L1-Übergabe, R5)

Beim physischen/virtuellen Zahlungsakt übergibt der Sender zusätzlich (**nur privat, nie gossip**):

```
W = (R_sig, s_sig, M_R, m_s)      // 4 × 32 B = 128 B
```

Empfänger prüft:
1. **Semantik:** `(R_sig, s_sig)` ist gültige Schnorr-Signatur unter dem ihm bekannten/anzeigen Payer-did:key `X_payer` über μ (Neuberechnung aus ds_tag, E, prev_hash des übergebenen Gutscheins). → verankert den Trap an der echten Identität.
2. **Struktur:** `R_i ≟ R_sig + τ_i·M_R` **und** `s_i ≟ s_sig + τ_i·m_s` für den im Fingerprint transportierten Shard. → garantiert, dass jede spätere Kollision exakt dieses σ rekonstruiert.

Bei Verletzung: Zahlung verweigern. Ein Betrüger kann sich damit **nicht** hinter Mülldaten verstecken (R5 erfüllt). Hinweis: `W` ist pro Eingabe spezifisch und linkt den Empfänger an genau diese Transaktion — Behandlungsrichtlinie: `W` als sensitiv einstufen (Leak von W = Offenlegung der Payer-Identität für diesen einen Input, kein Schlüsselmaterial).

### 5.4 Extraktion & Verifikation bei Kollision (Gossip, autonom)

Witness empfängt `F_1, F_2` mit gleichem `ds_tag`, `t_id_1 ≠ t_id_2`, beide layer2-Signaturen gültig (existierende Quarantäne-Pipeline unverändert davor/danach):

```
// Normative Reihenfolge (jede Verletzung ⇒ Klasse invalid-shard, NIEMALS Attribution):
1. layer2-Signaturen über kanonische Bytes prüfen (existierende HMC_TX_AUTH_V2-Logik, erweitert)
2. τ_i aus (ds_tag, t_id_i) rekompunieren; GUARD: τ_1 ≠ τ_2
3. Kanonität: trap_r dekomprimiert (ristretto255, kein Identity), trap_s < q kanonisch
4. GUARD (Evasion): (R_1,s_1) == (R_2,s_2) ⇒ Klasse evasion-attempt (absichtlich identische Shards)
5. Rekonstruktion:
     M̂_R = (R_1 − R_2) · (τ_1 − τ_2)^{-1}          (Skalar-Inverse mod q)
     m̂_s = (s_1 − s_2) · (τ_1 − τ_2)^{-1}
     R̂   = R_1 − τ_1 · M̂_R
     ŝ   = s_1 − τ_1 · m̂_s                          // (R̂, ŝ) = rekonstruierte „Geständnis-Signatur"
6. c = H(...μ ‖ enc(R̂));  X̂ = (ŝ·G − R̂) · c^{-1}    // Signaturverifikation UND Identitätsextraktion in einem Schritt
   GUARD: c ≠ 0, X̂ prime-order, X̂ ≠ identity
7. did:key(X̂) im Web of Trust auflösen:
     gefunden  ⇒ offender_id = did:key(X̂)  (volle Stufe, nicht mehr suspected_identity)
     nicht gefunden ⇒ Klasse unattributable-malicious (Attributierung bleibt ephemeral:<E>)
8. Post-Check je Shard (optional, hart empfohlen): R_i ≟ R̂ + τ_i·M̂_R ∧ s_i ≟ ŝ + τ_i·m̂_s
9. n ≥ 3 Spends: Paarweise Extraktion über kanonisch sortierte Shardliste; EINSTIMMIGKEIT
   aller Paare erforderlich, sonst Klasse malicious-inconsistent (niemals strittigen Namen senden)
10. proof_id/De-Duplikation wie bisher über (ds_tag, fork_point) — Replays echter Kollisionen sind idempotent
```

---

## 6. Sicherheitsbeweise

### 6.1 Framing-Immunität (Kernauftrag)

**Satz (Framing-Freiheit des SST).** Seien die Challenges H als Random Oracles mit Ausgabe ≥ 250 bit modelliert und sei DL in ristretto255 schwer. Für jeden PPT-Angreifer A, der den Opfer-Öffentlichschlüssel `X_V` (nicht `x_V`) kennt, eigenen Schlüsselmaterial besitzt (`x_B, e_B`) und zwei mit `e_B` gültig signierte Fingerprints ausgibt (gleicher ds_tag, `τ_1≠τ_2`), sodass Schritt 6 akzeptiert und `did:key(X̂) = X_V` liefert, gilt:

```
Pr[A frame] ≤ Adv^{EUF-CMA}_{Schnorr}(A) + 2·q_H² / 2^250  + negl()
```

*Beweis.* Akzeptanz in Schritt 6 bedeutet: `ŝ·G = R̂ + c·X_V` mit `c = H(μ_B ‖ R̂)`, wobei `μ_B` den **ds_tag und E des Angreifers** enthält — d. h. `(R̂, ŝ)` ist eine gültige Schnorr-Signatur von `X_V` über die Nachricht `μ_B`.

- **Fall 1 — Fälschung aus eigenen Bauteilen:** A kontrolliert Steigungen `M_R, m_s` frei, also ist `(R̂, ŝ)` ein von A gewähltes Objekt. Jede solche Ausgabe ist unmittelbar eine Schnorr-Fälschung unter `X_V` auf neue Nachricht `μ_B` → Umbruch zum EUF-CMA-Angreifer (Standard-Forking-Argument gibt den Term `2q_H²/q`). Entscheidend: A kann die Punktgleichung nicht „zusammenbauen", weil `X_V` nur als Punkt, nie als Skalar in seine Kontrolle gelangt (Kontrast zur Baseline: dort war `V := u·M_fake + X_V` punktweise konstruierbar ohne dlog — genau die Lücke aus H-01-01).
- **Fall 2 — Replay eines authentischen Opfer-σ:** Ein beobachtetes echtes `σ_V` gilt nur unter `μ_V ⊇ (ds_tag_V, E_V)`. Im Kontext des Angreifers wird `c = H(μ_B ‖ R̂)` gerechnet; da `ds_tag_B ≠ ds_tag_V` (A besitzt neither prev_hash-Kette noch `e_V`), schlägt die Verifikation deterministisch fehl. Um signieren zu können, müsste A neu unterschreiben = Fall 1.
- **Fall 3 — Grinding:** Variation von `t_id`/`τ` ändert nur affine Koeffizienten der Rekonstruktion; die Zielpunktgleichung enthält `X_V` ausschließlich im Exponenten. Das Erzwingen eines RO-Fixed-Point (`R̂` von `c` abhängig und umgekehrt) kostet Θ(2²⁵⁵)-artig; berücksichtigt im Term `2q_H²/2^250`. ∎

**Korollar (Shard-Mixing).** Mischt A einen authentischen Opfer-Shard in einen eigenen Slot, rekonstruiert Schritt 5 eine affine Mischung zweier verschiedener Zeilen → ungültige Signatur → Klasse *invalid-shard/unattributable*, niemals Attribution. Kopiert A beide Opfer-Shards, reproduziert er exakt deren wahre, bereits registrierte Kollision (idempotent, dedupliziert über proof_id) — kein neues Framing-Objekt.

### 6.2 Zero-Knowledge pro Einzelfingerprint (R1) — informationstheoretisch

Ein Shard `(R_i, s_i)` ist eine Zeilenauswertung an `τ_i` mit vier Unbekannten `(R_sig, s_sig, M_R, m_s)`. Für **jede** Hypothese `X'` existieren gleichverteilt viele konsistente Vier-Tupel; formal ist `(R_i, s_i)` als (uniformes σ) + (uniforme Maske) statistisch unabhängig von `X`. Es existiert **kein** P-pre-Prädikat (Abschnitt 2) — selbst ein Beobachter mit komplettem Registry-Dump erhält 0 Shannon-Bits pro Fingerprint. Mehrfach-Shards desselben Wallets über verschiedene Inputs sind pairwise-unabhängig (frische Masken je ds_tag) → kein Akkumulationsangriff (OTP-Argument, vgl. S2/V-4-Analyse). **Abgrenzung:** Genau hierin liegt der Vorsprung gegenüber dem Direkt-Shard `(R,z)`, dessen Gleichung `z·G ≟ R + c·X_guess` ein perfektes Testprädikat gegen enumerierte Schlüssel darstellt (S2/V-2, S3 §1: „simulatable ≠ unlinkable").

### 6.3 Autonome deterministische Öffnung (R2)

Schritte 5–6 benötigen ausschließlich Feldinhalte beider Fingerprints + öffentliche Ableitungen; Kosten: 2 Skalarinversionen, ~6 Skalarmultiplikationen, 2 Hashes — Millisekundenbereich, kein Nachladen von Transaktionsketten. Determinismus: korrekte, L1-verifizierte Traps öffnen **immer** zu `(σ, X)` (Konstruktion garantiert Kolinearität).

### 6.4 Unmöglichkeits-Theorem: striktes R1 ∧ in-band-R5

**Satz.** Existiert ein öffentlicher, deterministischer, effizienter Algorithmus `V(F, X) → {0,1}` mit Vollständigkeit 1 auf allen ehrlichen Einzelfingerprints bzgl. ihres wahren `X` und Ablehnungswahrscheinlichkeit ≥ 1−q⁻¹ sonst, so ist `V` ein effizienter Membership-Test und strikte R1 gegen enumerierbare Schlüsselmengen ist verletzt. Umgekehrt impliziert die Abwesenheit eines solchen Prädikats bei affinem `Open` Frambarkeit, außer die Zielidentität tritt nur im Exponenten auf. Folgerung: R5 muss out-of-band (privater L1-Kanal) oder als reine Post-Kollisionsprüfung (P-post) realisiert werden. ∎ *(Konsistent hergeleitet in S3 §9, S5 Teil B „Fundamental Theorem", S2 §1 — drei unabhängige Argumentationen, kein Widerspruch in allen Quellen.)*

Damit ist die Aufgabenstellung **positiv beantwortet**: Ihre Definition von R5 („Empfänger … bei der Übergabe (L1)") ist bereits die out-of-band-Variante — der SST füllt sie konkret aus.

### 6.5 Alternative: Candidate E (S4) und das Exponent-Hiding-Lemma — mit Korrektur

**Konstruktion (S4):** `k = H(x ‖ ds_tag)`, Shard = reiner Skalar `s_i = x + k·c_i` (32 B), L1-Anker `K = k·G` (privat), Empfänger prüft `s_i·G ≟ X + c_i·K`; Extraktion `k* = Δs/Δc`, `x* = s_1 − k*·c_1`.

**[KORREKTUR-S4]** Die Framing-Begründung in S4 („Angreifer benötigt k") ist unvollständig. Der korrekte Grund:

**Lemma (Exponent-Hiding).** Die Extraktion ist affin in den publizierten Skalaren: `x* = α·s_1 + β·s_2` mit öffentlichen α,β. Ein Angreifer, der beide Shards wählt, kann die skalare Zielgleichung `x* = Z` daher **immer** linear lösen — aber der Zielwert ist hier die **Zahl** `x_V`, die öffentlich nur als Punkt `X_V = x_V·G` existiert. Ohne `dlog(X_V)` ist die Gleichung im Skalarfeld unlösbar; gemischte/geraubte authentische Shards liefern affines Gemisch ≠ `x_V`. R3 hält somit — aber aus dem in Abschnitt 2 formulierten Exponenten-Prinzip. ∎

**Bewertung Candidate E:** R1 perfekt (Zwei-Unbekannten-Zeile), 32 B (theoretisches Minimum), R5 sauber. **Aber:** Die Extraktion liefert den **geheimen Langzeit-Skalar `x` selbst** („Identity Burning", in S4 für Candidate A noch als nuclear option verworfen, in E unkommentiert). Konsequenzen: (a) Jeder Netzwerkknoten kann die Identität danach vollständig impersonifizieren (WoT-Vouching, zukünftige Traps) — Sanktion wird zur „Identität wird Gemeingut"; (b) Key-Rotation/Revocation wird pflicht, obwohl Attributionszweck nur `X` braucht; (c) Zeugen könnten `x*` technisch gar geheim halten — die Extraktion produziert den Skalar zwangsläufig. **Platzierung:** Nur als optionale „Hardmode"-Sanktionsvariante, falls `x` ein reiner Reputationsschlüssel ohne weitere Authentikationsrolle ist und Burning politisch gewollt ist.

### 6.6 Direkt-Shard `(R,z)` — warum nicht Primär

Vorteil: einfachste Implementierung, natives R5 ohne Off-band-Daten (`z·G ≟ R + c·X`), 64 B. Nachweislich schwächeres R1: P-pre-Prädikat existiert → Registry-Mining de-anonymisiert normale Zahlungen (S2/V-2 nennt dies zu Recht „far exceeding the intended 'only cheaters reveal themselves'"). Zusätzlich gelten sämtliche S2-MUSTs (Challenge-Rekomputation durch Witnesses ist sicherheitskritisch — ohne sie ist Framing nach V-1 wieder kostenlos). Nur als Fallback/Migrationsstufe empfehlen.

---

## 7. Degenerate Cases & normative MUSTs (konsolidiert S2 §4-MUSTs, auf SST gemappt)

1. **Gruppe:** ausschließlich ristretto255 (Kofaktor 8-Falle: Monero/CryptoNote-Octuple-Spend-Präzedenz); Raw-Edwards nur mit `[ℓ]P ≠ ∯`-Checks.
2. **Skalare:** kanonisch, `trap_s < q` erzwingen (`parse_canonical_scalar` — existente Infrastruktur, vgl. HMSEC-SA01-02); Challenge aus SHA-512 (≥512 bit) mod q.
3. **Witness-Pipeline-Reihenfolge** wie 5.4 (Signatur → Rekompuation → Kanonität → Guards → Extraktion → Lookup); jede Abweichung = `invalid-shard`.
4. **layer2-Signatur deckt ALLE neuen Felder + Versionstag** (Mutations-/Strip-Attacken).
5. **Nonces:** `r` deterministisch domänensepariert (`H(x‖μ)`); NIE wiederverwenden; Bias = HNP-Katastrophe (Biased Nonce Sense/LadderLeak). Deterministische Ableitung ist hier sicher, weil μ input-spezifisch ist.
6. **Guards:** `τ_1 ≠ τ_2`, `c ≠ 0`, identische Shard-Paare = `evasion-attempt`, `X̂` prime-order/non-identity vor Registry-Lookup.
7. **Retention:** ds_tag-Index darf nicht vor `max(deletable_at)+Grace` gelöscht werden (sonst verfällt Attribution durch Timing, S2/V-8).
8. **Burner-Keys (S2/V-5):** Extraction beweist „Inhaber dieses Keys", nicht „Person X" — Governance: Proof-of-Possession bei did:key-Registrierung, Mindestalter/Staking; kryptographisch nicht lösbar.
9. **Negative Testvektoren (proptest):** nicht-kanonische Skalare/Punkte, identische Shards, geraubte Fremd-Shards, τ-Kollision, n-Weg-Inkonsistenz, kompletter Framing-Versuch nach 6.1 Fall 1–3, W-Leak-Simulation.

---

## 8. Byte-Budget (R4)

| Posten | SST | Candidate E | Direkt-Shard |
|---|---|---|---|
| Gossip-Zusatz/Fingerprint | **64 B** (trap_r+trap_s) | 32 B | 64 B |
| JSON-serialisiert (base58, ≈×1.6) | ≈ 104 B | ≈ 52 B | ≈ 104 B |
| L1-privat (einmalig, nicht gossip) | 128 B (W) | 32 B (K) | 0 B |
| **Budget ≤ 192 B** | ✔ | ✔ | ✔ |

---

## 9. Prior-Art-Einordnung (S1)

- **Brands '93 (offline e-cash):** Doppelshow identifiziert via `u₁ = (r₁−r₁′)/(r₂−r₂′)` — strukturell identische Zwei-Zeugen-Affinextraktion; Framingschutz dort durch **issuer-zertifizierte** Kontoschlüssel. Der SST ist die issuer-freie Transplantation: die Zertifizierungsfunktion des Issuers wird durch die **L1-Signaturübergabe an den Empfänger** (R5) ersetzt.
- **Chaum–Fiat–Naor '88:** XOR-Offenlegung von ⟨info⟩ bei Doppelausgabe — probabilistisch, transkriptschwer, issuer-pflichtig.
- **Franklin–Yung / fair e-cash:** verifiable encryption an Trustee — entspricht verworfenem VE-Pfad (≫192 B, Committee-Infrastruktur).
- **Traceable Ring Signatures (Fujisaki–Suzuki '07, 2025-Revision):** formalisiert **exculpability** = unsere R3; O(N)-Ringgröße sprengt Budget; die degenerierte „ring-of-one"-Instantiierung mit per-event PRF-Pseudonymen ist die nächstverwandte Familie.
- **Adaptor Signatures:** „pre-signed disclosure"-Muster bestätigt Kollisionsöffnung als etablierte Bauform; Dai et al. behandeln Unlinkability gegen Key-Guessing (unsere P-pre-Problematik).
- **Direkter Treffer fehlt:** Keine publizierte Lösung kombiniert issuer-frei + kollisionsgetriggerte DID-Offenlegung + Framing-Immunität + ≤192 B (Suchstand 2026-08). Der SST ist damit ein neuer, kleiner Baustein; Publikation/eprint wäre diskutabel.

---

## 10. Bezug zur Codebasis & Migration

- `src/models/conflict.rs::TransactionFingerprint`: `u`/`blinded_id` → `trap_r`/`trap_s` (serde default, Versionstag im `HMC_TX_AUTH_V2`-Digest; alte Fingerprints laufen bis Ablauf ihrer `deletable_at` weiter).
- `src/services/trap_manager.rs`: `extract_id_point_from_raw_data`/`verify_trap` (V/u/M-Logik inkl. delta_u/delta_v-Guards) werden durch die SST-Pipeline 5.4 ersetzt; `suspected_identity`-Stufe kann entfallen, wenn R5-flows dominieren (sonst als Fallback für nicht-L1-verifizierte Kollisionen behalten).
- `src/wallet/conflict_handler.rs`: Import-Gates (F05) bleiben; did:key-Attribution jetzt über Signaturverifikation statt „ZKP gegen extrahierten Punkt".
- `ProofOfDoubleSpend.offender_id`-Hierarchie unverändert; `conflicting_transactions` trägt rekonstruiertes `(R̂, ŝ)` als portables Beweisobjekt.
- Testbasis: bestehende Suite `tests/security_audit_module_01_traps.rs` (f01/f02/f07–f09) um SST-Vektoren erweitern (Abschnitt 7.9); `cargo nextest run --status-level fail`.

## 11. Residualrisiken & offene Fragen

1. **Burner-/Rogue-keys** (Governance, nicht Kryptographie) — WoT-Seitig lösen (CORE-001-Schnittstelle beachten: TrustProvider in humoco-web-of-trust).
2. **Evasions-Klasse:** Ein L1-*ungeprüfter* Betrüger kann Inert-Shards senden → Quarantäne ja, DID nein. Fundamental (Simulator-Argument); Gegenmittel: L1-Verifizierung zur Regel machen, `evasion-attempt` prominent flaggen.
3. **W-Vertraulichkeit:** Empfänger-Leak von W offenlegt Payer-Identität für den einzelnen Input (dokumentieren, keine Krypto-Folgen).
4. **Quantum:** Shor bricht die gesamte Ed25519-Stack-Umgebung gleichermaßen — keine Verschlechterung gegenüber Status quo.
5. **Offen:** Entscheidung Hardmode (Candidate E, Key-Burning) ja/nein; Policy zur `deletable_at`-Verlängerung für ds_tag-Indizes; ggf. Hybrid SST↔E über Flag im Versionstag.

---

*Anhänge: `appendix-prior-art-research.md` (S1) · `appendix-red-team-direct-shard.md` (S2) · `appendix-design-independent.md` (S3) · `appendix-external-analyses.md` (S4/S5, Archiv der eingereichten Analysen)*
