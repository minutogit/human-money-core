---
name: design-decisions
description: Architectural design decisions for human_money_core including SAI, instance IDs, TOML standards, and CEL engine choices.
---

# human_money_core — Design Decisions

Dieses Dokument hält die grundlegenden Design-Entscheidungen der `human_money_core`-Bibliothek fest und dient als Referenz für die Architektur.

## 1. Datenformate

**Abbildung des Geschlechts im `Creator` Struct:**
- **Entscheidung:** Das `gender`-Feld im `Creator`-Struct wird als `Int` definiert. Geschlecht des Erstellers nach ISO 5218 (1 = male, 2 = female, 0 = not known, 9 = Not applicable).
- **Begründung:** Diese Wahl ist pragmatisch und universell einsetzbar, ohne sich auf spezifische kulturelle oder rechtliche Definitionen von Geschlecht zu beschränken.

**Voucher Standard Definitionen via TOML:**
- **Entscheidung:** Nutzung von TOML für die Definitionsdateien der Gutschein-Standards.
- **Begründung:** TOML erlaubt Kommentare, was die Lesbarkeit und Dokumentation der Standards erheblich verbessert. JSON bietet diese Möglichkeit nicht.

**Besicherungskonzept (Collateral vs. Bürgen):**
- **Entscheidung:** Strikte Entkopplung von `Standard.blueprint.collateral_type` (Währungstyp-Klassifikation) und `Voucher.collateral` (optionaler Payload-Container). Bei `personal_guarantee` (z. B. Minuto) ist `voucher.collateral = None`, da Bürgschaften originär über kryptographische Signaturen (`signatures` mit Rolle `guarantor`) abgebildet werden. Für Sachwerte/Fiat bleibt `voucher.collateral` als offener Extension Point erhalten. Eine Verpflichtung zur Befüllung wird nicht im Core hardgecodet, sondern bei Bedarf dynamisch über CEL-Regeln (`custom_rules`) erzwungen.
- **Begründung:** Verhindert vorzeitiges Over-Engineering und juristische Fehlannahmen im Core, hält Gutscheine schlank und ermöglicht spätere Sachwert-Erweiterungen ohne Breaking Changes.

## 2. Wallet-Architektur

**local_voucher_instance_id:**
- **Entscheidung:** Einführung einer lokalen Instanz-ID als Primärschlüssel.
- **Begründung:** Nach einer `split`-Transaktion teilen sich mehrere Guthaben dieselbe `voucher_id`. Die Instanz-ID (Hash aus `voucher_id` und `t_id`) ermöglicht eine eindeutige Referenzierung im Wallet.

**Separated Account Identity (SAI):**
- **Entscheidung:** Kombination aus einheitlichem Web of Trust und strikter Kontotrennung.
- **Begründung:** Ein Nutzer hat einen Hauptschlüssel (Mnemonic), aber pro Kontext (Präfix oder Root) einen eigenen abgeleiteten Schlüssel (via HKDF). Dies verhindert Identitäts-Hopping und ermöglicht saubere Kontentrennung bei gleicher Identität.

## 3. Sicherheitsschichten

**WalletSeal Rollback Guard:**
- **Entscheidung:** Kryptographisches Epochen-System mit hash-verketteten Siegeln.
- **Begründung:** Verhindert das Wiedereinspielen alter Backups (Rollback-Angriff) und erkennt divergierende Wallet-Zustände (Forking).

**Storage Integrity:**
- **Entscheidung:** SHA3-256 Integritätsnachweise für alle Dateien, gebunden an das `WalletSeal`.
- **Begründung:** Erkennt sofort jede physische Manipulation an den Dateien auf dem Datenträger (Änderung, Löschung, Hinzufügung).

**Anti-Signature-Reuse-Firewall:**
- **Entscheidung:** Validierung der Signatur-Eindeutigkeit auf Ebene des binären Public Keys (`[u8; 32]`).
- **Begründung:** Verhindert Sybil-Angriffe, bei denen dieselbe Identität durch verschiedene Präfixe getarnt wird.

**Stealth Mode vs. Lokale Offline-Forensik (Hop-by-Hop Rückverfolgbarkeit):**
- **Entscheidung:** Strikte Unterscheidung zwischen *Artefakt-Anonymität* (Gutscheinkette und Transport-Container) und *lokaler Forensik im Wallet-Ledger*.
- **Begründung:** Im Stealth Mode darf der Gutschein selbst (`voucher.transactions`) und der Transit-Container keine Rückschlüsse für Dritte oder spätere Kettenglieder zulassen. Allerdings müssen die **direkten Transaktionspartner lokal im verschlüsselten Wallet-Event-Log** (`TransferSent` / `TransferReceived`) wissen, mit wem die direkte Transaktion stattfand. Bei Offline-Double-Spends ist diese Hop-by-Hop-Rückverfolgbarkeit die einzige Möglichkeit, den Betrug manuell aufzuklären (Kette von A -> B -> C: Wenn C einen Double Spend meldet, kann B nachweisen, dass er den Gutschein von A erhalten hat). Die lokale Speicherung der `counterparty_id` im verschlüsselten, durch `WalletSeal` geschützten Speicher des Nutzers ist daher kein Sicherheitsleck, sondern eine essenzielle funktionale Anforderung für Offline-Bargeld.

## 4. Geschäftslogik & Engines

**Dynamic Business Rules via CEL:**
- **Entscheidung:** Einsatz der **Common Expression Language (CEL)** für Gutschein-Validierungsregeln.
- **Begründung:** Ermöglicht flexible, komplexe Regeln in den Standards ohne Code-Änderungen im Core. CEL ist sicher, performant und nicht Turing-vollständig.

**Wallet Event Sourcing:**
- **Entscheidung:** Persistenter, append-only Ledger (`WalletEvent`) in monatlichen Chunks.
- **Begründung:** Ermöglicht Audit-Historie und Zustandswiederherstellung bei hoher Performance durch Chunking (`YYYY_MM.json.enc`).

## 5. Konfliktmanagement

**Dezentrales Konfliktmanagement & VIP-Gossip:**
- **Entscheidung:** Fokus auf lokale Overrides und "Very Important Proofs" (VIP).
- **Begründung:** Globaler Konsens wird vermieden, um Privatsphäre zu schützen und Sybil-Anfälligkeit zu reduzieren. Konflikte werden sozial oder via Layer 2 gelöst.
- **VIP Gossip:** Betrugsbeweise werden mit negativer `depth` priorisiert verbreitet.

**Self-Authenticating Fingerprints & Instant-Gossip-Proofs (V2):**
- **Entscheidung:** Gossip-Fingerprints sind keine unauthentifizierten Gerüchte mehr, sondern kryptographisch selbst-authentifizierende Sofort-Beweise. Ein einziger domänenseparierter SHA3-256-Digest unter Domain-Tag `HMC_TX_AUTH_V2` (length-prefixed via `get_raw_hash_from_slices`; bindet Challenge-ds_tag, t_id, `sender_ephemeral_pub`, Trap-Challenge u, blinden Identitätspunkt V, `encrypted_timestamp`, `deletable_at`) dient gleichzeitig als L1-Ownership-Proof, L2-Lock-Proof und Gossip-Proof. Dies behebt zugleich Legacy AUDIT-01-F03 (unpräfixierte Konkatenation im Payload-Hash).
- **Begründung:** Die defensive Post-Commit-Absicherung (fdfeb80) machte den Betrugsschutz langsam: Wallets mussten auf megabytegroße Transaktionsketten warten, bis ein Double Spend überhaupt beweisbar war. Der Wechsel zu verifizierbaren Beweisen ermöglicht echte Echtzeit-Verteidigung im Offline-Bargeld.
- **Ingress Signature Gate:** Gossip-Fingerprints werden nur akzeptiert, wenn ihre eingebettete `layer2_signature` den `HMC_TX_AUTH_V2`-Digest validiert (`verify_fingerprint_signature`, signiert vom Halter des offengelegten Ephemeral-Keys). Init-Fingerprints (u == "none") sind vom Gossip-Export/-Ingress ausgeschlossen; Legacy-Fremd-Fingerprints werden beim Laden/Cleanup entfernt.
- **Instant Quarantine:** `resolve_conflict_offline` lässt FREMDE, gültig signierte V2-Fingerprints wieder ins "Earliest Wins"-Rennen — eine signierte Kollisions-Gossip quarantänisiert den Verlierer-Ast in Millisekunden statt erst nach dem Eintreffen schwerer Transaktionsketten.
- **Threat-Modell-Grenze:** Die Angreiferklasse reduziert sich von "any external peer" (AUDIT-01-F01) auf Akteure, die jemals im Besitz des privaten Ephemeral-Einmalschlüssels des Outputs waren (z. B. Issuer oder Vorhalter). Diese sind mathematisch nicht von einem echten Double Spend unterscheidbar — das Paradigma "Fraud Detection, Not Prevention" bleibt gewahrt.
- **Attributions-Hierarchie (AUDIT-01-F05):** Kanonisches Offender-Attribut bei Instant-Gossip-Proofs ist die unfälschbare Bindung `offender_id = "ephemeral:<sender_ephemeral_pub>"`; mathematisch rekonstruierte did:key-Identitäten werden ausschließlich beratend als `suspected_identity` geführt (Anti-Framing bleibt intakt, da Soft-Placeholders mit `proof:"none"` die Identitätsverifikation fehlschlagen lassen).
- **Breaking Change:** Bestehende V1-`layer2_signature`s/Fingerprints werden ungültig. Das L2-Schema wurde synchron erweitert (`L2LockRequest`/`L2LockEntry` um `u`, `blinded_id`, `encrypted_timestamp`); externe L2-Server müssen dieses übernehmen.

**Shared-Signature Trap / SST (V3, `HMC_TX_AUTH_V3`) — autonome, fälschungssichere Täter-Enttarnung:**
- **Entscheidung:** Die V2-Trap-Mathematik (`V = m*U + ID`, Schnorr-Beweis über Kenntnis der Slope `m`) wurde vollständig durch den **Shared-Signature Trap (SST)** ersetzt. Jeder Spend veröffentlicht nur ein *Shard* $(R_i, s_i)$ einer deterministischen Schnorr-Signatur $\sigma = (R_{sig}, s_{sig})$ über die Nachricht $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \parallel ds\_tag \parallel E)$:
  - $R_i = R_{sig} + \tau_i \cdot M_R$, $s_i = s_{sig} + \tau_i \cdot m_s$ mit $\tau_i = H(\text{"HMC\_TAU\_V1"} \parallel ds\_tag \parallel t\_id)$.
  - Maskierung: $M_R = \mathrm{hash\_to\_curve}(\ldots)$, $m_s = H(\ldots) \bmod q$, beide abgeleitet ausschließlich aus Langzeitschlüssel $x$, Ephemeral-Key $E$ und $ds\_tag$.
  - Nonce: $r = H(\text{"NONCE"} \parallel x \parallel \mu)$ (deterministisch, keine RNG-Abhängigkeit zur Signaturzeit).
- **Begründung (Framing-Immunität, AUDIT-01-F07):** Unter V2 konnte ein Betrüger mit beliebiger, selbst bekannter Slope `m'` beide Forks an der Identität eines Unschuldigen verankern — die Beweise waren kryptographisch echt, die Anklage gefälscht. Unter SST ist die Zuschreibung an die EUF-CMA-Fälschungssicherheit von Schnorr/Ed25519 gekoppelt: Shards zu konstruieren, deren Rekonstruktion eine **gewählte** Fremd-Identität ergibt, wäre genau ein solches Forgery-Ereignis. Framing ist damit rechnerisch unerreichbar; `did:key`-Zuschreibung darf (und muss) direkt erfolgen.
- **Informationstheoretische Anonymität vor Kollision ("P-pre"):** Ein einzelnes Shard enthält null nutzbare Identitätsinformation. Das Empfänger-Konsistenzsystem hat 4 Unbekannte und nur 3 Gleichungen — pro Kandidaten-Identität existiert eine 1-parameterige Zeugen-Faser ($m_s$ als freier Parameter). Registry-Mining ohne Kollision ist daher unmöglich (getestet in `test_sst_zero_knowledge_no_p_pre_registry_mining`).
- **Autonome Gossip-Enttarnung (R2/R3):** Zwei kollidierende Shards rekonstruieren linear $(\hat{M}_R, \hat{m}_s, \hat{R}, \hat{s})$; der Challenge bindet sie an genau einen Public Key $\hat{X} = (\hat{s}G - \hat{R})c^{-1}$ → direkte `offender_id = did:key`. Kein Nachfordern von Transaktionsketten nötig.
- **Design-Abweichung von der Ur-Spezifikation (bewusst):** Der rohe `prev_hash` wurde aus $\mu$ entfernt ($\mu$ bindet nur `ds_tag || E`). Begründung: (a) `prev_hash` ist bereits kryptographisch via $ds\_tag = H(prev \| E)$ committet (Second-Preimage-Resistanz ⇒ identische Bindungsstärke); (b) Fingerprints transportieren `prev_hash` nicht — nur so ist $\mu$ aus Gossip-Daten allein ableitbar und die versprochene *autonome* Enttarnung ohne Ketten-Nachforderung überhaupt realisierbar. Die API-Signaturen wurden entsprechend vereinfacht.
- **L1-Betrugsverhinderung (R5):** Der private Zeuge $W = (R_{sig}, s_{sig}, M_R, m_s)$ wird im verschlüsselten `RecipientPayload` übergeben (`trap_r_sig/trap_s_sig/trap_m_r/trap_m_s`). Der Empfänger prüft beim Empfang fail-closed: Schnorr-Gleichung gegen die payer-DID plus Shard-Konsistenz; Müll-/manipulierte Traps führen zur sofortigen Zahlungsrückweisung (`verify_sst_witness`).
- **Degenerate-Firewall:** Guards vor jeder Inversion: $\tau_1 \neq \tau_2$, $(R_1,s_1) \neq (R_2,s_2)$, strikt kanonische Skalare (Malleability, AUDIT-01-F02/F09), dekomprimierbare Punkte, $c \neq 0$, $\hat{X} \neq \mathcal{O}$; bei $n \ge 3$ Shard-Sets müssen alle weiteren Shards auf der rekonstruierten Linie liegen (`verify_sst_shards_consistency`).
- **t_id-Präbild-Änderung (V3):** `trap_data` UND `privacy_guard` sind aus dem kanonischen `t_id`-Präbild entfernt. Begründung: Zirkularität $\tau_i(t\_id) \leftrightarrow t\_id(trap)$; Authentifizierung der Shards erfolgt separat über die V3-`layer2_signature` (Digest bindet `trap_r`/`trap_s`), der Privacy Guard ist AEAD-geschützt und wird beim Empfänger strikt entschlüsselungsverifiziert. Die Kettenverknüpfung (`prev_hash`) bleibt weiterhin Hash über das volle kanonische JSON inklusive Trap/Guard.
- **Breaking Change:** Alle V2-Signaturen/Fingerprints/Locks sind ungültig; `TrapData` heißt nun `{ds_tag, trap_r, trap_s}`, `TransactionFingerprint` ebenso (`u`/`blinded_id` entfallen); `L2LockRequest`/`L2LockEntry` nutzen `trap_r`/`trap_s` unter Domain-Tag `HMC_TX_AUTH_V3`. Der Test `f07_trap_anchoring_framing_arbitrary_slope_must_be_rejected` ist ent-ignoriert und als dauerhafte grüne Invariante in der Suite.

## 6. WASM & Cross-Platform Kompilierung

**Target-Gating für OS-abhängige Dependencies:**
- **Entscheidung:** OS- und I/O-spezifische Abhängigkeiten (`sysinfo`, `tokio`, `reqwest`) sind in `Cargo.toml` strikt unter `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` eingeordnet. Code-Abschnitte mit OS-Systemaufrufen (z. B. Prozess-Checks in `FileStorage`) sind mit `#[cfg(not(target_arch = "wasm32"))]` gekapselt.
- **Begründung:** Garantiert, dass `human_money_core` als reine Rust-Bibliothek direkt für `wasm32-unknown-unknown` (und Web/Browser/WASM) kompilierbar bleibt, während native Desktop-Features (File Lock Checks, CLI-Simulatoren) uneingeschränkt funktionieren.
- **WASM-Bridge Trennung:** Ein separates WASM-Bridge/Wrapper-Crate übernimmt ausschließlich die `wasm-bindgen`-JS-Schnittstellen und Browser-Storage-Adapter (`IndexedDBStorage` / `MemoryStorage`), um das Kern-Crate frei von JS-Binding-Ballast zu halten.

