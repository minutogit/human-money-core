---
creation date: 2026-02-01 10:28
modification date: 2026-02-10
tags:
  - human-money-core
  - security
  - philosophy
---
# 01. Sicherheitsmodell & Philosophie

**Kontext:** Teil 1 der Human Money Core Spezifikation.

## 1. Einführung und Design-Philosophie

Das System `human_money` realisiert ein digitales Bargeld, das radikaler ist als herkömmliche Kryptowährungen. Es verzichtet auf eine globale Blockchain zugunsten lokaler, dateibasierter Gutscheine ("Voucher"). Um in diesem dezentralen Umfeld Sicherheit und Privatsphäre zu garantieren, kombiniert das Protokoll drei fortschrittliche Konzepte:

1. **Quantensichere Forward Secrecy (Der Anker):**
    
    Die Identität (Public Key) des aktuellen Besitzers wird niemals im Klartext in der Kette gespeichert. Stattdessen nutzt das Protokoll kryptographische Commitments (Hashes). Erst im Moment der Ausgabe wird der Schlüssel enthüllt. Dies schützt ruhende Guthaben selbst vor zukünftigen Angriffen durch Quantencomputer, da der Private Key nicht aus dem Hash abgeleitet werden kann.
    
2. **Mathematische Double-Spend Erkennung (Die Falle):**
    
    Da es keine zentrale Instanz gibt, die "Doppelausgaben" in Echtzeit verhindert, nutzt das System eine mathematische Falle. Wer denselben Gutschein-Zustand zweimal ausgibt, muss zwangsläufig seine kryptographische Identität enthüllen. Dies geschieht rein rechnerisch durch den Vergleich von zwei anonymen Transaktions-Fingerprints (Slope-Calculation).
    
3. **Kontext-Integrität (Sub-Accounts):**
    
    Durch "Präfix-Validierung" im verschlüsselten Payload wird sichergestellt, dass Guthaben strikt in seinem definierten ökonomischen Kontext (z. B. "Regionalwährung A" vs. "Zeitbank B") bleibt, auch wenn der Nutzer denselben kryptographischen Hauptschlüssel (did:key) verwendet.

## 2. Bedrohungsmodell & Sicherheitsanalyse

Dieses Modell beschreibt, wie das System spezifische Angriffe durch kryptographische Garantien abwehrt.

### 2.1 Angriff: "Brute Force Deanonymization"

- **Szenario:** Ein Angreifer sammelt Millionen von Public Keys und versucht, durch Einsetzen in die mathematische Falle (Trap) herauszufinden, wer der Sender einer anonymen Transaktion war.
    
- **Analyse:** Die Trap-Gleichung lautet $V = m \cdot U + ID$. Da der Angreifer den Zufallsfaktor $m$ (die Steigung) nicht kennt, gibt es für jeden beliebigen Public Key auf der Welt ein hypothetisches $m$, das die Gleichung lösen würde.
    
- **Ergebnis (Perfect Hiding):** Es ist mathematisch unmöglich, den wahren Sender von einer zufälligen Annahme zu unterscheiden. Die Privatsphäre ist informationstheoretisch sicher.
    

### 2.2 Angriff: "Trap Evasion" (Ausweichen der Falle)

- **Szenario:** Ein böswilliger Sender versucht, beim zweiten Ausgeben (Double Spend) ein anderes $m$ zu wählen, damit die mathematische Enttarnung fehlschlägt.
    
- **Abwehr (Deterministischer Zwang):** Der Zero-Knowledge-Proof (ZKP) validiert nicht nur die Gleichung, sondern erzwingt deterministische Ableitung via HKDF:
    
    $$m = HKDF(SenderPrivateKey, prev\_hash, info = prefix)$$
    (Wobei das Präfix via HKDF-Expand untrennbar mit dem Schlüssel $m$ gebunden wird).
- **Ergebnis:**
    
    - Wählt der Angreifer das korrekte (gleiche) $m$ $\rightarrow$ Die Falle schnappt zu (Identität wird berechnet).
        
    - Wählt der Angreifer ein anderes $m$ $\rightarrow$ Der ZKP ist ungültig. Die Transaktion wird technisch abgewiesen.

### 2.3 Angriff: "Prefix Confusion" (Falschbuchung)

- **Szenario:** Ein Sender schickt "Währung A" an die Adresse von "Währung B" desselben Empfängers (gleicher Public Key).
    
- **Abwehr:** Das Ziel-Präfix (z. B. `minuto:bth`) ist untrennbar im verschlüsselten Payload eingebettet. Das Präfix ist der Teil der ID vor dem `@` (frei wählbar, mit Checksumme verifiziert).


### 2.4 Angriff: "Sybil-Identität" (Fake DID Proxy)

- **Szenario:** Ein Angreifer sendet Guthaben von seinem Hauptkonto an eine frische Wegwerf-Identität ("Fake DID"). Diese Fake-Identität führt den Double-Spend aus.

- **Analyse:** Die mathematische Falle enthüllt die Fake-ID. Da diese keine Reputation im Web of Trust hat, ist der direkte Reputationsschaden für den Angreifer gering.

- **Abwehr (Manuelle Rückverfolgung):** Hier greift die soziale Komponente des Systems. Da der kryptographische Schutz bei der Fake-ID endet, muss der Pfad manuell rekonstruiert werden:

    1.  **Rückwärts (vom Opfer):** Wer hat den Gutschein von der Fake-ID angenommen?
    2.  **Vorwärts (vom Ersteller):** Wer hat Guthaben AN die Fake-ID gesendet?

    **Konsequenz:** Der letzte *bekannte* Teilnehmer der Kette, der Guthaben an die unbekannte Fake-ID weitergeleitet hat, gerät unter Generalverdacht. Er ist entweder der Angreifer selbst oder hat grob fahrlässig mit einer unvertrauenswürdigen Partei gehandelt. In einem Web of Trust gilt das Prinzip: Wer Werte an Anonyme leitet, haftet sozial für deren Fehlverhalten.

## 3. Zusammenfassung und Sicherheits-Nuancen

|   |   |   |
|---|---|---|
|**Eigenschaft**|**Garantie**|**Mechanismus**|
|**Privatsphäre**|**Perfect Hiding**|Angreifer können IDs nicht erraten, da $m$ via HKDF geschützt ist.|
|**Sicherheit**|**Unbreakable**|Trap kann nicht umgangen werden, da ZKP deterministisches $m$ erzwingt.|
|**Ordnung**|**Prefix Scoping**|Bezeichner wie `creator:fY7@did...` erzwingen strikte Kontext-Trennung.|

### 3.1 Hinweis zur Quantensicherheit

Das System bietet eine **hybride Sicherheit**:

1. **Layer 2 (Post-Quantum):** Die Anker (`receiver_ephemeral_pub_hash`) basieren auf kryptographischen Hashes (**SHA3-256**). Ein Quantencomputer kann das Preimage nicht berechnen. Ruhende Guthaben (Cold Storage) sind daher sicher, solange der Key nicht enthüllt wurde.
    
2. **Layer 1 (Pre-Quantum):** Die Identitäten (`did:key`) und Signaturen basieren auf Ed25519 (Elliptische Kurven). Ein hinreichend mächtiger Quantencomputer könnte theoretisch den Private Key aus einem Public Key errechnen.
    
    - **Risiko-Einordnung:** Das Brechen von Ed25519 erfordert staatliche Ressourcen. Für lokale Netzwerke und private Kreise bleibt das Verfahren sicher.
        
    - **Schutz:** Selbst wenn eine Identität gebrochen wird, kann der Angreifer Guthaben **nicht** stehlen, solange er nicht den _aktuellen_ Layer-2-Anker (den Hash-Preimage) kennt.
