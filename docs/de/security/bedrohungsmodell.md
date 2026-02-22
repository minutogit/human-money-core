# Bedrohungsmodell (Threat Model)

Basis für die Sicherheitsarchitektur von `human-money-core` ist eine systematische Analyse möglicher Angriffsvektoren. Wir verwenden hierfür das **STRIDE-Modell**.

Ziel ist es nicht, nur bekannte Lücken zu schließen, sondern proaktiv zu fragen: "Was kann schiefgehen?"

## STRIDE Analyse-Matrix

| Kategorie | Beschreibung (Deutsch) | Angriffs-Szenario im System | Gegenmaßnahme (Mitigation) | Status |
| :--- | :--- | :--- | :--- | :--- |
| **S**poofing | **Identitätsverschleierung** | Ein Angreifer gibt vor, der Inhaber eines Vouchers zu sein (Replay Attacke). | **TrapData Context Binding**: Jeder Voucher-Transfer ist an den Hash der Vorgänger-Transaktion gebunden. Die Identität wird durch Signaturen (Public Mode) oder ZKP (Private Mode) bewiesen. | ✅ Implementiert |
| **T**ampering | **Manipulation** | Ein Angreifer ändert den Betrag (`amount`) oder Empfänger im Voucher. | **Signaturen & Hashes**: Jede Änderung invalidiert die Signatur des Vorbesitzers oder den Hash-Link (`prev_hash`). | ✅ Implementiert |
| **R**epudiation | **Abstreitbarkeit** | Ein Nutzer leugnet, eine Zahlung getätigt zu haben. | **Signaturen**: Transaktionen (im Public Mode) sind signiert. Im Private-Mode ist dies *by design* möglich (Feature, nicht Bug), aber Double-Spending wird durch TrapData verhindert. | ⚠️ By Design (Privacy) |
| **I**nformation Disclosure | **Informationsleck** | Metadaten (Zeitstempel, IDs) lecken in Private-Transaktionen. | **Privacy Matrix**: Validation Logic verbietet strikt das Vorhandensein von IDs im Private Mode. (Siehe `datenschutz_analyse.md`). | 🔄 In Arbeit (Härtung) |
| **D**enial of Service | **Verweigerung** | Angreifer flutet das System mit riesigen Vouchern. | **Größenbeschränkung**: Maximale Anzahl Transaktionen pro Voucher. **Parsing-Limits**: Abbruch bei zu tief verschachtelten Strukturen. | ❓ Zu prüfen |
| **E**levation of Privilege | **Rechteausweitung** | Ein Nutzer versucht, Creator-Rechte (Währungsschöpfung) zu erlangen. | **Rollen-Checks**: Code prüft explizit, ob Signer == Creator. Validation Logic verhindert `role="creator"` für normale Nutzer. | ✅ Implementiert |

## Fokusbereiche für Härtung

Basierend auf der Analyse liegen die größten Risiken aktuell bei:

1.  **Private Mode Implementation**: Die Gefahr, dass Validierungsregeln (wie TrapData-Checks) übersprungen werden, weil Felder fehlen ("Fail Open" statt "Fail Close").
2.  **Metadata Leaks**: Unabsichtliches Lecken von Informationen durch Seiteneffekte (z.B. Timing Attacks oder Fehlermeldungen, die Rückschlüsse auf Existenz von Usern zulassen).

## Nächste Schritte

- Integration von **Property-Based Testing** (siehe `test_strategie.md`), um die Matrix automatisiert gegen den Code zu prüfen.
- Review der `Denial of Service` Maßnahmen (z.B. max. Voucher-Größe in Bytes).
