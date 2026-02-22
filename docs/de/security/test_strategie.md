# Sicherheits-Teststrategie

Um das Ziel zu erreichen, nicht nur "Tests zu schreiben", sondern "Eigenschaften zu garantieren", setzen wir auf fortgeschrittene Testmethoden.

## 1. Property-Based Testing (PBT)

Statt einzelner Beispiele ("Example-Based Testing") definieren wir Eigenschaften, die **immer** wahr sein müssen, und lassen den Computer Randfälle suchen.

**Werkzeug:** `proptest` (Rust Crate)

### Zu testende Invarianten (Beispiele):
*   "Für **jeden** generierten Voucher gilt: Wenn `sender_id` leer ist, MUSS `trap_data` valide sein (oder der Voucher wird abgelehnt)."
*   "Die Summe der Beträge darf sich durch eine Transaktion **niemals** ändern (Input == Output)."
*   "Ein Voucher darf **niemals** eine Signatur enthalten, deren Zeitstempel VOR der Erstellung (`creation_date`) liegt."

**Aktion:** Einrichtung von Fuzzing-Targets für die `validate_voucher`-Funktion.

## 2. Mutation Testing

Wir überprüfen die Qualität unserer Tests, indem wir den Code absichtlich "kaputt machen" (Sabotage).

**Werkzeug:** `cargo-mutants`

### Verfahren:
1.  Das Tool ändert den Quellcode (z.B. entfernt ein `if`-Statement oder dreht eine Bedingung um).
2.  Es führt die Testsuite aus.
3.  **Erwartung:** Mindestens ein Test **MUSS** fehlschlagen ("mutant killed").
4.  **Fehlerfall:** Wenn die Tests trotz Sabotage grün bleiben ("mutant survived"), haben wir eine Testlücke.

**Ziel:** Sicherstellen, dass kritische Checks (wie der `ds_tag`-Check im Private Mode) nicht unbemerkt entfernt werden können.

## 3. Negative Testing & Invarianz-Prüfung

Wir testen explizit das "Scheitern".

*   **Test-Harness:** Ein Generator erzeugt valide Transaktionen und korrumpiert dann gezielt einzelne Bytes oder Felder.
*   **Erwartung:** Der Parser oder Validator MUSS mit einem definierten Fehler ablehnen (kein Panic, kein Akzeptieren).

## Roadmap
1.  [ ] Einführung von `proptest` in `Cargo.toml`.
2.  [ ] Erstellung eines "Generators" für valide/invalide Voucher-Strukturen.
3.  [ ] Durchführung eines Mutation-Runs zur Bestandsaufnahme der Testabdeckung.
