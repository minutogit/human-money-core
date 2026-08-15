---
name: git-release
description: Standardisierter Workflow zum Übertragen von Änderungen aus `live` in `dev` (vollständige Historie) und konsolidiert mit wenigen, sauberen Commits in `master`. Bereitet `live` anschließend für die nahtlose Weiterarbeit vor. Erstellt immer zuerst einen Plan zur Freigabe.
---

# Git Release & Branch Merge Workflow (`live` -> `dev` -> `master`)

Dieser Skill definiert den standardisierten, automatisierten und ausfallsicheren Workflow, um Entwicklungsschritte aus dem Branch `live` sicher in `dev` und `master` zu überführen.

---

## 1. Kern-Prinzipien

1. **Plan First (Immer vor Ausführung)**:
   - Vor jeder Änderung an Branches wird ein `implementation_plan.md` erstellt.
   - Der Plan analysiert alle Commits auf `live` seit dem letzten Release und schlägt eine logische Bündelung (3–5 thematische Commits nach *Conventional Commits*) für `master` vor.
   - Die Ausführung startet **erst nach expliziter Bestätigung** durch den Nutzer.

2. **Branch-Rollen**:
   - **`live`**: Der aktive Arbeits-Branch für fortlaufende Entwicklung und Iterationen.
   - **`dev`**: Der Integrations-Branch mit vollständiger, lückenloser Commit-Historie aller Zwischenschritte (`merge live -> dev`).
   - **`master`**: Der produktive / Release-Branch mit sauberen, gebündelten Commits ("Clean History").

3. **Integritäts-Garantie & Ausfallsicherheit**:
   - **Pre-Flight-Check:** Arbeitsverzeichnis muss vor Beginn sauber sein (`git status --porcelain`).
   - **Staging-Branch-Methode:** `master` wird über einen isolierten temporären Branch (`release/staging`) aufgebaut. Dadurch werden Rebase-Konflikte und fehlerhafte Zwischenzustände mathematisch ausgeschlossen.
   - **Zero-Diff-Garantie:** `master`, `dev` und `live` müssen am Ende 100% denselben Code-Stand haben (`git diff master live` ist leer).
   - Alle Tests (`cargo test`) müssen fehlerfrei durchlaufen.
   - `live` wird so synchronisiert, dass neue Arbeiten direkt und ohne Verzweigungskonflikte darauf fortgeführt werden können.

---

## 2. Ablauf-Schritte

### Phase 1: Pre-Flight & Plan-Erstellung
1. Prüfen, ob das Arbeitsverzeichnis sauber ist:
   ```bash
   git status --porcelain
   ```
2. Commits auf `live` seit `master` ermitteln:
   ```bash
   git log --oneline master..live
   ```
3. Gruppierung der Commits in 2–5 thematisch getrennte Blöcke entwerfen:
   - `feat(...)`: Neue Features & Endpunkte
   - `fix(...)`: Fehlerkorrekturen
   - `refactor(...)`: Code-Bereinigungen / Architektur-Optimierungen
   - `docs(...)`: Dokumentation, Übersetzungen, Spezifikationen
4. `implementation_plan.md` schreiben und auf Freigabe des Nutzers warten.

---

### Phase 2: Ausführung (nach Freigabe)

```bash
# 1. Sicherheits-Backup anlegen
git branch backup/pre-release-$(date +%Y%m%d%H%M%S) live

# 2. dev mit vollständiger Historie aktualisieren
git checkout dev
git merge live -m "Merge branch 'live' into dev"

# 3. master über isolierten Staging-Branch deterministisch aufbauen
git checkout -b release/staging master

# Für jeden geplanten Commit-Block (Gruppe 1 bis N):
# Schrittweise den Code-Stand des jeweiligen Commit-Blocks auf release/staging anwenden:
# (Beispiel Gruppe 1 bis Commit <COMMIT_G1_HASH>):
git checkout <COMMIT_G1_HASH> -- .
git commit -m "feat(module): descriptive message for group 1"

# (Beispiel Gruppe 2 bis Commit <COMMIT_G2_HASH>):
git checkout <COMMIT_G2_HASH> -- .
git commit -m "feat(module): descriptive message for group 2"

# (Beispiel finale Gruppe bis live):
git checkout live -- .
git commit -m "docs: descriptive message for final group"

# 4. Zero-Diff Verifikation auf Staging-Branch
git diff release/staging live # MUSS komplett leer sein!

# 5. master und live atomar aktualisieren
git branch -f master release/staging
git checkout live
git reset --hard master
git branch -D release/staging

# 6. Testsuite verifizieren
cargo test
git diff master dev
git diff master live
```

---

### Phase 3: Abschluss & Walkthrough
1. Erstellen von `walkthrough.md` mit Übersicht der erstellten Master-Commits und aktuellem Branch-Status.
2. Bestätigen, dass `live` bereit für neue Änderungen ist.
