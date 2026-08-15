---
name: git-release
description: Standardisierter Workflow zum Übertragen von Änderungen aus `live` in `dev` (vollständige Historie) und konsolidiert mit wenigen, sauberen Commits in `master`. Bereitet `live` anschließend für die nahtlose Weiterarbeit vor. Erstellt immer zuerst einen Plan zur Freigabe.
---

# Git Release & Branch Merge Workflow (`live` -> `dev` -> `master`)

Dieser Skill definiert den standardisierten, wiederverwendbaren Workflow, um Entwicklungsschritte aus dem Branch `live` sicher in `dev` und `master` zu überführen.

---

## 1. Kern-Prinzipien

1. **Plan First (Immer vor Ausführung)**:
   - Vor jeder Änderung an Branches wird ein `implementation_plan.md` erstellt.
   - Der Plan fasst alle neuen Commits auf `live` zusammen und schlägt eine logische Bündelung (3–5 thematische Commits nach *Conventional Commits*) für `master` vor.
   - Die Ausführung startet **erst nach expliziter Bestätigung** durch den Nutzer.

2. **Branch-Rollen**:
   - **`live`**: Der aktive Arbeits-Branch für fortlaufende Entwicklung und Iterationen.
   - **`dev`**: Der Integrations-Branch mit vollständiger, lückenloser Commit-Historie aller Zwischenschritte (`merge live -> dev`).
   - **`master`**: Der produktive / Release-Branch mit sauberen, gebündelten Commits ("Clean History").

3. **Integritäts-Garantie**:
   - Am Ende müssen `master`, `dev` und `live` denselben finalen Code-Stand haben (`git diff master live` ist leer).
   - Alle Tests (`cargo test`) müssen fehlerfrei durchlaufen.
   - `live` wird so synchronisiert, dass neue Arbeiten direkt und ohne Verzweigungskonflikte darauf fortgeführt werden können.

---

## 2. Ablauf-Schritte

### Phase 1: Analyse & Plan-Erstellung
1. Git-Status und Diff zwischen `origin/master` (bzw. aktuellem `master`) und `live` ermitteln:
   ```bash
   git log --oneline master..live
   ```
2. Gruppierung der Commits in 2–5 thematisch getrennte Blöcke entwerfen:
   - `feat(...)`: Neue Features & Endpunkte
   - `fix(...)`: Fehlerkorrekturen
   - `refactor(...)`: Code-Bereinigungen / Architektur-Optimierungen
   - `docs(...)`: Dokumentation, Übersetzungen, Spezifikationen
3. `implementation_plan.md` schreiben und auf Freigabe des Nutzers warten.

### Phase 2: Ausführung (nach Freigabe)

```bash
# 1. Sicherheits-Backup anlegen
git branch backup/pre-release-$(date +%Y%m%d%H%M%S) live

# 2. dev mit vollständiger Historie aktualisieren
git checkout dev
git merge live -m "Merge branch 'live' into dev"

# 3. master mit konsolidierten Commits aktualisieren
git checkout master
# Hier werden die geplanten thematischen Commits erstellt
# Sicherstellen: git diff master live ist leer!

# 4. live auf den gemeinsamen Stand rebasen / synchronisieren
git checkout live
git reset --hard master

# 5. Verifikation
cargo test
git diff master dev
git diff master live
```

### Phase 3: Abschluss & Walkthrough
1. Erstellen von `walkthrough.md` mit Übersicht der erstellten Master-Commits und aktuellem Branch-Status.
2. Bestätigen, dass `live` bereit für neue Änderungen ist.
