# Offline Double-Spend Simulation & Immune System Benchmark

Dieses Tool simuliert und misst die Effektivität des **Gossip-basierten Immunsystems (Transaktions-Fingerprints)** im Vergleich zu einer **naiven Gutscheinketten-Prüfung** in einem vollständig isolierten P2P-Offline-Netzwerk.

---

## 1. Versuchsaufbau & Methodik

* **Topologie:** Watts-Strogatz Small-World-Netzwerk ($N=500$ bis $1.000$ Knoten, $k=6$ Nachbarn, $p=0.1$ Rewiring für Hubs/Abkürzungen).
* **Interaktionsmuster (80/20):** 80 % aller Zahlungen erfolgen im eng vernetzten lokalen Cluster (Nachbarschaft/Stammkunden), 20 % an beliebige Knoten oder Hubs (Märkte).
* **Gepaarter Monte-Carlo-Test:** Beide Modi laufen pro Run auf **exakt demselben Graphen** und **derselben Transaktionssequenz** mit identischem Seed.
* **Gossip-Einschränkung:** Realistischer Ringpuffer ($K=15$ Fingerprints pro Wallet) und max. $M=4$ transportierte Fingerprints pro Transaktionsbundle.

---

## 2. Gemessene Ergebnisse

### Benchmark 1: $N = 500$ Knoten (50 Monte-Carlo-Runs)

| Metrik | Ohne Fingerprints (Modus A) | Mit Fingerprints (Modus B) | Vorteil / Faktor |
| :--- | :--- | :--- | :--- |
| **Erkennungsrate** | 100 % | 100 % | Identisch |
| **Zeit bis Erkennung (Ticks, Mean)** | 504.9 Ticks | 101.5 Ticks | **5.0x schneller** |
| **Zeit bis Erkennung (Ticks, Median)** | 435.0 Ticks | 91.5 Ticks | **4.8x schneller** |
| **Netzwerk-Transaktionen (Mean)** | 12.609 TX | 2.526 TX | **5.0x weniger TX** |
| **Geschädigte Opfer (Mean)** | 42.1 Personen | 11.1 Personen | **-31 Personen (-74 %)** |
| **Geschädigte Opfer (Maximal)** | 100 Personen | 31 Personen | **-69 Personen (-69 %)** |

---

### Benchmark 2: $N = 1.000$ Knoten (50 Monte-Carlo-Runs)

| Metrik | Ohne Fingerprints (Modus A) | Mit Fingerprints (Modus B) | Vorteil / Faktor |
| :--- | :--- | :--- | :--- |
| **Zeit bis Erkennung (Ticks, Mean)** | 1.503.8 Ticks | 228.6 Ticks | **6.6x schneller** |
| **Zeit bis Erkennung (Ticks, Median)** | 1.543.5 Ticks | 201.5 Ticks | **7.7x schneller** |
| **Netzwerk-Transaktionen (Mean)** | 37.583 TX | 5.702 TX | **6.6x weniger TX** |
| **Geschädigte Opfer (Mean)** | 62.1 Personen | 12.0 Personen | **-50 Personen (-81 %)** |
| **Geschädigte Opfer (Maximal)** | 123 Personen | 38 Personen | **-85 Personen (-69 %)** |

---

## 3. Ausführen der Simulation

```bash
# Standard-Lauf (500 Knoten, 50 Runs)
python3 tools/simulations/offline-gossip/simulate.py

# Großes Netzwerk (1.000 Knoten, 100 Runs)
python3 tools/simulations/offline-gossip/simulate.py --nodes 1000 --runs 100

# Distanter Betrug (Opfer in weit entfernten Regionen)
python3 tools/simulations/offline-gossip/simulate.py --nodes 500 --scenario distant
```
