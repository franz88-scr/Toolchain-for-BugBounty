# Toolchain-for-BugBounty

# Recon Pipeline

Automatisierte Reconnaissance-Pipeline für Bug Bounty und Pentesting auf Kali Linux.

## Quick Start

### 1. Repository-Dateien kopieren

```bash
cd ~/recon-pipeline
```

### 2. Alle Tools aus den offiziellen GitHub-Repositories installieren

```bash
chmod +x install.sh
./install.sh
source ~/.bashrc
```

> Dadurch wird sichergestellt, dass `~/go/bin` im PATH verfügbar ist.

### 3. Pipeline starten

```bash
./recon.py -d example.com
```

---

# Usage

```text
usage: recon.py [-h] -d DOMAIN [-o OUTPUT] [--dry-run] [--force] [--yes]
                [--no-exploit] [--skip SKIP] [--only ONLY]
                [--wordlist WORDLIST] [--kite KITE] [--threads THREADS]
                [--timeout TIMEOUT] [--rate-limit RATE_LIMIT]
                [--linkfinder-workers LINKFINDER_WORKERS]
```

## Optionen

| Flag | Beschreibung |
|--------|-------------|
| `-d DOMAIN` | Pflichtparameter. Ziel-Domain (z. B. `example.com`) |
| `-o DIR` | Output-Verzeichnis (Standard: `./output/<domain>`) |
| `--dry-run` | Zeigt nur die geplanten Befehle an, führt nichts aus |
| `--force` | Führt Stages erneut aus, auch wenn bereits Ergebnisse vorhanden sind |
| `--yes` | Beantwortet alle interaktiven Fragen automatisch |
| `--no-exploit` | Überspringt XSStrike und sqlmap |
| `--skip subfinder,httpx` | Einzelne Stages überspringen |
| `--only gau,waybackurls` | Nur bestimmte Stages ausführen |
| `--wordlist FILE` | Eigene Wortliste für Gobuster |
| `--kite FILE` | Eigene Wortliste für Kiterunner |
| `--threads N` | Anzahl der Threads für Brute-Force-Stages |
| `--timeout N` | Globaler Timeout pro Stage in Sekunden |
| `--rate-limit N` | Rate-Limit für httpx in Requests pro Sekunde (`0` = Tool-Default) |
| `--linkfinder-workers N` | Parallele Worker für die LinkFinder-Stage |

---

# Beispiele

## Standardlauf

> Achtung: XSStrike und sqlmap führen aktive Tests durch.

```bash
./recon.py -d example.com
```

## Passive Recon

Nur Subdomain-Discovery und URL-Harvesting:

```bash
./recon.py -d example.com \
  --no-exploit \
  --only subfinder,httpx,gau,waybackurls
```

## Große Wortliste mit mehr Threads

```bash
./recon.py -d example.com \
  --wordlist ~/wordlists/raft-large.txt \
  --threads 50
```

## Bestimmte Stages überspringen

```bash
./recon.py -d example.com \
  --skip sqlmap,xsstrike
```

## Unattended / CI-Modus

```bash
./recon.py -d example.com \
  --yes \
  --no-exploit \
  --timeout 3600
```

## Trockenlauf

```bash
./recon.py -d example.com --dry-run
```

---

# Output-Struktur

```text
output/<domain>/
├── pipeline.log
├── summary.json
├── subs/
│   ├── subfinder.txt
│   └── alive.txt
├── urls/
│   ├── gau.txt
│   ├── wayback.txt
│   ├── gau_extra.txt
│   └── all_urls.txt
├── js/
│   ├── js_files.txt
│   └── endpoints.txt
├── params/
│   ├── paramspider.txt
│   └── results/
├── arjun/
│   └── arjun.json
├── bruteforce/
│   ├── gobuster.txt
│   └── kiterunner.json
└── exploits/
    ├── xsstrike.txt
    ├── sqlmap.txt
    └── sqlmap_out/
```

---

# Architektur

```text
recon.py
├── ANSI-Klasse
│   └── Farben (automatisch deaktiviert bei nicht-TTY)
│
├── Tool-Registry (TOOLS)
│   └── Enthält alle Tools, GitHub-URLs und Installationsbefehle
│
├── Pipeline
│   ├── check_dependencies()
│   ├── _try_install()
│   ├── _run()
│   ├── stage_1_subfinder()
│   ├── stage_2_httpx()
│   ├── stage_3_gau_wayback()      (parallel)
│   ├── stage_4_linkfinder()
│   ├── stage_5_paramspider()
│   ├── stage_6_arjun()
│   ├── stage_7_bruteforce()       (parallel)
│   └── stage_8_exploits()
│
└── main()
    └── argparse + PATH-Setup
```

---

# Bug-Bounty-Workflows

## Scope-Datei vorbereiten

```bash
cat scope.txt | while read d; do
  echo "$d" >> targets.txt
done
```

## Mehrere Domains nacheinander scannen

```bash
while read domain; do
  ./recon.py \
    -d "$domain" \
    --no-exploit \
    -o "./bounty/$(echo "$domain" | tr '.' '_')"
done < targets.txt
```

## Ergebnisse aggregieren

```bash
cat ./bounty/*/urls/all_urls.txt | sort -u > all_endpoints.txt
```

---

# Troubleshooting

| Problem | Lösung |
|----------|---------|
| `command not found: subfinder` | `source ~/.bashrc` oder `export PATH=$PATH:~/go/bin` |
| `xsstrike.py: not found` | Repository klonen: `git clone https://github.com/s0md3v/XSStrike ~/tools/XSStrike` |
| Stages dauern sehr lange | `--timeout 600` setzen oder einzelne Stages überspringen |
| Zu viele Hosts für Brute Force | `--threads 5` und kleinere Wortliste verwenden |
| Falsche Sprache oder Encoding | `export LANG=C.UTF-8` |
| `--domain` wird abgelehnt | Nur Domainnamen ohne Schema/Pfad verwenden, z. B. `example.com` statt `https://example.com/` |

---

# Hinweise

Diese Pipeline kombiniert mehrere bekannte Recon-Tools zu einem automatisierten Workflow für:

* Subdomain Discovery
* Alive Host Detection
* URL Harvesting
* JavaScript Endpoint Discovery
* Parameter Discovery
* API- und Directory-Bruteforce
* Optionale XSS- und SQLi-Prüfungen

Verwende aktive Tests ausschließlich auf Systemen, für die du eine ausdrückliche Berechtigung besitzt.
