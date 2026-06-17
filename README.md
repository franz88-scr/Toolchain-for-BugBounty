# Toolchain-for-BugBounty

Read Me

QuickStart auf kali linux

# 1. Repo-Dateien kopieren
cd ~/recon-pipeline

# 2. Alle Tools aus den offiziellen GitHub-Repos installieren
chmod +x install.sh
./install.sh
source ~/.bashrc   # damit ~/go/bin im PATH ist

# 3. Pipeline laufen lassen
./recon.py -d example.com

Usage:

usage: recon.py [-h] -d DOMAIN [-o OUTPUT] [--dry-run] [--force] [--yes]
                [--no-exploit] [--skip SKIP] [--only ONLY]
                [--wordlist WORDLIST] [--kite KITE] [--threads THREADS]
                [--timeout TIMEOUT]

Flag	Bedeutung
-d DOMAIN	Pflicht: Ziel-Domain (z. B. example.com)
-o DIR	Output-Verzeichnis (default ./output/<domain>)
--dry-run	Nur die Befehle anzeigen, nichts ausführen
--force	Stages neu ausführen, auch wenn Output bereits existiert
--yes	Alle interaktiven Fragen automatisch beantworten (CI-Modus)
--no-exploit	XSStrike & sqlmap überspringen (kein Risiko)
--skip subfinder,httpx	Einzelne Stages auslassen (Komma-Liste)
--only gau,waybackurls	Nur bestimmte Stages laufen lassen
--wordlist FILE	Wortliste für Gobuster
--kite FILE	.kite-Wortliste für Kiterunner
--threads N	Thread-Anzahl für Brute-Force-Stages
--timeout N	Globaler Timeout pro Stage in Sekunden

Beispiele

# Standard-Run mit allen Tools (Vorsicht: XSStrike/sqlmap sind invasiv!)
./recon.py -d example.com

# Nur Subdomain-Discovery + URL-Harvesting (passiv, keine aktiven Tests)
./recon.py -d example.com --no-exploit --only subfinder,httpx,gau,waybackurls

# Große Wortliste, schneller Brute-Force
./recon.py -d example.com --wordlist ~/wordlists/raft-large.txt --threads 50

# Nur bestimmte Stage überspringen
./recon.py -d example.com --skip sqlmap,xsstrike

# Pipeline unattended im CI laufen lassen
./recon.py -d example.com --yes --no-exploit --timeout 3600

# Trockenlauf – zeigt nur die geplanten Befehle
./recon.py -d example.com --dry-run

Outputstrucktur

output/<domain>/
├── pipeline.log                  # Komplettes Log mit Timestamps
├── summary.json                  # Maschinenlesbarer Run-Report
├── subs/
│   ├── subfinder.txt             # Stage 1: Subdomains
│   └── alive.txt                 # Stage 2: Lebende Hosts (httpx)
├── urls/
│   ├── gau.txt                   # Stage 3a: URLs aus gau
│   ├── wayback.txt               # Stage 3b: URLs aus Wayback
│   ├── gau_extra.txt             # Stage 3c: URLs aus gau (gegen lebende Hosts)
│   └── all_urls.txt              # Stage 3: dedupiertes Merge
├── js/
│   ├── js_files.txt              # Stage 4: gefundene .js-Dateien
│   └── endpoints.txt             # Stage 4: extrahierte JS-Endpoints
├── params/
│   ├── paramspider.txt           # Stage 5: URLs mit Parametern
│   └── results/                  # ParamSpider-Roh-Output
├── arjun/
│   └── arjun.json                # Stage 6: versteckte Parameter
├── bruteforce/
│   ├── gobuster.txt              # Stage 7a: Gobuster-Treffer
│   └── kiterunner.json           # Stage 7b: Kiterunner-Treffer
└── exploits/
    ├── xsstrike.txt              # Stage 8a: XSS-Findings
    ├── sqlmap.txt                # Stage 8b: SQLi-Findings
    └── sqlmap_out/               # sqlmap-Roh-Output

Architektur

recon.py
├── ANSI-Klasse C         (Farben, automatisch deaktiviert bei nicht-TTY)
├── Tool-Registry TOOLS    (alle 11 Tools + GitHub-URL + Install-Cmd)
├── Pipeline-Klasse
│   ├── check_dependencies()    interaktiver Tool-Check
│   ├── _try_install()          versucht Install-Befehl auszuführen
│   ├── _run()                  subprocess-Wrapper mit Timeout/Logging
│   ├── stage_1_subfinder()
│   ├── stage_2_httpx()
│   ├── stage_3_gau_wayback()   PARALLEL
│   ├── stage_4_linkfinder()
│   ├── stage_5_paramspider()
│   ├── stage_6_arjun()
│   ├── stage_7_bruteforce()    Gobuster + Kiterunner parallel
│   └── stage_8_exploits()      XSStrike + sqlmap (mit Confirm)
└── main()                 argparse + PATH-Setup

Tips für BugBounty

# Subdomain-Scope aus BB-Platform übergeben (eine pro Zeile)
cat scope.txt | while read d; do echo "$d" >> targets.txt; done

# Pipeline für jede Domain nacheinander (sequentiell)
while read domain; do
  ./recon.py -d "$domain" --no-exploit -o ./bounty/$(echo $domain | tr '.' '_')
done < targets.txt

# Outputs aggregieren
cat ./bounty/*/urls/all_urls.txt | sort -u > all_endpoints.txt

Troubleshooting
Problem	Lösung
command not found: subfinder	source ~/.bashrc oder export PATH=$PATH:~/go/bin
xsstrike.py: not found	git clone https://github.com/s0md3v/XSStrike ~/tools/XSStrike
Stages dauern ewig	--timeout 600 setzen oder einzelne Stages mit --skip weglassen
Zu viele Hosts für Brute-Force	--threads 5 und kürzere --wordlist
Falsche Sprache/Encoding	export LANG=C.UTF-8
