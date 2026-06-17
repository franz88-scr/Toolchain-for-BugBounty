#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 recon.py — End-to-End Recon & Vuln-Pipeline für Kali Linux
================================================================================

Verkettet die folgenden Tools (jeweils aus den offiziellen GitHub-Repos):

    subfinder  ──▶  httpx  ──▶  ( gau + waybackurls )  ──▶  LinkFinder
                                                          │
                                                          ▼
                       ParamSpider  ──▶  Arjun  ──▶  ( Gobuster | Kiterunner )
                                                          │
                                                          ▼
                                            ( XSStrike | sqlmap )

Dieses Skript ist nur der "Klebstoff". Es ruft die jeweiligen Binaries auf,
pipet die Ausgaben von Stage zu Stage und legt alles in einer
Output-Struktur ab. Es ist KEIN eigenständiges Tool, das die Scan-Logik
dupliziert - die eigentliche Arbeit macht der Code aus den jeweiligen
GitHub-Repos (siehe TOOLS-Liste unten).

Autor : Mavis
Lizenz: Nur für autorisierte Bug-Bounty-/Pentest-Targets.
================================================================================
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# =============================================================================
#  ANSI-Farben (deaktivieren, wenn nicht TTY)
# =============================================================================
class C:
    R = "\033[1;31m"; G = "\033[1;32m"; Y = "\033[1;33m"; B = "\033[1;34m"
    M = "\033[1;35m"; CY = "\033[1;36m"; W = "\033[1;37m"; DIM = "\033[2m"; N = "\033[0m"
    @classmethod
    def disable(cls):
        for a in ("R","G","Y","B","M","CY","W","DIM","N"):
            setattr(cls, a, "")
if not sys.stdout.isatty():
    C.disable()

# =============================================================================
#  Tool-Registry (alle Quellen verweisen auf die offiziellen GitHub-Repos)
# =============================================================================
@dataclass
class Tool:
    name: str
    github: str
    binary: str                       # Binary/Pfad, das im Skript geprüft wird
    install_cmd: str                   # Empfohlener Install-Befehl
    kind: str                          # go | pip | git | binary
    required: bool = True              # Muss vorhanden sein, sonst Abbruch?
    path_override: str = ""            # Absoluter Pfad, falls nicht im PATH

TOOLS: List[Tool] = [
    Tool("subfinder",    "https://github.com/projectdiscovery/subfinder",
         "subfinder",
         "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
         "go"),

    Tool("httpx",        "https://github.com/projectdiscovery/httpx",
         "httpx",
         "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
         "go"),

    Tool("gau",          "https://github.com/lc/gau",
         "gau",
         "go install github.com/lc/gau/v2/cmd/gau@latest",
         "go"),

    Tool("waybackurls",  "https://github.com/tomnomnom/waybackurls",
         "waybackurls",
         "go install github.com/tomnomnom/waybackurls@latest",
         "go"),

    Tool("LinkFinder",   "https://github.com/GerbenJavado/LinkFinder",
         "linkfinder.py",
         "git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder && "
         "pip install -r ~/tools/LinkFinder/requirements.txt",
         "git",
         path_override=str(Path.home() / "tools/LinkFinder/linkfinder.py")),

    Tool("ParamSpider",  "https://github.com/devanshbatham/ParamSpider",
         "paramspider.py",
         "git clone https://github.com/devanshbatham/ParamSpider.git ~/tools/ParamSpider",
         "git",
         path_override=str(Path.home() / "tools/ParamSpider/paramspider.py")),

    Tool("Arjun",        "https://github.com/s0md3v/Arjun",
         "arjun",
         "pip install arjun",
         "pip"),

    Tool("Gobuster",     "https://github.com/OJ/gobuster",
         "gobuster",
         "go install github.com/OJ/gobuster/v3@latest",
         "go"),

    Tool("Kiterunner",   "https://github.com/assetnote/kiterunner",
         "kr",
         "siehe install.sh (Binary-Release von GitHub)",
         "binary",
         required=False),  # Gobuster ist Alternative

    Tool("XSStrike",     "https://github.com/s0md3v/XSStrike",
         "xsstrike.py",
         "git clone https://github.com/s0md3v/XSStrike.git ~/tools/XSStrike && "
         "pip install -r ~/tools/XSStrike/requirements.txt",
         "git",
         required=False,   # Exploit-Tools – bestätigungspflichtig
         path_override=str(Path.home() / "tools/XSStrike/xsstrike.py")),

    Tool("sqlmap",       "https://github.com/sqlmapproject/sqlmap",
         "sqlmap",
         "git clone https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap",
         "git",
         required=False,   # Exploit-Tools – bestätigungspflichtig
         path_override=str(Path.home() / "tools/sqlmap/sqlmap.py")),
]

# =============================================================================
#  Pipeline-Klasse
# =============================================================================
class Pipeline:
    BANNER = (
        f"{C.CY}╔══════════════════════════════════════════════════════════════╗\n"
        f"║{C.W}              recon.py — Recon & Vuln Pipeline                 {C.CY}║\n"
        f"║{C.DIM}     subfinder → httpx → gau+waybackurls → LinkFinder →      {C.CY}║\n"
        f"║{C.DIM}     ParamSpider → Arjun → Gobuster/Kiterunner →             {C.CY}║\n"
        f"║{C.DIM}     XSStrike / sqlmap                                      {C.CY}║\n"
        f"╚══════════════════════════════════════════════════════════════╝{C.N}"
    )

    def __init__(self, args: argparse.Namespace):
        self.domain: str = args.domain
        self.out: Path = Path(args.output).expanduser().resolve()
        self.dry: bool = args.dry_run
        self.skip: set = set(s.lower() for s in (args.skip or []))
        self.only: set = set(s.lower() for s in (args.only or []))
        self.wordlist: Path = Path(args.wordlist).expanduser()
        self.kite: Path = Path(args.kite).expanduser()
        self.no_exploit: bool = args.no_exploit
        self.threads: int = args.threads
        self.timeout: int = args.timeout
        self.yes: bool = args.yes
        self.force: bool = args.force
        self.results: Dict[str, dict] = {}
        self.binaries: Dict[str, str] = {}    # name → resolved path
        self.start_time = time.time()

        # Output-Struktur
        for sub in ("subs", "urls", "js", "params", "arjun", "bruteforce", "exploits"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ Utils
    def _logfile(self) -> Path:
        return self.out / "pipeline.log"

    def log(self, msg: str) -> None:
        print(msg)
        with open(self._logfile(), "a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def info(self, m): self.log(f"{C.CY}[*]{C.N} {m}")
    def ok(self, m):   self.log(f"{C.G}[+]{C.N} {m}")
    def warn(self, m): self.log(f"{C.Y}[!]{C.N} {m}")
    def err(self, m):  self.log(f"{C.R}[-]{C.N} {m}")
    def head(self, m): self.log(f"\n{C.B}{C.W}▶ {m}{C.N}\n" + "─" * 64)

    # ---------------------------------------------------------------- File IO
    def _read(self, p: Path) -> List[str]:
        if not p.exists(): return []
        return [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()]

    def _write(self, p: Path, lines: List[str]) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        # Deduplizieren und sortieren
        uniq = sorted(set(l.strip() for l in lines if l.strip()))
        p.write_text("\n".join(uniq) + ("\n" if uniq else ""))

    def _count(self, p: Path) -> int:
        return len(self._read(p))

    # ------------------------------------------------------------------ Tools
    def _resolve(self, tool: Tool) -> Optional[str]:
        if tool.path_override:
            p = Path(os.path.expanduser(tool.path_override))
            if p.exists(): return str(p)
            return None
        return shutil.which(tool.binary)

    def _prompt_yes_no(self, q: str, default_yes: bool = False) -> bool:
        if self.yes: return True
        suf = "[J/n]" if default_yes else "[j/N]"
        while True:
            try:
                ans = input(f"{C.Y}?{C.N} {q} {suf}: ").strip().lower()
            except EOFError:
                return default_yes
            if not ans: return default_yes
            if ans in ("j","ja","y","yes"): return True
            if ans in ("n","nein","no"): return False

    def _prompt_choice(self, q: str, options: List[str]) -> str:
        """Fragt ab, gibt das gewählte Element aus options zurück (oder 'q')."""
        opts = "/".join(options + ["q=quit"])
        while True:
            try:
                ans = input(f"{C.Y}?{C.N} {q} ({opts}): ").strip().lower()
            except EOFError:
                return "q"
            if ans in ("q","quit","exit"): return "q"
            if ans in options: return ans
            print(f"  {C.DIM}bitte eine der Optionen: {opts}{C.N}")

    def check_dependencies(self) -> bool:
        """Prüft alle Tools, fragt interaktiv bei fehlenden nach Aktion."""
        self.head("Prüfe Tool-Verfügbarkeit")
        missing_required: List[Tool] = []

        for tool in TOOLS:
            path = self._resolve(tool)
            if path:
                self.binaries[tool.name] = path
                self.ok(f"{tool.name:14s} → {C.DIM}{path}{C.N}")
            else:
                self.err(f"{tool.name:14s} → NICHT GEFUNDEN  {C.DIM}({tool.github}){C.N}")
                if tool.required:
                    missing_required.append(tool)

        # Interaktive Nachfrage für jedes fehlende Tool
        for tool in TOOLS:
            if tool.name in self.binaries:
                continue
            self.warn(f"\nFehlt: {tool.name}")
            self.log(f"    Quelle:    {tool.github}")
            self.log(f"    Install:   {tool.install_cmd}")

            # Bei --yes: für required → install versuchen, sonst skip
            if self.yes:
                choice = "install" if tool.required else "skip"
                self.info(f"--yes aktiv → automatische Wahl: {choice}")
            else:
                choice = self._prompt_choice(
                    f"Was tun mit '{tool.name}'?",
                    ["install", "skip", "abort"]
                )
            if choice == "abort":
                self.err("Abbruch auf Wunsch des Users.")
                return False
            elif choice == "install":
                ok = self._try_install(tool)
                if ok:
                    path = self._resolve(tool)
                    if path:
                        self.binaries[tool.name] = path
                        self.ok(f"{tool.name} jetzt verfügbar: {path}")
                    else:
                        self.warn(f"{tool.name} wurde installiert, aber nicht im PATH/Pfad gefunden.")
                        if tool.required:
                            missing_required.append(tool)
                else:
                    self.err(f"Installation von {tool.name} fehlgeschlagen.")
                    if tool.required:
                        missing_required.append(tool)
            elif choice == "skip":
                self.warn(f"Überspringe {tool.name}.")
                if tool.required:
                    missing_required.append(tool)

        if missing_required:
            self.err(f"\nFehlende Pflicht-Tools: {[t.name for t in missing_required]}")
            return False
        return True

    def _try_install(self, tool: Tool) -> bool:
        """Versucht, ein Tool zu installieren. Gibt True bei Erfolg zurück."""
        self.info(f"Versuche {tool.name} zu installieren: {tool.install_cmd}")
        try:
            # Bei 'git clone' brauchen wir kein sudo; bei 'go install' meistens auch nicht
            shell_cmd = tool.install_cmd
            if tool.kind in ("pip",) and "pip install" in shell_cmd:
                shell_cmd = shell_cmd.replace("pip install",
                    "python3 -m pip install --quiet --break-system-packages")
            proc = subprocess.run(
                shell_cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=600,
            )
            self.log(f"{C.DIM}    {proc.stdout.decode(errors='ignore')[-500:]}{C.N}")
            return proc.returncode == 0
        except Exception as e:
            self.err(f"Installations-Fehler: {e}")
            return False

    # ------------------------------------------------------------------ Runner
    def _run(self, cmd: List[str], *,
             stdin_file: Optional[Path] = None,
             stdout_file: Optional[Path] = None,
             timeout: Optional[int] = None,
             env: Optional[dict] = None,
             check: bool = False) -> Tuple[int, str]:
        """Führt einen Befehl aus, leitet optional stdin/stdout in Dateien um."""
        if self.dry:
            self.info(f"[DRY] {' '.join(cmd)}")
            return 0, ""

        if stdout_file:
            stdout_file.parent.mkdir(parents=True, exist_ok=True)

        full_env = os.environ.copy()
        if env: full_env.update(env)
        # PATH um ~/go/bin und ~/tools/* erweitern
        extra = f"{os.path.expanduser('~/go/bin')}:{os.path.expanduser('~/tools')}"
        full_env["PATH"] = extra + ":" + full_env.get("PATH", "")

        stdin_handle = open(stdin_file, "rb") if stdin_file else None
        stdout_handle = open(stdout_file, "wb") if stdout_file else None

        try:
            proc = subprocess.run(
                cmd,
                stdin=stdin_handle, stdout=stdout_handle, stderr=subprocess.PIPE,
                timeout=timeout or self.timeout, env=full_env,
            )
            err_out = proc.stderr.decode(errors="ignore")
            return proc.returncode, err_out
        except subprocess.TimeoutExpired:
            self.err(f"Timeout nach {timeout or self.timeout}s: {' '.join(cmd)}")
            return 124, "timeout"
        except FileNotFoundError as e:
            self.err(f"Binary nicht gefunden: {e}")
            return 127, str(e)
        finally:
            if stdin_handle: stdin_handle.close()
            if stdout_handle: stdout_handle.close()

    def _should_run(self, stage: str) -> bool:
        if self.only:
            return stage.lower() in self.only
        if self.skip:
            return stage.lower() not in self.skip
        return True

    def _stage_result(self, name: str, output: Path, cmd: List[str], rc: int) -> None:
        cnt = self._count(output) if output.exists() else 0
        self.results[name] = {
            "output": str(output), "lines": cnt, "command": " ".join(cmd), "rc": rc,
        }
        badge = f"{C.G}OK{C.N}" if rc == 0 else f"{C.Y}RC={rc}{C.N}"
        self.ok(f"Stage {name}: {cnt} Einträge in {output.relative_to(self.out)} [{badge}]")

    # ========================================================================
    #  STAGES
    # ========================================================================
    def stage_1_subfinder(self) -> Path:
        self.head("Stage 1/8: subfinder  (Subdomain-Enumeration)")
        out = self.out / "subs" / "subfinder.txt"
        if out.exists() and not self.force:
            self.warn(f"Output existiert bereits ({self._count(out)} subs). --force zum Neu-Run.")
            return out
        cmd = [self.binaries["subfinder"], "-d", self.domain, "-all", "-silent"]
        rc, err = self._run(cmd, stdout_file=out)
        if rc != 0 and err:
            self.warn(err.strip().splitlines()[-1] if err else "")
        self._stage_result("subfinder", out, cmd, rc)
        return out

    def stage_2_httpx(self, subs_file: Path) -> Path:
        self.head("Stage 2/8: httpx  (HTTP-Probing / lebende Hosts)")
        out = self.out / "subs" / "alive.txt"
        if not subs_file.exists() or self._count(subs_file) == 0:
            self.warn("Keine Subdomains – überspringe httpx.")
            return out
        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn(f"Output existiert bereits. --force zum Neu-Run.")
            return out
        cmd = [
            self.binaries["httpx"], "-l", str(subs_file),
            "-silent", "-follow-redirects",
            "-status-code", "-title", "-tech-detect",
            "-o", str(out),
        ]
        rc, err = self._run(cmd)
        if rc != 0 and err:
            self.warn(err.strip().splitlines()[-1] if err else "")
        self._stage_result("httpx", out, cmd, rc)
        return out

    def stage_3_gau_wayback(self, alive_file: Path) -> Path:
        """gau und waybackurls laufen PARALLEL und werden gemerged."""
        self.head("Stage 3/8: gau + waybackurls  (URL-Harvesting, parallel)")
        out = self.out / "urls" / "all_urls.txt"
        gau_raw = self.out / "urls" / "gau.txt"
        wb_raw = self.out / "urls" / "wayback.txt"

        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn(f"Output existiert bereits ({self._count(out)} URLs).")
            return out

        def run_gau():
            cmd = [self.binaries["gau"], "--subs", self.domain, "--threads", "5"]
            return ("gau", cmd, gau_raw)

        def run_wb():
            cmd = [self.binaries["waybackurls"], self.domain]
            return ("waybackurls", cmd, wb_raw)

        # Optional: zusätzlich mit jeder lebenden Domain aus alive_file
        # → waybackurls/gau akzeptieren aber Domain, nicht URL; daher nur Hauptdomain.
        jobs = [run_gau(), run_wb()]

        # Falls alive-Datei URLs enthält, gau auch gegen diese laufen lassen
        if alive_file.exists() and self._count(alive_file) > 0:
            extra_hosts = self.out / "urls" / "gau_extra.txt"
            hosts = set()
            for line in self._read(alive_file):
                m = re.match(r"https?://([^/]+)", line)
                if m: hosts.add(m.group(1))
            if hosts:
                cmd = [self.binaries["gau"], "--subs"] + sorted(hosts) + ["--threads", "5"]
                jobs.append(("gau-extra", cmd, extra_hosts))
            else:
                self.warn("Keine Hostnamen aus alive.txt extrahierbar – gau-extra entfällt.")

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futures = {ex.submit(self._run, cmd, stdout_file=outf, timeout=300):
                       (name, cmd, outf) for name, cmd, outf in jobs}
            for fut in concurrent.futures.as_completed(futures):
                name, cmd, outf = futures[fut]
                try:
                    rc, err = fut.result()
                    self._stage_result(name, outf, cmd, rc)
                except Exception as e:
                    self.err(f"{name} crashed: {e}")

        # Mergen + dedup
        merged: List[str] = []
        for f in [gau_raw, wb_raw, self.out / "urls" / "gau_extra.txt"]:
            if f.exists():
                merged.extend(self._read(f))
        self._write(out, merged)
        self.ok(f"Total nach Merge + Dedup: {self._count(out)} unique URLs")
        return out

    def stage_4_linkfinder(self, urls_file: Path) -> Path:
        self.head("Stage 4/8: LinkFinder  (JS-Endpoints extrahieren)")
        js_files = self.out / "js" / "js_files.txt"
        out = self.out / "js" / "endpoints.txt"

        if not urls_file.exists() or self._count(urls_file) == 0:
            self.warn("Keine URLs – überspringe LinkFinder.")
            return out

        # 1) JS-Dateien aus URLs extrahieren
        js_urls: set = set()
        for line in self._read(urls_file):
            for m in re.findall(r"https?://[^\s\"'<>]+\.js", line, re.IGNORECASE):
                js_urls.add(m)
        self._write(js_files, list(js_urls))
        self.info(f"{len(js_urls)} eindeutige .js-Dateien gefunden")

        if not js_urls:
            self.warn("Keine JS-Dateien – LinkFinder übersprungen.")
            return out

        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn("LinkFinder-Output existiert bereits.")
            return out

        # 2) LinkFinder pro JS-URL aufrufen, parsen
        # LinkFinder CLI: python linkfinder.py -i <url|file> -o <out.html>
        # Wir parsen die HTML-Ausgabe nach Endpoints.
        lf_bin = self.binaries["LinkFinder"]
        all_endpoints: List[str] = []
        for js in js_urls:
            tmp_html = self.out / "js" / f"_lf_{abs(hash(js))}.html"
            cmd = ["python3", lf_bin, "-i", js, "-o", str(tmp_html)]
            rc, err = self._run(cmd, timeout=120)
            if rc == 0 and tmp_html.exists():
                # Endpoints aus HTML kratzen: jede Zeile mit http(s) ist ein Endpoint
                eps = re.findall(r"https?://[^\s\"'<>]+", tmp_html.read_text(errors="ignore"))
                all_endpoints.extend(eps)
            tmp_html.unlink(missing_ok=True)

        self._write(out, all_endpoints)
        self._stage_result("linkfinder", out, ["linkfinder"], 0)
        return out

    def stage_5_paramspider(self) -> Path:
        self.head("Stage 5/8: ParamSpider  (URLs mit Parametern)")
        out = self.out / "params" / "paramspider.txt"
        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn("ParamSpider-Output existiert bereits.")
            return out
        ps_bin = self.binaries["ParamSpider"]
        cmd = [
            "python3", ps_bin,
            "--domain", self.domain,
            "--exclude", "woff,css,png,jpg,jpeg,svg,gif,ico,woff2,ttf",
            "--output", str(self.out / "params"),
            "--level", "high",
        ]
        rc, err = self._run(cmd, timeout=600)
        # ParamSpider schreibt results/<domain>.txt
        default_out = self.out / "params" / "results" / f"{self.domain}.txt"
        if default_out.exists():
            self._write(out, self._read(default_out))
        self._stage_result("paramspider", out, cmd, rc)
        return out

    def stage_6_arjun(self, params_file: Path) -> Path:
        self.head("Stage 6/8: Arjun  (versteckte Parameter entdecken)")
        out = self.out / "arjun" / "arjun.json"
        if not params_file.exists() or self._count(params_file) == 0:
            self.warn("Keine parametrisierten URLs – überspringe Arjun.")
            return out
        if out.exists() and out.stat().st_size > 0 and not self.force:
            self.warn("Arjun-Output existiert bereits.")
            return out

        # Arjun kann -i <file> (Liste URLs) verwenden
        cmd = [
            self.binaries["arjun"],
            "-i", str(params_file),
            "-oJ", str(out),
            "--stable", "--passive",
        ]
        rc, err = self._run(cmd, timeout=900)
        if rc != 0 and err:
            # Fallback: ohne --passive
            self.warn("Fallback: Arjun ohne --passive")
            cmd = [self.binaries["arjun"], "-i", str(params_file),
                   "-oJ", str(out), "--stable"]
            rc, err = self._run(cmd, timeout=900)
        self._stage_result("arjun", out, cmd, rc)
        return out

    def stage_7_bruteforce(self, alive_file: Path) -> Tuple[Path, Path]:
        """Gobuster + Kiterunner parallel."""
        self.head("Stage 7/8: Gobuster & Kiterunner  (Directory/API-Brute-Force)")
        gob_out = self.out / "bruteforce" / "gobuster.txt"
        kr_out = self.out / "bruteforce" / "kiterunner.json"

        if not alive_file.exists() or self._count(alive_file) == 0:
            self.warn("Keine lebenden Hosts – überspringe Bruteforce.")
            return gob_out, kr_out

        # Wir nehmen die ersten N Hosts, um nicht ausufernd zu werden
        alive_lines_all = self._read(alive_file)
        alive_lines = alive_lines_all[: max(1, min(5, len(alive_lines_all)))]
        self.info(f"Bruteforce gegen {len(alive_lines)} Hosts")

        # Gobuster
        if self._should_run("gobuster") and "Gobuster" in self.binaries:
            gob_raw = self.out / "bruteforce" / "gobuster_raw.txt"
            gob_raw.unlink(missing_ok=True)
            with open(gob_raw, "a") as fout:
                for host in alive_lines:
                    base = re.match(r"(https?://[^/]+)", host)
                    if not base: continue
                    cmd = [
                        self.binaries["gobuster"], "dir",
                        "-u", base.group(1),
                        "-w", str(self.wordlist),
                        "-q", "-t", str(self.threads),
                        "-o", str(self.out / "bruteforce" / f"gob_{abs(hash(host))}.txt"),
                        "-b", "404,403",
                    ]
                    rc, _ = self._run(cmd, timeout=600)
                    # Outputs sammeln
                    single = self.out / "bruteforce" / f"gob_{abs(hash(host))}.txt"
                    if single.exists():
                        fout.write(f"\n# === {host} ===\n")
                        fout.write(single.read_text())
                        single.unlink()
            self._write(gob_out, self._read(gob_raw))
            self._stage_result("gobuster", gob_out, ["gobuster"], 0)
        else:
            self.warn("Gobuster übersprungen / nicht verfügbar.")

        # Kiterunner (optional, falls vorhanden)
        if "Kiterunner" in self.binaries and self.binaries["Kiterunner"]:
            kr_raw = self.out / "bruteforce" / "kr_raw.json"
            kr_raw.unlink(missing_ok=True)
            for host in alive_lines:
                base = re.match(r"(https?://[^/]+)", host)
                if not base: continue
                cmd = [
                    self.binaries["Kiterunner"], "scan",
                    base.group(1),
                    "-w", str(self.kite),
                    "--json", "-q",
                ]
                rc, _ = self._run(cmd, timeout=300,
                                  stdout_file=kr_raw.with_name(f"kr_{abs(hash(host))}.json"))
            # Merge aller KR-JSONs
            merged: List[str] = []
            for f in (self.out / "bruteforce").glob("kr_*.json"):
                if f.exists():
                    merged.extend(self._read(f))
                    f.unlink()
            self._write(kr_out, merged)
            self._stage_result("kiterunner", kr_out, ["kiterunner"], 0)
        else:
            self.warn("Kiterunner nicht verfügbar – übersprungen.")

        return gob_out, kr_out

    def stage_8_exploits(self, params_file: Path, alive_file: Path) -> Tuple[Path, Path]:
        """XSStrike & sqlmap. Diese sind invasiv → Bestätigung erforderlich."""
        self.head("Stage 8/8: XSStrike & sqlmap  (aktive Tests)")
        xs_out = self.out / "exploits" / "xsstrike.txt"
        sq_out = self.out / "exploits" / "sqlmap.txt"

        if self.no_exploit:
            self.warn("Exploit-Stages übersprungen (--no-exploit).")
            return xs_out, sq_out

        # Zielauswahl: URLs mit Parametern + Alive-Hosts
        targets: List[str] = []
        if params_file.exists():
            targets.extend(self._read(params_file)[:20])
        if not targets and alive_file.exists():
            targets.extend(self._read(alive_file)[:5])
        targets = sorted(set(targets))[:20]
        if not targets:
            self.warn("Keine Ziele für Exploit-Stages.")
            return xs_out, sq_out

        self.warn(f"Aktive Tests gegen {len(targets)} Ziele. Diese sind INVASIV.")
        self.warn(f"Stelle sicher, dass Du eine schriftliche Autorisierung für "
                  f"'{self.domain}' hast.")
        if not self._prompt_yes_no("Exploit-Stages jetzt wirklich ausführen?", default_yes=False):
            self.warn("Exploit-Stages vom User abgebrochen.")
            return xs_out, sq_out

        # XSStrike
        if "XSStrike" in self.binaries:
            xs_raw = self.out / "exploits" / "xsstrike_raw.txt"
            xs_raw.unlink(missing_ok=True)
            xs_bin = self.binaries["XSStrike"]
            for url in targets:
                if "?" not in url:
                    url = url.rstrip("/") + "/?q=test"
                cmd = ["python3", xs_bin, "-u", url,
                       "--crawl", "--blind", "--timeout", "10", "--skip-dom"]
                rc, _ = self._run(cmd, timeout=300,
                                  stdout_file=xs_raw.with_name(f"xs_{abs(hash(url))}.txt"))
            merged = []
            for f in (self.out / "exploits").glob("xs_*.txt"):
                merged.extend(self._read(f))
                f.unlink()
            self._write(xs_out, merged)
            self._stage_result("xsstrike", xs_out, ["xsstrike"], 0)
        else:
            self.warn("XSStrike nicht verfügbar.")

        # sqlmap
        if "sqlmap" in self.binaries:
            sq_raw = self.out / "exploits" / "sqlmap_raw.txt"
            sq_raw.unlink(missing_ok=True)
            sq_bin = self.binaries["sqlmap"]
            for url in targets:
                cmd = ["python3", sq_bin, "-u", url,
                       "--batch", "--random-agent", "--level=2", "--risk=1",
                       "--threads=2", "--timeout=10",
                       "--output-dir", str(self.out / "exploits" / "sqlmap_out")]
                rc, _ = self._run(cmd, timeout=300)
            self._write(sq_out, self._read(sq_raw))
            self._stage_result("sqlmap", sq_out, ["sqlmap"], 0)
        else:
            self.warn("sqlmap nicht verfügbar.")

        return xs_out, sq_out

    # ========================================================================
    #  MAIN RUN
    # ========================================================================
    def run(self) -> None:
        self.log(self.BANNER)
        self.log(f"{C.B}Ziel   :{C.N} {self.domain}")
        self.log(f"{C.B}Output :{C.N} {self.out}")
        self.log(f"{C.B}Start  :{C.N} {datetime.now().isoformat()}\n")

        if not self.check_dependencies():
            self.err("Abhängigkeiten nicht erfüllt – Abbruch.")
            sys.exit(2)

        # Pipeline ausführen
        subs = self.stage_1_subfinder()
        alive = self.stage_2_httpx(subs)
        urls = self.stage_3_gau_wayback(alive)
        js_endpoints = self.stage_4_linkfinder(urls)
        params = self.stage_5_paramspider()
        arjun = self.stage_6_arjun(params)
        gob, kr = self.stage_7_bruteforce(alive)
        xs, sq = self.stage_8_exploits(params, alive)

        # Summary
        self._print_summary()
        self._write_summary()

    def _print_summary(self) -> None:
        dur = time.time() - self.start_time
        self.head(f"Pipeline abgeschlossen in {dur:.1f}s")
        self.log(f"{C.W}Stage            Datei                                           Einträge{C.N}")
        self.log("─" * 72)
        for name, info in self.results.items():
            try:
                rel = Path(info["output"]).relative_to(self.out)
            except ValueError:
                rel = Path(info["output"]).name
            self.log(f"  {name:14s} {C.DIM}{str(rel):45s}{C.N}  {C.G}{info['lines']}{C.N}")
        self.log("")
        self.ok(f"Alle Artefakte liegen in: {C.W}{self.out}{C.N}")
        self.ok(f"Log-Datei:                 {C.W}{self._logfile()}{C.N}")

    def _write_summary(self) -> None:
        s = {
            "domain": self.domain,
            "output": str(self.out),
            "duration_seconds": round(time.time() - self.start_time, 1),
            "finished": datetime.now().isoformat(),
            "tools_used": list(self.binaries.keys()),
            "stages": self.results,
        }
        (self.out / "summary.json").write_text(json.dumps(s, indent=2))


# =============================================================================
#  CLI
# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Verkettet subfinder → httpx → gau+waybackurls → LinkFinder → "
                    "ParamSpider → Arjun → Gobuster/Kiterunner → XSStrike/sqlmap "
                    "(jeweils aus den offiziellen GitHub-Repos).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Beispiel:
  {C.CY}./recon.py -d example.com{C.N}
  {C.CY}./recon.py -d example.com --no-exploit --only subfinder,httpx{C.N}
  {C.CY}./recon.py -d example.com --wordlist ~/wordlists/big.txt --threads 50{C.N}

Output landet in:  ./output/<domain>/
        """,
    )

    p.add_argument("-d", "--domain", required=True,
                   help="Ziel-Domain (z. B. example.com)")
    p.add_argument("-o", "--output", default="./output/{domain}",
                   help="Output-Verzeichnis (default: ./output/<domain>)")
    p.add_argument("--dry-run", action="store_true",
                   help="Nur Commands anzeigen, nichts ausführen")
    p.add_argument("--force", action="store_true",
                   help="Stages neu ausführen, auch wenn Output existiert")
    p.add_argument("--yes", action="store_true",
                   help="Alle interaktiven Fragen mit Ja beantworten")
    p.add_argument("--no-exploit", action="store_true",
                   help="XSStrike & sqlmap überspringen")
    p.add_argument("--skip", default="",
                   help="Komma-getrennte Liste Stages zum Überspringen "
                        "(subfinder,httpx,gau,waybackurls,linkfinder,paramspider,"
                        "arjun,gobuster,kiterunner,xsstrike,sqlmap)")
    p.add_argument("--only", default="",
                   help="Nur diese Stages ausführen (Komma-Liste)")
    p.add_argument("--wordlist", default=str(Path.home() / "wordlists/directory-list-2.3-medium.txt"),
                   help="Wortliste für Gobuster")
    p.add_argument("--kite", default=str(Path.home() / "tools/kiterunner-wordlists/large.kite"),
                   help="Kiterunner-Wortliste (.kite)")
    p.add_argument("--threads", type=int, default=20,
                   help="Thread-Anzahl für Brute-Force-Stages")
    p.add_argument("--timeout", type=int, default=1800,
                   help="Globaler Timeout pro Stage (Sekunden)")

    args = p.parse_args()
    args.output = args.output.format(domain=args.domain)
    if args.skip:   args.skip   = [s.strip() for s in args.skip.split(",") if s.strip()]
    if args.only:   args.only   = [s.strip() for s in args.only.split(",") if s.strip()]

    # PATH-Vorbereitung (für Go-Tools ohne 'source ~/.bashrc')
    extra = f"{os.path.expanduser('~/go/bin')}:{os.path.expanduser('~/tools')}"
    os.environ["PATH"] = extra + ":" + os.environ.get("PATH", "")

    try:
        Pipeline(args).run()
    except KeyboardInterrupt:
        print(f"\n{C.Y}Abbruch durch User.{C.N}")
        sys.exit(130)


if __name__ == "__main__":
    main()
