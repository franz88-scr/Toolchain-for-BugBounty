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

Autor : franz88-scr
Lizenz: Nur für autorisierte Bug-Bounty-/Pentest-Targets.

Changelog (gegenüber v1):
  • Bugfix: Tool-Lookup normalisiert auf lowercase-Keys (KeyError in Stage 6/7 behoben)
  • Bugfix: sqlmap-Output wird jetzt tatsächlich geschrieben und gemerged
  • Bugfix: --dry-run führt keine echten Install-Befehle mehr aus
  • Verbesserung: LinkFinder läuft parallel statt seriell
  • Verbesserung: bessere Hostname-Extraktion aus httpx-Output
  • Verbesserung: gau-extra nutzt --list statt vieler CLI-Argumente
  • Verbesserung: Kiterunner respektiert --skip
  • Verbesserung: defensive Checks in allen Stages (kein KeyError bei übersprungenen Tools)
  • Verbesserung: Tempfiles via uuid statt hash() (kollisionsfrei, deterministisch lesbar)
================================================================================
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

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
#  Tool-Registry
#
#  name          : canonicaler Lookup-Key (lowercase). Wird in self.binaries genutzt.
#  display       : menschenlesbarer Name für Print-Ausgabe.
#  binary        : Binary-Name, das in PATH gesucht wird (shutil.which).
#  path_override : absoluter Pfad zum Binary, falls nicht in PATH installiert.
#  required      : True → Pipeline bricht ab, wenn das Tool fehlt.
# =============================================================================
@dataclass(frozen=True)
class Tool:
    name: str
    display: str
    github: str
    binary: str
    install_cmd: str
    kind: str                          # go | pip | git | binary
    required: bool = True
    path_override: str = ""


TOOLS: List[Tool] = [
    Tool("subfinder",   "subfinder",
         "https://github.com/projectdiscovery/subfinder",
         "subfinder",
         "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
         "go"),

    Tool("httpx",       "httpx",
         "https://github.com/projectdiscovery/httpx",
         "httpx",
         "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
         "go"),

    Tool("gau",         "gau",
         "https://github.com/lc/gau",
         "gau",
         "go install github.com/lc/gau/v2/cmd/gau@latest",
         "go"),

    Tool("waybackurls", "waybackurls",
         "https://github.com/tomnomnom/waybackurls",
         "waybackurls",
         "go install github.com/tomnomnom/waybackurls@latest",
         "go"),

    Tool("linkfinder",  "LinkFinder",
         "https://github.com/GerbenJavado/LinkFinder",
         "linkfinder.py",
         "git clone https://github.com/GerbenJavado/LinkFinder.git "
         "$HOME/tools/LinkFinder && pip install -r $HOME/tools/LinkFinder/requirements.txt",
         "git",
         path_override=str(Path.home() / "tools/LinkFinder/linkfinder.py")),

    Tool("paramspider", "ParamSpider",
         "https://github.com/devanshbatham/ParamSpider",
         "paramspider.py",
         "git clone https://github.com/devanshbatham/ParamSpider.git $HOME/tools/ParamSpider",
         "git",
         path_override=str(Path.home() / "tools/ParamSpider/paramspider.py")),

    Tool("arjun",       "Arjun",
         "https://github.com/s0md3v/Arjun",
         "arjun",
         "pip install arjun",
         "pip"),

    Tool("gobuster",    "Gobuster",
         "https://github.com/OJ/gobuster",
         "gobuster",
         "go install github.com/OJ/gobuster/v3@latest",
         "go"),

    Tool("kiterunner",  "Kiterunner",
         "https://github.com/assetnote/kiterunner",
         "kr",
         "siehe install.sh (Binary-Release von GitHub)",
         "binary",
         required=False),  # optional, Gobuster ist Alternative

    Tool("xsstrike",    "XSStrike",
         "https://github.com/s0md3v/XSStrike",
         "xsstrike.py",
         "git clone https://github.com/s0md3v/XSStrike.git "
         "$HOME/tools/XSStrike && pip install -r $HOME/tools/XSStrike/requirements.txt",
         "git",
         required=False,   # Exploit-Tool – bestätigungspflichtig
         path_override=str(Path.home() / "tools/XSStrike/xsstrike.py")),

    Tool("sqlmap",      "sqlmap",
         "https://github.com/sqlmapproject/sqlmap",
         "sqlmap.py",
         "git clone https://github.com/sqlmapproject/sqlmap.git $HOME/tools/sqlmap",
         "git",
         required=False,   # Exploit-Tool – bestätigungspflichtig
         path_override=str(Path.home() / "tools/sqlmap/sqlmap.py")),
]

# Lookup-Map für schnellen Zugriff nach name (lowercase)
TOOL_BY_NAME: Dict[str, Tool] = {t.name: t for t in TOOLS}
VALID_STAGES: Set[str] = {t.name for t in TOOLS}
EXPLOIT_STAGES: Set[str] = {"xsstrike", "sqlmap"}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


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

    # Max. Hosts, gegen die Brute-Force / Exploits laufen sollen
    BRUTEFORCE_HOST_LIMIT = 5
    EXPLOIT_TARGET_LIMIT = 20

    def __init__(self, args: argparse.Namespace):
        self.domain: str = args.domain
        self.out: Path = Path(args.output).expanduser().resolve()
        self.dry: bool = args.dry_run
        self.skip: Set[str] = set(s.lower() for s in (args.skip or []))
        self.only: Set[str] = set(s.lower() for s in (args.only or []))
        self.wordlist: Path = Path(args.wordlist).expanduser()
        self.kite: Path = Path(args.kite).expanduser()
        self.no_exploit: bool = args.no_exploit
        self.threads: int = args.threads
        self.timeout: int = args.timeout
        self.yes: bool = args.yes
        self.force: bool = args.force
        self.rate_limit: int = args.rate_limit
        self.linkfinder_workers: int = args.linkfinder_workers

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
            # ANSI-Escapes aus dem Logfile raus halten
            f.write(_ANSI_RE.sub("", msg) + "\n")

    def info(self, m): self.log(f"{C.CY}[*]{C.N} {m}")
    def ok(self, m):   self.log(f"{C.G}[+]{C.N} {m}")
    def warn(self, m): self.log(f"{C.Y}[!]{C.N} {m}")
    def err(self, m):  self.log(f"{C.R}[-]{C.N} {m}")
    def head(self, m): self.log(f"\n{C.B}{C.W}▶ {m}{C.N}\n" + "─" * 64)

    # ---------------------------------------------------------------- File IO
    def _read(self, p: Path) -> List[str]:
        if not p.exists(): return []
        return [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()]

    def _write(self, p: Path, lines: Sequence[str]) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        uniq = sorted(set(l.strip() for l in lines if l.strip()))
        p.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")

    def _count(self, p: Path) -> int:
        return len(self._read(p))

    # ------------------------------------------------------------------ Tools
    def _resolve(self, tool: Tool) -> Optional[str]:
        if tool.path_override:
            p = Path(os.path.expanduser(tool.path_override))
            if p.exists():
                return str(p)
            # Fallback: wenn path_override definiert ist, aber Datei fehlt,
            # versuchen wir es trotzdem in PATH (z. B. bei custom install path).
            found = shutil.which(tool.binary)
            if found:
                return found
            return None
        return shutil.which(tool.binary)

    def _tool_needed(self, tool: Tool) -> bool:
        if self.no_exploit and tool.name in EXPLOIT_STAGES:
            return False
        return self._should_run(tool.name)

    @staticmethod
    def _cmd_display(cmd: Sequence[str]) -> str:
        return " ".join(shlex.quote(str(part)) for part in cmd)

    def _prompt_yes_no(self, q: str, default_yes: bool = False) -> bool:
        if self.yes: return True
        suf = "[J/n]" if default_yes else "[j/N]"
        while True:
            try:
                ans = input(f"{C.Y}?{C.N} {q} {suf}: ").strip().lower()
            except EOFError:
                return default_yes
            if not ans: return default_yes
            if ans in ("j", "ja", "y", "yes"): return True
            if ans in ("n", "nein", "no"): return False

    def _prompt_choice(self, q: str, options: List[str]) -> str:
        opts = "/".join(options + ["q=quit"])
        while True:
            try:
                ans = input(f"{C.Y}?{C.N} {q} ({opts}): ").strip().lower()
            except EOFError:
                return "q"
            if ans in ("q", "quit", "exit"): return "q"
            if ans in options: return ans
            print(f"  {C.DIM}bitte eine der Optionen: {opts}{C.N}")

    def _have(self, name: str) -> bool:
        """True, wenn Tool vorhanden UND der Stage-Skip nicht aktiv ist."""
        if name not in self.binaries:
            return False
        if not self._should_run(name):
            return False
        return True

    def check_dependencies(self) -> bool:
        """Prüft alle Tools, fragt interaktiv bei fehlenden nach Aktion."""
        self.head("Prüfe Tool-Verfügbarkeit")
        missing_required: List[Tool] = []
        missing_optional: List[Tool] = []

        for tool in TOOLS:
            if not self._tool_needed(tool):
                self.info(f"{tool.display:14s} → übersprungen (--skip/--only/--no-exploit)")
                continue
            path = self._resolve(tool)
            if path:
                self.binaries[tool.name] = path
                self.ok(f"{tool.display:14s} → {C.DIM}{path}{C.N}")
            else:
                tag = "PFLICHT" if tool.required else "optional"
                self.err(f"{tool.display:14s} → NICHT GEFUNDEN  "
                         f"[{tag}]  {C.DIM}({tool.github}){C.N}")
                if tool.required:
                    missing_required.append(tool)
                else:
                    missing_optional.append(tool)

        # Interaktive Nachfrage für jedes fehlende Tool
        unresolved_required: Set[str] = {t.name for t in missing_required}
        for tool in list(missing_required) + missing_optional:
            if tool.name in self.binaries:
                continue
            self.warn(f"\nFehlt: {tool.display}")
            self.log(f"    Quelle:    {tool.github}")
            self.log(f"    Install:   {tool.install_cmd}")

            if self.dry:
                # Dry-Run darf das System nicht verändern.
                self.info(f"[DRY] würde {tool.display} installieren wollen, "
                          f"nutze Platzhalter für die Befehlsanzeige.")
                self.binaries[tool.name] = tool.binary
                unresolved_required.discard(tool.name)
                continue

            if self.yes:
                choice = "install" if tool.required else "skip"
                self.info(f"--yes aktiv → automatische Wahl: {choice}")
            else:
                choice = self._prompt_choice(
                    f"Was tun mit '{tool.display}'?",
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
                        unresolved_required.discard(tool.name)
                        self.ok(f"{tool.display} jetzt verfügbar: {path}")
                    else:
                        self.warn(f"{tool.display} wurde installiert, "
                                  f"aber nicht im PATH/Pfad gefunden.")
                        if tool.required:
                            unresolved_required.add(tool.name)
                else:
                    self.err(f"Installation von {tool.display} fehlgeschlagen.")
                    if tool.required:
                        unresolved_required.add(tool.name)
            elif choice == "skip":
                self.warn(f"Überspringe {tool.display}.")
                if tool.required:
                    unresolved_required.add(tool.name)

        if unresolved_required:
            missing = [TOOL_BY_NAME[name].display for name in sorted(unresolved_required)]
            self.err(f"\nFehlende Pflicht-Tools: "
                     f"{missing}")
            return False
        return True

    def _try_install(self, tool: Tool) -> bool:
        """Versucht, ein Tool zu installieren. Gibt True bei Erfolg zurück."""
        self.info(f"Versuche {tool.display} zu installieren: {tool.install_cmd}")
        try:
            steps = self._install_steps(tool)
            if not steps:
                self.warn(f"Keine automatische Installation für {tool.display}.")
                return False
            full_env = os.environ.copy()
            extra = f"{os.path.expanduser('~/go/bin')}:{os.path.expanduser('~/tools')}"
            full_env["PATH"] = extra + ":" + full_env.get("PATH", "")
            for cmd in steps:
                self.info(f"Install-Step: {self._cmd_display(cmd)}")
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=600,
                    env=full_env,
                )
                self.log(f"{C.DIM}    "
                         f"{proc.stdout.decode(errors='ignore')[-500:]}{C.N}")
                if proc.returncode != 0:
                    return False
            return proc.returncode == 0
        except Exception as e:
            self.err(f"Installations-Fehler: {e}")
            return False

    def _install_steps(self, tool: Tool) -> List[List[str]]:
        home = Path.home()
        tools_dir = home / "tools"
        if tool.kind == "go":
            module = tool.install_cmd.split("go install ", 1)[1]
            return [["go", "install", module]]
        if tool.kind == "pip" and tool.name == "arjun":
            return [["python3", "-m", "pip", "install", "--quiet", "--user", "arjun"]]
        if tool.kind != "git":
            return []

        repos = {
            "linkfinder": (
                "https://github.com/GerbenJavado/LinkFinder.git",
                tools_dir / "LinkFinder",
                True,
            ),
            "paramspider": (
                "https://github.com/devanshbatham/ParamSpider.git",
                tools_dir / "ParamSpider",
                False,
            ),
            "xsstrike": (
                "https://github.com/s0md3v/XSStrike.git",
                tools_dir / "XSStrike",
                True,
            ),
            "sqlmap": (
                "https://github.com/sqlmapproject/sqlmap.git",
                tools_dir / "sqlmap",
                False,
            ),
        }
        if tool.name not in repos:
            return []
        url, dest, has_requirements = repos[tool.name]
        steps: List[List[str]] = []
        if not dest.exists():
            steps.append(["git", "clone", "--depth", "1", url, str(dest)])
        if has_requirements:
            steps.append([
                "python3", "-m", "pip", "install", "--quiet", "--user",
                "-r", str(dest / "requirements.txt"),
            ])
        return steps

    # ------------------------------------------------------------------ Runner
    def _run(self, cmd: List[str], *,
             stdin_file: Optional[Path] = None,
             stdout_file: Optional[Path] = None,
             timeout: Optional[int] = None,
             env: Optional[dict] = None) -> Tuple[int, str]:
        """Führt einen Befehl aus, leitet optional stdin/stdout in Dateien um."""
        if self.dry:
            self.info(f"[DRY] {self._cmd_display(cmd)}")
            return 0, ""

        if stdout_file:
            stdout_file.parent.mkdir(parents=True, exist_ok=True)

        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        # PATH um ~/go/bin und ~/tools erweitern
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
            self.err(f"Timeout nach {timeout or self.timeout}s: {self._cmd_display(cmd)}")
            return 124, "timeout"
        except FileNotFoundError as e:
            self.err(f"Binary nicht gefunden: {e}")
            return 127, str(e)
        finally:
            if stdin_handle: stdin_handle.close()
            if stdout_handle: stdout_handle.close()

    def _should_run(self, stage: str) -> bool:
        stage = stage.lower()
        if self.only:
            return stage in self.only
        if self.skip:
            return stage not in self.skip
        return True

    def _stage_result(self, name: str, output: Path, cmd: List[str], rc: int) -> None:
        cnt = self._count(output) if output.exists() else 0
        self.results[name] = {
            "output": str(output),
            "lines": cnt,
            "command": self._cmd_display(cmd),
            "rc": rc,
        }
        badge = f"{C.G}OK{C.N}" if rc == 0 else f"{C.Y}RC={rc}{C.N}"
        self.ok(f"Stage {name}: {cnt} Einträge in "
                f"{output.relative_to(self.out)} [{badge}]")

    @staticmethod
    def _uid() -> str:
        """Kurze, deterministisch-pro-Run eindeutige ID für Temp-Files."""
        return uuid.uuid4().hex[:10]

    # ========================================================================
    #  STAGES
    # ========================================================================
    def stage_1_subfinder(self) -> Path:
        self.head("Stage 1/8: subfinder  (Subdomain-Enumeration)")
        if not self._should_run("subfinder"):
            self.warn("subfinder übersprungen (--skip/--only).")
            return self.out / "subs" / "subfinder.txt"
        if "subfinder" not in self.binaries:
            self.err("subfinder nicht verfügbar – Stage übersprungen.")
            return self.out / "subs" / "subfinder.txt"

        out = self.out / "subs" / "subfinder.txt"
        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn(f"Output existiert bereits ({self._count(out)} subs). "
                      f"--force zum Neu-Run.")
            return out
        cmd = [self.binaries["subfinder"], "-d", self.domain, "-all", "-silent"]
        rc, err = self._run(cmd, stdout_file=out)
        if rc != 0 and err:
            self.warn(err.strip().splitlines()[-1] if err else "")
        self._stage_result("subfinder", out, cmd, rc)
        return out

    def stage_2_httpx(self, subs_file: Path) -> Path:
        self.head("Stage 2/8: httpx  (HTTP-Probing / lebende Hosts)")
        if not self._should_run("httpx"):
            self.warn("httpx übersprungen (--skip/--only).")
            return self.out / "subs" / "alive.txt"
        if "httpx" not in self.binaries:
            self.err("httpx nicht verfügbar – Stage übersprungen.")
            return self.out / "subs" / "alive.txt"

        out = self.out / "subs" / "alive.txt"
        if not subs_file.exists() or self._count(subs_file) == 0:
            self.warn("Keine Subdomains – überspringe httpx.")
            return out
        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn("Output existiert bereits. --force zum Neu-Run.")
            return out

        cmd = [
            self.binaries["httpx"],
            "-l", str(subs_file),
            "-silent", "-follow-redirects",
            "-status-code", "-title", "-tech-detect",
            "-o", str(out),
        ]
        if self.rate_limit > 0:
            cmd += ["-rate-limit", str(self.rate_limit)]
        rc, err = self._run(cmd)
        if rc != 0 and err:
            self.warn(err.strip().splitlines()[-1] if err else "")
        self._stage_result("httpx", out, cmd, rc)
        return out

    @staticmethod
    def _extract_host(line: str) -> Optional[str]:
        """Extrahiert einen Hostnamen aus einer Zeile.

        Funktioniert sowohl mit reinen URL-Zeilen (httpx -o Format) als auch
        mit dem ausführlichen httpx-Output "https://host [200] [Title]".
        """
        m = re.match(r"https?://([^/\s\[]+)", line)
        return m.group(1) if m else None

    def stage_3_gau_wayback(self, alive_file: Path) -> Path:
        """gau und waybackurls laufen PARALLEL und werden gemerged."""
        self.head("Stage 3/8: gau + waybackurls  (URL-Harvesting, parallel)")
        if not self._should_run("gau") and not self._should_run("waybackurls"):
            self.warn("gau+waybackurls übersprungen (--skip/--only).")
            return self.out / "urls" / "all_urls.txt"

        out = self.out / "urls" / "all_urls.txt"
        gau_raw = self.out / "urls" / "gau.txt"
        wb_raw = self.out / "urls" / "wayback.txt"
        extra_raw = self.out / "urls" / "gau_extra.txt"

        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn(f"Output existiert bereits ({self._count(out)} URLs).")
            return out

        jobs: List[Tuple[str, List[str], Path]] = []

        if self._should_run("gau") and "gau" in self.binaries:
            jobs.append(("gau",
                         [self.binaries["gau"], "--subs", self.domain,
                          "--threads", "5"],
                         gau_raw))
        if self._should_run("waybackurls") and "waybackurls" in self.binaries:
            jobs.append(("waybackurls",
                         [self.binaries["waybackurls"], self.domain],
                         wb_raw))

        # Zusätzlich: gau gegen jeden gefundenen lebenden Host.
        # Wir schreiben die Hostliste in eine Temp-Datei und nutzen
        # `gau --list` (vermeidet ARG_MAX-Probleme bei vielen Hosts).
        if (self._should_run("gau") and "gau" in self.binaries
                and alive_file.exists() and self._count(alive_file) > 0):
            hosts = sorted({
                h for h in (self._extract_host(line) for line in self._read(alive_file))
                if h and h != self.domain
            })
            if hosts:
                host_list = self.out / "urls" / "_gau_hosts.txt"
                self._write(host_list, hosts)
                jobs.append(("gau-extra",
                             [self.binaries["gau"], "--subs",
                              "--list", str(host_list),
                              "--threads", "5"],
                             extra_raw))
            else:
                self.warn("Keine zusätzlichen Hostnamen – gau-extra entfällt.")

        if not jobs:
            self.warn("Keine URL-Harvesting-Tools verfügbar – Stage leer.")
            return out

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
        for f in [gau_raw, wb_raw, extra_raw]:
            if f.exists():
                merged.extend(self._read(f))
        self._write(out, merged)
        self.ok(f"Total nach Merge + Dedup: {self._count(out)} unique URLs")
        return out

    # Matcht .js-URLs, optional mit Query-String, schließt .map / .min.map.js aus.
    _JS_URL_RE = re.compile(
        r"https?://[^\s\"'<>)]+?\.js(?:\?[^\s\"'<>)]*)?$",
        re.IGNORECASE,
    )

    def stage_4_linkfinder(self, urls_file: Path) -> Path:
        self.head("Stage 4/8: LinkFinder  (JS-Endpoints extrahieren)")
        if not self._should_run("linkfinder"):
            self.warn("LinkFinder übersprungen (--skip/--only).")
            return self.out / "js" / "endpoints.txt"
        if "linkfinder" not in self.binaries:
            self.err("LinkFinder nicht verfügbar – Stage übersprungen.")
            return self.out / "js" / "endpoints.txt"

        js_files_out = self.out / "js" / "js_files.txt"
        out = self.out / "js" / "endpoints.txt"

        if not urls_file.exists() or self._count(urls_file) == 0:
            self.warn("Keine URLs – überspringe LinkFinder.")
            return out

        # 1) JS-Dateien aus URLs extrahieren (Query-Strings toleriert, .map ausgeschlossen)
        js_urls: Set[str] = set()
        for line in self._read(urls_file):
            for m in self._JS_URL_RE.findall(line):
                low = m.lower()
                if low.endswith(".map") or low.endswith(".map.js") or ".map?" in low:
                    continue
                js_urls.add(m)
        self._write(js_files_out, list(js_urls))
        self.info(f"{len(js_urls)} eindeutige .js-Dateien gefunden")

        if not js_urls:
            self.warn("Keine JS-Dateien – LinkFinder übersprungen.")
            return out

        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn("LinkFinder-Output existiert bereits.")
            return out

        # 2) LinkFinder pro JS-URL aufrufen, HTML-Output parsen.
        #    Parallel statt seriell – bei SPAs mit 100+ JS-Files ein riesiger Unterschied.
        lf_bin = self.binaries["linkfinder"]
        tmp_dir = self.out / "js" / "_lf_tmp"
        tmp_dir.mkdir(exist_ok=True)

        endpoints: List[str] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.linkfinder_workers
        ) as ex:
            future_to_url = {
                ex.submit(self._run_linkfinder, lf_bin, js, tmp_dir): js
                for js in js_urls
            }
            for fut in concurrent.futures.as_completed(future_to_url):
                js = future_to_url[fut]
                try:
                    eps = fut.result()
                    endpoints.extend(eps)
                except Exception as e:
                    self.warn(f"LinkFinder-Fehler bei {js}: {e}")

        # tmp_html-Files aufräumen
        for f in tmp_dir.glob("*.html"):
            f.unlink(missing_ok=True)
        try:
            tmp_dir.rmdir()
        except OSError:
            pass

        self._write(out, endpoints)
        self._stage_result("linkfinder", out, ["linkfinder"], 0)
        return out

    # Regex für saubere Endpoint-Extraktion aus LinkFinder-HTML.
    # LinkFinder nutzt sowohl <a href="..."> als auch <li class="...">text</li>.
    _LF_HREF_RE = re.compile(r"""<a[^>]+href=["'](https?://[^"']+)["']""", re.IGNORECASE)
    _LF_LI_RE = re.compile(r"""<li[^>]*>\s*([^\s<][^\s<]*)""", re.IGNORECASE)

    def _run_linkfinder(self, lf_bin: str, js_url: str, tmp_dir: Path) -> List[str]:
        """Führt LinkFinder für eine JS-URL aus und gibt gefundene Endpoints zurück."""
        tmp_html = tmp_dir / f"lf_{self._uid()}.html"
        cmd = ["python3", lf_bin, "-i", js_url, "-o", str(tmp_html)]
        rc, _ = self._run(cmd, timeout=120)
        if rc != 0 or not tmp_html.exists():
            return []
        try:
            html = tmp_html.read_text(errors="ignore")
        finally:
            tmp_html.unlink(missing_ok=True)
        # Saubere Endpoint-Extraktion: nur <a href> und <li>-Inhalte.
        endpoints: Set[str] = set()
        endpoints.update(self._LF_HREF_RE.findall(html))
        for li in self._LF_LI_RE.findall(html):
            # Nur pfad- oder URL-ähnliche Li-Inhalte
            if li.startswith("/") or li.startswith("http"):
                endpoints.add(li)
        return list(endpoints)

    def stage_5_paramspider(self) -> Path:
        self.head("Stage 5/8: ParamSpider  (URLs mit Parametern)")
        if not self._should_run("paramspider"):
            self.warn("ParamSpider übersprungen (--skip/--only).")
            return self.out / "params" / "paramspider.txt"
        if "paramspider" not in self.binaries:
            self.err("ParamSpider nicht verfügbar – Stage übersprungen.")
            return self.out / "params" / "paramspider.txt"

        out = self.out / "params" / "paramspider.txt"
        if out.exists() and self._count(out) > 0 and not self.force:
            self.warn("ParamSpider-Output existiert bereits.")
            return out

        ps_bin = self.binaries["paramspider"]
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
        if not self._should_run("arjun"):
            self.warn("Arjun übersprungen (--skip/--only).")
            return self.out / "arjun" / "arjun.json"
        if "arjun" not in self.binaries:
            self.err("Arjun nicht verfügbar – Stage übersprungen.")
            return self.out / "arjun" / "arjun.json"

        out = self.out / "arjun" / "arjun.json"
        if not params_file.exists() or self._count(params_file) == 0:
            self.warn("Keine parametrisierten URLs – überspringe Arjun.")
            return out
        if out.exists() and out.stat().st_size > 0 and not self.force:
            self.warn("Arjun-Output existiert bereits.")
            return out

        # Arjun kennt kein --passive. Nur --stable ist ein gängiges Stabilitäts-Flag.
        cmd = [
            self.binaries["arjun"],
            "-i", str(params_file),
            "-oJ", str(out),
            "--stable",
        ]
        rc, err = self._run(cmd, timeout=900)
        if rc != 0 and err:
            self.warn(f"Arjun rc={rc}: {err.strip().splitlines()[-1] if err else ''}")
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

        # Defensive: nur die ersten N Hosts, um nicht ausufernd zu werden
        alive_lines_all = self._read(alive_file)
        alive_lines = alive_lines_all[: max(1, min(self.BRUTEFORCE_HOST_LIMIT,
                                                  len(alive_lines_all)))]
        self.info(f"Bruteforce gegen {len(alive_lines)} Hosts")

        # --- Gobuster ---
        if self._have("gobuster"):
            if not self.wordlist.is_file():
                self.warn(f"Gobuster-Wortliste fehlt: {self.wordlist}")
                self._stage_result("gobuster", gob_out, ["gobuster"], 1)
            else:
                gob_raw = self.out / "bruteforce" / "gobuster_raw.txt"
                gob_raw.unlink(missing_ok=True)
                rc_values: List[int] = []
                for host in alive_lines:
                    base = re.match(r"(https?://[^/]+)", host)
                    if not base:
                        continue
                    out_file = self.out / "bruteforce" / f"gob_{self._uid()}.txt"
                    cmd = [
                        self.binaries["gobuster"], "dir",
                        "-u", base.group(1),
                        "-w", str(self.wordlist),
                        "-q", "-t", str(self.threads),
                        "-o", str(out_file),
                        "-b", "404,403",
                    ]
                    rc, _ = self._run(cmd, timeout=600)
                    rc_values.append(rc)
                    if out_file.exists():
                        with gob_raw.open("a", encoding="utf-8") as fout:
                            fout.write(f"\n# === {host} ===\n")
                            fout.write(out_file.read_text(errors="ignore"))
                        out_file.unlink()
                self._write(gob_out, self._read(gob_raw))
                stage_rc = 0 if rc_values and all(rc == 0 for rc in rc_values) else 1
                self._stage_result("gobuster", gob_out, ["gobuster"], stage_rc)
        else:
            self.warn("Gobuster übersprungen / nicht verfügbar.")

        # --- Kiterunner (optional) ---
        # ACHTUNG: respektiert jetzt --skip/--only (Bugfix v2).
        if self._have("kiterunner"):
            if not self.kite.is_file():
                self.warn(f"Kiterunner-Wortliste fehlt: {self.kite}")
                self._stage_result("kiterunner", kr_out, ["kiterunner"], 1)
            else:
                kr_out.unlink(missing_ok=True)
                rc_values = []
                for host in alive_lines:
                    base = re.match(r"(https?://[^/]+)", host)
                    if not base:
                        continue
                    out_file = self.out / "bruteforce" / f"kr_{self._uid()}.json"
                    cmd = [
                        self.binaries["kiterunner"], "scan",
                        base.group(1),
                        "-w", str(self.kite),
                        "--json", "-q",
                    ]
                    rc, _ = self._run(cmd, timeout=300, stdout_file=out_file)
                    rc_values.append(rc)
                # Merge aller KR-JSONs
                merged: List[str] = []
                for f in (self.out / "bruteforce").glob("kr_*.json"):
                    if f.exists():
                        merged.extend(self._read(f))
                        f.unlink()
                self._write(kr_out, merged)
                stage_rc = 0 if rc_values and all(rc == 0 for rc in rc_values) else 1
                self._stage_result("kiterunner", kr_out, ["kiterunner"], stage_rc)
        else:
            self.warn("Kiterunner übersprungen / nicht verfügbar.")

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
            targets.extend(self._read(params_file)[:self.EXPLOIT_TARGET_LIMIT])
        if not targets and alive_file.exists():
            targets.extend(self._read(alive_file)[:5])
        targets = sorted(set(targets))[:self.EXPLOIT_TARGET_LIMIT]
        if not targets:
            self.warn("Keine Ziele für Exploit-Stages.")
            return xs_out, sq_out

        self.warn(f"Aktive Tests gegen {len(targets)} Ziele. Diese sind INVASIV.")
        self.warn(f"Stelle sicher, dass Du eine schriftliche Autorisierung für "
                  f"'{self.domain}' hast.")
        if not self._prompt_yes_no("Exploit-Stages jetzt wirklich ausführen?",
                                   default_yes=False):
            self.warn("Exploit-Stages vom User abgebrochen.")
            return xs_out, sq_out

        # --- XSStrike ---
        if self._have("xsstrike"):
            for url in targets:
                if "?" not in url:
                    url = url.rstrip("/") + "/?q=test"
                out_file = self.out / "exploits" / f"xs_{self._uid()}.txt"
                cmd = ["python3", self.binaries["xsstrike"], "-u", url,
                       "--crawl", "--blind", "--timeout", "10", "--skip-dom"]
                rc, _ = self._run(cmd, timeout=300, stdout_file=out_file)
            merged: List[str] = []
            for f in (self.out / "exploits").glob("xs_*.txt"):
                if f.exists():
                    merged.extend(self._read(f))
                    f.unlink()
            self._write(xs_out, merged)
            self._stage_result("xsstrike", xs_out, ["xsstrike"], 0)
        else:
            self.warn("XSStrike übersprungen / nicht verfügbar.")

        # --- sqlmap ---
        if self._have("sqlmap"):
            for url in targets:
                # sqlmap-Output pro URL in eigene Datei, dann am Ende mergen.
                # (Bugfix v2: sq_raw existierte vorher, wurde aber nie beschrieben.)
                out_file = self.out / "exploits" / f"sq_{self._uid()}.txt"
                cmd = ["python3", self.binaries["sqlmap"], "-u", url,
                       "--batch", "--random-agent", "--level=2", "--risk=1",
                       "--threads=2", "--timeout=10",
                       "--output-dir", str(self.out / "exploits" / "sqlmap_out")]
                rc, _ = self._run(cmd, timeout=300, stdout_file=out_file)
            merged = []
            for f in (self.out / "exploits").glob("sq_*.txt"):
                if f.exists():
                    merged.extend(self._read(f))
                    f.unlink()
            self._write(sq_out, merged)
            self._stage_result("sqlmap", sq_out, ["sqlmap"], 0)
        else:
            self.warn("sqlmap übersprungen / nicht verfügbar.")

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
        self.log(f"{C.W}Stage            Datei                                           "
                 f"Einträge{C.N}")
        self.log("─" * 72)
        for name, info in self.results.items():
            try:
                rel = Path(info["output"]).relative_to(self.out)
            except ValueError:
                rel = Path(info["output"]).name
            self.log(f"  {name:14s} {C.DIM}{str(rel):45s}{C.N}  "
                     f"{C.G}{info['lines']}{C.N}")
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
        (self.out / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")


# =============================================================================
#  CLI
# =============================================================================
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


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
                   help="Nur Commands anzeigen, nichts ausführen und nichts installieren")
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
    p.add_argument("--wordlist",
                   default=str(Path.home() / "wordlists/directory-list-2.3-medium.txt"),
                   help="Wortliste für Gobuster")
    p.add_argument("--kite",
                   default=str(Path.home() / "tools/kiterunner-wordlists/large.kite"),
                   help="Kiterunner-Wortliste (.kite)")
    p.add_argument("--threads", type=int, default=20,
                   help="Thread-Anzahl für Brute-Force-Stages")
    p.add_argument("--timeout", type=int, default=1800,
                   help="Globaler Timeout pro Stage (Sekunden)")
    p.add_argument("--rate-limit", type=int, default=0,
                   help="Rate-Limit für httpx (Requests/Sekunde, 0=default)")
    p.add_argument("--linkfinder-workers", type=int, default=10,
                   help="Parallele Worker für LinkFinder-Stage")

    args = p.parse_args()
    args.domain = args.domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(args.domain):
        p.error("--domain muss ein Domainname ohne Schema oder Pfad sein, z. B. example.com")

    try:
        args.output = args.output.format(domain=args.domain)
    except (KeyError, IndexError, ValueError) as exc:
        p.error(f"--output enthält ein ungültiges Format-Template: {exc}")

    if args.skip:
        args.skip = [s.strip().lower() for s in args.skip.split(",") if s.strip()]
    if args.only:
        args.only = [s.strip().lower() for s in args.only.split(",") if s.strip()]

    unknown_skip = sorted(set(args.skip) - VALID_STAGES)
    unknown_only = sorted(set(args.only) - VALID_STAGES)
    if unknown_skip:
        p.error(f"Unbekannte --skip Stage(s): {', '.join(unknown_skip)}")
    if unknown_only:
        p.error(f"Unbekannte --only Stage(s): {', '.join(unknown_only)}")
    if args.skip and args.only:
        p.error("--skip und --only koennen nicht zusammen verwendet werden")
    if args.threads < 1:
        p.error("--threads muss >= 1 sein")
    if args.timeout < 1:
        p.error("--timeout muss >= 1 sein")
    if args.rate_limit < 0:
        p.error("--rate-limit muss >= 0 sein")
    if args.linkfinder_workers < 1:
        p.error("--linkfinder-workers muss >= 1 sein")

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
