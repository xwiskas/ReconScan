# ReconScan

A beginner-friendly cockpit for the **scanning** phase of an authorized penetration test.

ReconScan wraps the real tools — nmap, masscan, nuclei, nikto, whatweb, gobuster — behind a guided dashboard that explains what each option does, **shows you the exact command before it runs**, streams live output, and then interprets the results in plain English with a suggested next step.

It runs its engine on Kali (where the tools live) and is used from a browser on any device.

---

## Quick Start

### Option 1: Docker (recommended, tools included)

```bash
docker compose up --build
```

Then open https://localhost:8000

The container includes nmap, masscan, nuclei, nikto, whatweb, gobuster plus wordlists.

### Option 2: Native (Kali / Linux with tools installed)

```bash
cd app
pip install -r requirements.txt
python -m reconscan
```

Open http://127.0.0.1:8000

### Option 3: Windows (Demo mode — no tools needed)

```cmd
cd app
pip install -r requirements.txt
python -m reconscan
```

Open http://127.0.0.1:8000 — runs in Demo mode with realistic saved scans.

---

## LAN Access (for team use or mobile testing)

```bash
# Linux/macOS
sudo python -m reconscan --lan

# Windows (run as Administrator)
run.bat --lan
```

Creates HTTPS with login. First run creates an account.

---

## Requirements

**For real scans (not Demo mode):**
- Linux (Kali recommended)
- nmap, masscan, nuclei, nikto, whatweb, gobuster installed
- Python 3.11+

**Install on Kali:**
```bash
sudo apt install -y nmap masscan nikto whatweb wordlists dirb
nuclei -update-templates
```

---

## How it works

1. **Create a project** — records authorization for this engagement
2. **Declare scope** — paste targets; anything not listed is blocked
3. **Pick a goal** — "What ports are open?" not raw flags
4. **Review preflight** — exact command with plain-English explanations
4. **Run scan** — live output, stoppable anytime
5. **Read findings** — each has meaning + next step
5. **Export** — Markdown, PDF, HTML, JSON

---

## Safety

- No shell anywhere — commands built as argument lists, not strings
- Preview = command that executes (no hidden code path)
- Scope enforced per project; exclusions always override inclusions
- Audit log of every command run

---

## Legal

Scanning without written permission is a crime in most jurisdictions. ReconScan requires an authorization note per project and enforces scope. Legal practice targets: your own VMs, class lab ranges, `scanme.nmap.org` (limited scans).

---

## Project Layout

```
app/
  requirements.txt
  reconscan/
    __main__.py     entry point, CLI flags, HTTPS wiring
    api.py          HTTP + WebSocket routes, LAN auth guard
    config.py       runtime configuration
    db.py           SQLite schema and helpers
    validate.py     strict input validation, scope rules
    runner.py       execution engine: streaming, cancel, demo playback
    interpret.py    what a finding means + next step
    fixtures.py     realistic saved output for Demo mode
    glossary.py     plain-English definitions
    diff.py         comparing two scans
    scheduler.py    unattended scans, scope re-checked at fire time
    quiz.py         question bank + questions from your own scans
    auth.py         single-user login, Argon2id, sessions, rate limiting
    certs.py        self-signed certificate generation for LAN mode
    report.py       one report model, four renderings
    pdf.py          dependency-free PDF writer
    tools/
      base.py       ScanPlan, Goal, Option, Card
      __init__.py   catalog + the only place a command is built
      nmap.py  masscan.py  nuclei.py  nikto.py  whatweb.py  gobuster.py
    web/            UI: index.html, app.js, styles.css (no build step)
```

Data lives in `app/data/` — `reconscan.sqlite3` plus LAN certificate.

---

## License

MIT
