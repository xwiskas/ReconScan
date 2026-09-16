# ReconScan

A beginner-friendly cockpit for the **scanning** phase of an authorized penetration test.

ReconScan wraps the real tools — nmap, masscan, nuclei, nikto, whatweb, gobuster — behind a
guided dashboard that explains what each option does, **shows you the exact command before it
runs**, streams live output, and then interprets the results in plain English with a suggested
next step.

It runs its engine on Kali (where the tools live) and is used from a browser on any device.

---

## Quick start

```bash
cd app
pip install -r requirements.txt
python -m reconscan
```

Open <http://127.0.0.1:8000>. On Windows it starts in **Demo mode**, so you can click through
the entire application — every screen, parser and report — without sending a single packet.

### Reaching it from another device

```bash
sudo python -m reconscan --lan
```

This binds all interfaces over **HTTPS** and requires a login. On first run it generates a
self-signed certificate and the first screen asks you to create the single account. Your browser
will warn once that the certificate is not trusted; that warning is accurate — the certificate
proves nothing about identity, it only encrypts the connection so your password does not cross
the LAN in clear text.

Never expose ReconScan directly to the internet.

### Docker (one command, tools included)

```bash
docker compose up --build
```

Then open <https://localhost:8000>. The image is built on Kali and ships nmap, masscan, nuclei,
nikto, whatweb and gobuster plus the standard wordlists, so every scan the UI offers can
actually run. It starts in LAN mode, so the first screen asks you to create the account.

Raw-packet scans need two Linux capabilities; the compose file grants `NET_RAW` and `NET_ADMIN`
rather than running the container privileged. To scan machines on your own LAN rather than just
other containers, swap the `ports:` block for `network_mode: host` — the comment in
[docker-compose.yml](docker-compose.yml) shows exactly what to change. Your projects and scans
live in a named volume, so a rebuild does not throw them away.

### A desktop icon

```bash
python make_shortcut.py           # adds "ReconScan" to your desktop
python make_shortcut.py --menu    # and to the Start Menu / app list
python make_shortcut.py --remove  # take it away again
```

Double-click it and ReconScan starts, opening your browser automatically. A console window
stays open while it runs - **that window is the server**, so closing it stops ReconScan.

On Linux this writes a `.desktop` entry, which launches as your normal user. That is enough for
Demo mode and TCP connect scans, but SYN scans, OS detection, UDP scans and masscan need raw
packets - for those, run `sudo ./run.sh` from a terminal.

The icon is drawn in code by [app/reconscan/icon.py](app/reconscan/icon.py), which writes the
`.ico` and `.png` by hand rather than adding an image library to a project that has none.

### Portable (USB stick)

```bash
python make_portable.py --dest E:/ReconScan
```

That copies the app to the stick and downloads its Python dependencies into it, so it runs on a
machine where nothing is installed. Then `run.bat` (double-click on Windows) or `./run.sh`
(Linux/macOS). About 33 MB.

Your projects, scans and reports live in `app/data/` next to the application, so **they travel
with the stick** — plug it into another machine and your engagement is still there.

Three things to know:

- **The dependency folder is platform-specific.** A few packages ship compiled code, so
  `_vendor/win-amd64-py3.12/` will not run on Kali. Run `make_portable.py` again on each
  platform; the folders sit side by side and `launch.py` picks the right one. If it can't find a
  match it says so and prints the exact command to fix it.
- **Python itself is not on the stick.** The machine you plug into needs Python 3.11+. Kali
  always has it.
- **Two of the six scanning tools can ride along; four cannot.** See below.

### Carrying the scanning tools

```bash
python fetch_tools.py --dest E:/ReconScan                      # for this machine
python fetch_tools.py --dest E:/ReconScan --platform kali      # for the Kali side
python fetch_tools.py --list                                   # what can and cannot be carried
```

This downloads **nuclei** and **gobuster** into `app/tools/<platform>/`. Both are written in Go
and link statically, so each is a single file that runs with nothing installed. ReconScan looks
there *before* the host's PATH, so the stick runs the versions you put on it — and says so in the
scan output when it does.

The other four cannot be carried, for reasons worth understanding rather than fighting:

| Tool | Why not |
| --- | --- |
| nmap, masscan | Need a packet-capture layer — libpcap on Linux, and on Windows the Npcap **kernel driver**, which must be installed, not run from a folder |
| nikto | Is a Perl program and needs a Perl interpreter |
| whatweb | Is a Ruby program and needs a Ruby interpreter |

On Kali all four are one command away, which is the intended setup:

```bash
sudo apt install -y nmap masscan nikto whatweb wordlists dirb
nuclei -update-templates      # nuclei ships no templates until you fetch them
```

**Learn & glossary** shows where each tool is coming from — bundled, installed on the host, or
absent — so you can see at a glance what the current machine can actually run.

One security note: on a FAT32 or exFAT stick, the `chmod 600` applied to the LAN certificate's
private key silently does nothing, leaving it world-readable. If you plan to use `--lan` from a
USB stick, format it NTFS or ext4.

### Other flags

| Flag | Effect |
| --- | --- |
| `--demo` / `--real` | Force the default scan mode regardless of platform |
| `--port 9000` | Listen on a different port |
| `--host 192.168.1.5` | Bind one specific address (implies LAN mode) |

Environment variables `RECONSCAN_HOST`, `RECONSCAN_PORT`, `RECONSCAN_DEMO`,
`RECONSCAN_DATA_DIR` and `RECONSCAN_SESSION_TTL_HOURS` do the same thing.

---

## The workflow

1. **Create a project** — records what authorizes this testing. That note goes into your report.
2. **Declare your scope** — paste your recon output; comments and extra columns are ignored.
   ReconScan refuses to scan anything not on this list.
3. **Pick a goal, not a flag** — "What ports are open on this host?" rather than `-sS -T4`.
4. **Review the preflight** — the exact command with every flag explained, how many addresses it
   expands to, roughly how long it will take, and a plain-English warning for anything slow,
   loud or risky.
5. **Run it** — live output over a WebSocket, stoppable at any time.
6. **Read the findings** — each one carries what it means and what to do next.
7. **Export** — Markdown, PDF, HTML or JSON, from one canonical report model.

## Going further

**Compare scans.** Run the same scan twice and see what moved: ports that appeared, findings
that vanished, versions that changed. Each difference is explained, with the caveat that matters
most — a finding that disappears is *not* proof it was fixed, because a dropped packet looks
identical to a patched service.

**Saved setups.** Tuned a scan the way you want it? Save it from the preflight screen and it
appears at the top of New scan, ready to point at anything in scope. The target is never part of
a saved setup, so scope is always re-checked.

**Schedules.** Re-run a scan on an interval and diff the results. This is the one feature that
puts packets on a network while nobody is watching, so it is deliberately cautious: scope is
re-checked every time a schedule fires, a schedule whose target leaves scope disables itself,
runs never stack, and new schedules default to Demo mode with a run cap.

**Quiz yourself.** Questions on methodology, tool choice, reading results and the legal rules —
plus questions generated from your own scans ("your scan found 3306/MySQL open — what next?").
Every option is explained, including why the tempting wrong ones are wrong.

---

## Two safety properties worth knowing

**Commands are never built as shell strings.** Every command is assembled as a list of separate
arguments and handed straight to the operating system with `create_subprocess_exec`. There is no
shell anywhere in the execution path, so shell metacharacters in a target are inert. On top of
that, every user-supplied value is pattern-checked in `reconscan/validate.py` before it can
become an argument.

**The preview is the command.** One `ScanPlan` object produces both the preview you read and the
argv that executes. There is no second code path that could diverge from what you were shown.

---

## Project layout

```
app/
  requirements.txt
  reconscan/
    __main__.py     entry point, CLI flags, HTTPS wiring
    api.py          HTTP + WebSocket routes, LAN auth guard
    config.py       runtime configuration
    db.py           SQLite schema and helpers
    validate.py     strict input validation (injection defence), scope rules
    runner.py       execution engine: streaming, cancel, demo playback
    interpret.py    what a finding means + the suggested next step
    fixtures.py     realistic saved output for Demo mode
    glossary.py     plain-English definitions
    diff.py         comparing two scans, and what a difference does not prove
    scheduler.py    unattended scans, with scope re-checked at fire time
    quiz.py         question bank + questions built from your own findings
    auth.py         single-user login, Argon2id, sessions, rate limiting
    certs.py        self-signed certificate generation for LAN mode
    report.py       one report model, four renderings
    pdf.py          dependency-free PDF writer
    tools/
      base.py       ScanPlan, Goal, Option, Card
      __init__.py   catalog + the only place a command is built
      nmap.py  masscan.py  nuclei.py  nikto.py  whatweb.py  gobuster.py
    web/            the UI: index.html, app.js, styles.css (no build step)
```

Data lives in `app/data/` — `reconscan.sqlite3` plus the LAN certificate.

---

## Scope of the tool

**In scope:** host discovery, TCP/UDP port scanning, service and version detection, OS
fingerprinting, NSE and nuclei vulnerability *checks*, web server scanning, technology
fingerprinting, content discovery.

**Deliberately out of scope:** exploitation, payload delivery, credential attacks, recon/OSINT
gathering. ReconScan takes you up to "here is a likely weakness, verified as far as an outside
look allows" and stops. That boundary is the difference between an assessment and an intrusion.

---

## Legal

Scanning a computer you do not have written permission to test is a criminal offence in most
jurisdictions, regardless of intent or harm caused. ReconScan requires an authorization note per
project, enforces a scope allow-list, and writes every command it runs to an audit log. None of
that makes an unauthorized scan legal — it makes it harder to do by accident.

Scope has two halves. An entry marked **in scope** permits a target; an entry marked **excluded**
forbids it, and an exclusion always beats an in-scope range that would otherwise cover it. So you
can declare `10.10.10.0/24` in scope and exclude `10.10.10.1` — the range stays scannable, that
one machine does not. That is how you carve out the box nobody is allowed to touch.

Legal practice targets: your own VMs, your class lab range, and `scanme.nmap.org` (the nmap
project publishes permission; keep it to a few light scans a day).
