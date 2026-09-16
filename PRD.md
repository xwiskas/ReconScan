# PRD — ReconScan
### A beginner-friendly cockpit for the **scanning phase** of a penetration test

> **Status:** Draft v0.2 · **Owner:** Sebastian · **Purpose:** Class penetration-testing engagement (authorized lab use)
> **Product name:** **ReconScan**

---

## 1. Summary (one paragraph)

ReconScan is a **web application** that acts as a friendly control panel for the scanning phase of a penetration test. It wraps the real industry-standard scanning tools (nmap, masscan, nuclei, nmap NSE scripts, and web scanners like nikto/whatweb/gobuster) behind a **clean, beginner-friendly dashboard** that **explains what each tool and option does, shows you the exact command it will run before it runs, streams live results, and then interprets those results in plain English with suggested next steps.** It is built for someone *new to cybersecurity* — every screen teaches — while still exposing the full advanced power of the underlying tools. It runs its engine on **Kali Linux** (where the tools live) and is used from a **browser on any device**, including Windows, with **no login** (LAN-only + Demo mode). A built-in **Demo/Learn mode** lets you explore every feature with realistic sample output before you ever fire a real scan.

---

## 2. Context & background

**Where this fits.** The penetration-testing lifecycle is roughly:

`Recon → ► Scanning ◄ → Enumeration → Exploitation → Post-exploitation → Reporting`

You have **completed reconnaissance**. ReconScan owns the **Scanning** step (and bridges into Enumeration via service/version detection). Recon output (a list of hosts/domains/IPs) can be **imported as targets** so you don't retype anything.

**Why build it (the problem).** Beginners in a pentest class face two walls at the scanning stage:
1. **The tools are cryptic.** `nmap -sS -sV -O -p- --min-rate 1000 -T4` means nothing to a newcomer, and a wrong flag can be slow, noisy, or useless.
2. **The results are cryptic.** A wall of ports and service banners doesn't tell a beginner *what matters* or *what to do next*.

ReconScan removes both walls **without hiding the real tools**, so you learn the actual craft (not a toy) but with training wheels you can take off as you grow.

---

## 3. Goals & non-goals

### Goals
- **G1 — Teach while doing.** Every tool, option, and result is explained in plain language ("what / why / when / what this result means").
- **G2 — Never click blind.** The app always shows the **exact command** it will run and a short explanation *before* execution.
- **G3 — Be genuinely powerful.** Full access to the real tools and their advanced options — **no artificial tool limits**.
- **G4 — Be safe by default.** Sensible defaults, guardrails, and legal authorization gating so a beginner can't accidentally do something harmful or illegal.
- **G5 — Testable safely.** Demo/Learn mode + support for legal practice targets so you can explore risk-free.
- **G6 — Produce a deliverable.** Export scan results into a clean report for class submission, **in your choice of format**.

### Non-goals (explicitly out of scope, at least for now)
- **Not an exploitation tool.** No launching exploits, no Metasploit integration, no payloads. Scanning/enumeration only.
- **Not a recon tool.** Recon is done; we only *import* its output.
- **Not a replacement for learning the CLI.** It teaches the CLI, it doesn't hide it forever.
- **Not for unauthorized targets.** The app actively discourages and gates scanning of anything you don't have permission to scan.

---

## 4. Target user

**Primary:** *Student* — a student new to cybersecurity, working through an authorized pentest class lab. Comfortable with computers, **not** yet comfortable with Linux CLI security tooling. Needs to *understand* every action.

**Design implication:** Default everything to the explained, guided path. Make "advanced/raw" power opt-in, one click away, never the default.

---

## 5. Design principles

1. **Explain everything, everywhere.** No unlabeled buttons. Hover = tooltip; click "?" = deeper explanation.
2. **Show the command.** The generated CLI command is always visible and copy-able — this is *the* core teaching feature.
3. **Guardrails, not walls.** Warn and confirm on risky/slow/noisy actions; don't forbid learning.
4. **Progressive disclosure.** Beginner sees a clean guided flow; "Advanced" reveals raw flags and expert options.
5. **Interpret, don't just dump.** Results always come with a plain-English "what this means / what's interesting / what to do next."
6. **Safe by default.** Conservative defaults (timing, scope), demo mode available, authorization acknowledged.

---

## 6. UI / UX direction

- **Clean, light dashboard** — not a cluttered "hacker console." Calm, modern, lots of whitespace, clear typography.
- **Simple left-nav layout:** *Dashboard · Targets · New Scan · Results · Reports · Learn/Glossary.*
- **Beginner-first hierarchy:** the guided path is front and center; advanced/raw options live behind an "Advanced" toggle.
- **Consistent explanation pattern:** every tool/option/result has the same "?" affordance and the same "what / why / next" structure, so once you learn the pattern once, you know it everywhere.
- **Status clarity:** always obvious whether you're in **Demo mode** or running **real scans**, and whether a scan is queued/running/done.

---

## 7. Legal, safety & authorization guardrails  *(senior-dev addition)*

Scanning a system you don't own or have written permission to test is **illegal** in most jurisdictions. Because this tool makes scanning *easy*, it must make *responsible use* easy too.

- **A1 — Authorization acknowledgement per project.** Creating a project requires acknowledging an "I am authorized to scan these targets" statement, and recording *what* authorizes it (class lab, own VM, scanme.nmap.org, instructor scope doc).
- **A2 — Scope allow-list.** Targets must be added to a defined scope. Scans outside the declared scope are blocked with a clear warning.
- **A3 — Guardrails on dangerous options.** Noisy/aggressive/slow options (e.g. `-T5`, full `-p-` on large ranges, aggressive NSE categories) trigger a plain-English "here's what this does and why you might not want it" confirmation.
- **A4 — Audit log.** Every scan (command, target, time) is recorded — good practice *and* useful for your class report.
- **A5 — App-level security.** The engine runs powerful tools, so: **bind to localhost/LAN only** by default (no login, so network exposure must be limited), and — critically — **never pass user input to a shell string**; build commands as validated argument arrays to prevent command injection (see §12).
- **A6 — Legal footer & first-run notice.** A short, unmissable "authorized use only" notice and a link to a plain-English ethics/legal primer.

> **Note on "no login":** since there's no authentication, the backend must **only listen on localhost or your trusted LAN** — never expose it to the open internet. This is called out in the design so it isn't forgotten.

---

## 8. Architecture (proposed)

```
   ┌─────────────────────────┐        HTTP + WebSocket        ┌────────────────────────────────────┐
   │  Browser (Windows / any) │  ◄──────────────────────────►  │        Kali Linux host             │
   │  ─ React web UI          │      (LAN only, no login)      │  ┌──────────────────────────────┐  │
   │  ─ Guided scan builder   │                                │  │  Backend API (FastAPI/Python) │  │
   │  ─ Live results view     │                                │  │  ─ scan orchestrator/queue    │  │
   └─────────────────────────┘                                │  │  ─ output parsers             │  │
                                                               │  │  ─ demo-mode fixtures         │  │
                                                               │  └──────────────┬───────────────┘  │
                                                               │        subprocess (arg arrays)      │
                                                               │  ┌──────────────▼───────────────┐  │
                                                               │  │ Real tools: nmap, masscan,    │  │
                                                               │  │ nuclei, NSE, nikto, whatweb,  │  │
                                                               │  │ gobuster, … (no limit)        │  │
                                                               │  └───────────────────────────────┘  │
                                                               │  SQLite: projects, scans, results   │
                                                               └────────────────────────────────────┘
```

- **Engine on Kali, client anywhere.** The backend runs on Kali (where the tools are installed) and serves the web UI to your browser on Windows/any device on the LAN.
- **Demo/Learn mode = same UI, fixture data.** Instead of calling the real tools, the backend returns realistic saved output. Lets you (and the app itself, on Windows without the tools) run the full experience safely.
- **Portable later.** The same backend + tools can be packaged as **Docker** so it runs anywhere without a Kali install.
- **Live streaming.** Long scans stream progress/output to the UI over WebSocket; you can stop a running scan.

---

## 9. Feature scope

### MVP (v1) — the core loop
| # | Feature | What it does | Beginner layer |
|---|---------|--------------|----------------|
| F1 | **Project workspace** | One project per engagement/class assignment; holds scope, scans, results. | Guided project setup wizard + authorization acknowledgement. |
| F2 | **Target & scope management** | Add hosts/IPs/ranges; import recon output (paste or file). | Validates input, explains CIDR/ranges, shows what's in scope. |
| F3 | **Guided Scan Builder** | Pick a *goal* ("find open ports", "identify services", "check for known vulns", "scan a web server") → app assembles the right tool + options. | Plain-English goals, not raw flags. **Live command preview** with per-flag explanations. |
| F4 | **Tool catalog (no limit)** | nmap, masscan, nuclei, NSE, nikto, whatweb, gobuster/dirb, and more — each with a "what/why/when" card. | Beginner cards + advanced raw-flag mode. |
| F5 | **Execution engine** | Runs the real command (or demo fixture), streams live output, lets you stop it. | Progress bar, "what's happening now" narration. |
| F6 | **Parsed results views** | Ports table, services/versions, OS guess, vuln findings with severity, web findings — plus a raw-output toggle. | Color-coded severity, plain-English labels. |
| F7 | **"Explain this result" + next steps** | For a finding, explain what it is and suggest the logical next action. | e.g. "Port 445/SMB open → next: enumerate SMB shares." |
| F8 | **Scan history** | List past scans per project, re-open, re-run, delete. | Timeline view. |
| F9 | **Demo / Learn mode** | Full UI with realistic canned output; no real scanning. | Toggle in header; clearly labeled "DEMO". |
| F10 | **Glossary & help** | Searchable plain-English definitions (port, service, CVE, CIDR, SYN scan…). | Linked from everywhere via "?" icons. |
| F11 | **Report export (multi-format)** | Export a project's findings for class submission — **choose Markdown, PDF, or HTML** (and raw JSON for data). | Clean template with summary + evidence; pick your format at export time. |

### Scan capabilities in MVP (all in scope — no tool limit)
- ✅ **Host discovery + port scanning** — nmap host discovery, TCP/UDP port scans, masscan for fast large-range sweeps.
- ✅ **Service & version / OS detection** — `nmap -sV`, `-O`, banner grabbing (bridges into enumeration).
- ✅ **Vulnerability scanning** — nmap NSE `vuln` scripts + nuclei templates, with severity + CVE explanations.
- ✅ **Web app / web server scanning** — nikto, whatweb, gobuster/dirb, nuclei web templates.

### Phase 2 (nice-to-have / later)
- 🔷 **Scan comparison / diff** between two runs (what changed).
- 🔷 **Saved scan templates** you can reuse.
- 🔷 **Scan scheduling.**
- 🔷 **Docker one-command deploy.**
- 🔷 **Interactive quizzes** ("what would you scan next?") for extra learning.

---

## 10. The learning layer (what makes it beginner-friendly)

This is the heart of the product. Concretely:

- **Command Preview panel** — always shows the exact command, with each flag underlined and hover-explained. "This is what a pro would type; here's what each part means."
- **Goal-first Scan Builder** — you choose *what you want to learn about the target*, not which flag to use. The app translates goals → tools/flags and shows its work.
- **Tool cards** — every tool has: *What it is · Why/when you'd use it · What it's noisy/quiet about · A safe default preset · The raw command.*
- **Result interpretation** — parsed findings carry plain-English meaning, a severity/importance signal, and a **"Next step"** suggestion tying into the pentest methodology.
- **Inline glossary** — any jargon term is a clickable definition.
- **Safety confirmations** — dangerous/slow/noisy choices explain the trade-off before you commit.
- **Demo mode** — practice the entire flow with zero risk.

---

## 11. Tools inventory (no limit — starter set)

| Tool | Category | Beginner note the UI will show |
|------|----------|-------------------------------|
| **nmap** | Port/service/OS scan, NSE vuln scripts | "The Swiss-army knife of scanning — finds open ports, what's running, and known issues." |
| **masscan** | Ultra-fast port scan | "Very fast at finding open ports across many hosts — great first pass, less detail than nmap." |
| **nuclei** | Template-based vuln scanning | "Checks targets against a big library of known-issue templates." |
| **nmap NSE (vuln/safe/default)** | Scripted checks | "Mini-programs that extend nmap — e.g. check for specific vulnerabilities." |
| **nikto** | Web server scanner | "Checks a web server for known issues and misconfigurations." |
| **whatweb** | Web tech fingerprinting | "Identifies what a website is built with (server, CMS, frameworks)." |
| **gobuster / dirb** | Content/dir discovery | "Finds hidden pages and directories on a web server." |
| *…more* | — | New tools can be added via the same tool-card pattern. |

*All tools invoked as validated argument arrays, never via a shell string (see §12).*

---

## 12. Data model sketch (initial)

```
Project        (id, name, authorization_note, created_at)
  └─ Target    (id, project_id, value, type[host|ip|cidr|range|url], in_scope)
  └─ Scan      (id, project_id, tool, goal, command_args[], status, started_at, finished_at, is_demo)
        └─ RawOutput   (scan_id, stdout, stderr, exit_code)
        └─ Finding     (id, scan_id, target, type[port|service|os|vuln|web],
                        data{port, proto, state, service, version, cve, severity...},
                        interpretation, suggested_next_step)
  └─ AuditEntry  (id, project_id, action, command, timestamp)
```

**Command-injection safety (critical):** user-supplied values (targets, ports) are validated against strict patterns and passed as **individual arguments** to the subprocess API — the app **never** builds a shell command string from user input.

---

## 13. Tech stack (recommendation — open to change)

| Layer | Choice | Why |
|-------|--------|-----|
| Backend | **Python + FastAPI** | Python is native to Kali; excellent subprocess handling; nmap parsing libraries exist; easy WebSockets. |
| Scan parsing | `python-libnmap` / nmap XML; JSON output for nuclei/masscan | Reliable structured results instead of scraping text. |
| Frontend | **React (Vite) + a component library** | Fast to build a clean, light dashboard; good for tooltips/panels. |
| Realtime | **WebSocket** | Live scan output streaming. |
| Storage | **SQLite** | Zero-config, perfect for a single-user class project; upgradeable later. |
| Report export | Markdown → PDF/HTML rendering | Multi-format export from one source. |
| Packaging | Run natively on Kali for v1; **Docker** in Phase 2 | Simple now, portable later. |

---

## 14. Success metrics

- **Time-to-first-scan** for a total beginner: under 5 minutes from opening the app.
- **Comprehension:** user can correctly explain, in their own words, what a scan did and what a finding means — *without outside help* — for ≥80% of MVP scan types.
- **Zero blind clicks:** every action reachable in the UI has an explanation available at that spot.
- **Deliverable:** user can produce a class-ready report from real scan results, in their chosen format.
- **Safety:** no scans possible outside a declared, acknowledged scope.

---

## 15. Milestones (suggested build order)

1. **M0 — Skeleton:** project + target CRUD, DB, Demo mode returning fixtures end-to-end, clean dashboard shell.
2. **M1 — nmap core:** guided builder → command preview → real execution → live output → parsed ports/services view.
3. **M2 — Interpretation layer:** result explanations + next-step suggestions + glossary.
4. **M3 — Vuln scanning:** NSE vuln + nuclei integration with severity/CVE explanations.
5. **M4 — masscan + OS detection + history.**
6. **M5 — Web scanning:** nikto, whatweb, gobuster.
7. **M6 — Report export** (Markdown / PDF / HTML / JSON).
8. **Phase 2:** diff, templates, scheduling, Docker, quizzes.

---

## 16. Open questions (only one left)

1. **Recon import format:** what does your recon output look like right now (a plain text list of IPs? a specific tool's export file?) so I design the importer to match. *(If unsure, I'll default to "paste a list of hosts/IPs/URLs, one per line" plus common file uploads.)*

*Resolved:* no login (LAN-only) · report export offers Markdown/PDF/HTML/JSON · clean light beginner dashboard · product name **ReconScan** · no tool limits (web scanning included in MVP).

---

## 17. Out of scope (v1)

Exploitation, payload delivery, brute-forcing/password attacks, recon/OSINT gathering, unauthorized-target scanning, and mobile-native apps.

---

*Next step: confirm the recon import format (§16), then I'll turn the MVP (M0–M2) into a working skeleton you can run.*
