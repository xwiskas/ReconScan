"""nikto - the classic web server checker."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .. import validate
from .base import BuildResult, Card, Goal, Option, Tool, Warning_, RAW_FLAGS, finding

TOOL = Tool(
    id="nikto",
    name="nikto",
    binary="nikto",
    category="Web server scanning",
    card=Card(
        what=("nikto walks a web server through a checklist of about 7,000 known-dangerous "
              "files, outdated server versions, risky HTTP methods and missing security "
              "headers. It is old, simple, and still finds things."),
        why=("It covers the unglamorous misconfiguration issues that template scanners "
             "sometimes skip - leftover admin scripts, directory indexing, an ancient "
             "Apache, a missing X-Frame-Options header."),
        when=("Once you know a web server is listening on a port. Run it alongside nuclei "
              "rather than instead of it; they overlap less than you would expect."),
        noise=("Very loud, and it does not pretend otherwise - nikto identifies itself in "
               "its own User-Agent by default. Assume the target's logs will show exactly "
               "what you did."),
        safe_default="A default scan of one host on one port, with the standard checks.",
        docs="https://github.com/sullo/nikto/wiki",
    ),
    goals=[
        Goal(
            id="web_server_scan", label="Check a web server for known issues",
            blurb="Run the standard checklist of dangerous files, old versions and bad headers.",
            detail=("Every line nikto prints starting with '+' is an observation. Many are "
                    "informational (a header it would like to see set); a few are real "
                    "findings (an exposed /admin directory, a vulnerable server version). "
                    "Read them, do not just paste them into a report - nikto has a "
                    "reputation for false positives."),
            options=[
                Option(id="port", label="Port", type="number", default=80,
                       help="Which port the web server is on. 80 is plain HTTP, 443 is HTTPS, 8080 and 8443 are common alternatives.",
                       min=1, max=65535),
                Option(id="ssl", label="This is an HTTPS server", type="bool", default=False,
                       help="Tell nikto to speak TLS. Set this for port 443 or any other HTTPS port, or every request will fail."),
                Option(id="tuning", label="Which checks to run", type="select", default="all",
                       help="nikto groups its checks into categories. Narrowing them makes the scan much faster and quieter.",
                       choices=[
                           {"value": "all", "label": "All checks (default)", "help": "The full checklist. Slowest, most thorough."},
                           {"value": "123b", "label": "Interesting files and config only", "help": "Categories 1,2,3 and b: interesting files, misconfigurations, information disclosure, software identification."},
                           {"value": "x6", "label": "Skip denial-of-service checks", "help": "Everything except category 6, which contains checks that can knock a fragile server over."},
                       ]),
                Option(id="maxtime", label="Stop after (minutes)", type="number", default=10,
                       help="A hard time budget. nikto scans can run a long time; this stops it cleanly and keeps whatever it found.",
                       min=1, max=120, advanced=True),
                RAW_FLAGS,
            ],
            target_types=("ip", "host", "url"),
            typical_duration="5-20 minutes",
        ),
    ],
    flag_help={
        "nikto": "The program itself - a web server vulnerability checklist scanner.",
        "-h": "The host to scan.",
        "-p": "The port the web server is listening on.",
        "-ssl": "Speak HTTPS rather than plain HTTP.",
        "-Tuning": "Limit the scan to particular categories of check.",
        "-maxtime": "Give up after this long and report what was found so far.",
        "-nointeractive": "Never pause to ask a question - required when a program is driving nikto.",
        "-ask": "Whether to prompt about submitting updates. 'no' keeps the run non-interactive.",
        "-Display": "Control what detail is printed. 'V' adds verbose progress.",
    },
)


HINTS = [
    (r"Can't locate .* in @INC|perl",
     "nikto is a Perl program and a module it needs is missing. On Kali: sudo apt install -y "
     "nikto  (which pulls in the right Perl modules)."),
    (r"ERROR: Cannot resolve hostname|No web server found|Connection refused",
     "nikto could not reach a web server there. Check the port, and tick 'This is an HTTPS "
     "server' if the service uses TLS - otherwise every request fails."),
]


def build(goal_id: str, target: str, opts: dict) -> BuildResult:
    if goal_id != "web_server_scan":
        raise validate.ValidationError(f"Unknown nikto goal {goal_id!r}.")

    ttype = validate.classify(target)
    ssl = bool(opts.get("ssl"))
    port = validate.validate_int(opts.get("port", 80), 1, 65535, "Port")
    notes: list[str] = []

    if ttype == "url":
        parts = urlsplit(target)
        host = parts.hostname or target
        if parts.scheme == "https":
            ssl = True
        if parts.port:
            port = parts.port
        elif parts.scheme == "https":
            port = 443
        notes.append(f"Read the host, port and protocol out of the URL: {host}:{port}"
                     f"{' over HTTPS' if ssl else ''}.")
    else:
        host = target

    tuning = validate.validate_choice(
        opts.get("tuning", "all"), ["all", "123b", "x6"], "check selection")
    maxtime = validate.validate_int(opts.get("maxtime", 10), 1, 120, "Time budget")

    args = ["-h", host, "-p", str(port), "-nointeractive", "-ask", "no",
            "-maxtime", f"{maxtime}m"]
    if ssl:
        args += ["-ssl"]
    if tuning != "all":
        args += ["-Tuning", tuning]
    args += validate.validate_raw_flags(opts.get("raw_flags", ""))

    warns = [Warning_(
        "caution", "nikto announces itself",
        "It requests thousands of suspicious paths and, by default, puts its own name in "
        "the User-Agent header. There is no stealth here - the target's administrator can "
        "see exactly what ran and when. That is fine on an authorized test and a problem "
        "anywhere else.")]
    if tuning == "all":
        warns.append(Warning_(
            "info", "The full checklist includes a denial-of-service category",
            "Category 6 contains checks that can hang or crash a fragile web server. If the "
            "target must stay up, choose 'Skip denial-of-service checks' instead."))

    return BuildResult(args=args, warnings=warns, notes=notes, est_seconds=maxtime * 60)


_PLUS_RE = re.compile(r"^\+\s+(.*)$")
_OSVDB_RE = re.compile(r"\b(OSVDB-\d+|CVE-\d{4}-\d{4,7})\b")
_PATH_RE = re.compile(r"^(/\S*)\s*:\s*(.*)$")


def parse(stdout: str, stderr: str, target: str) -> list[dict]:
    out: list[dict] = []
    host = validate.scan_host_part(target)
    skip_prefixes = ("Target IP", "Target Hostname", "Target Port", "Start Time",
                     "End Time", "Server:", "host(s) tested", "SSL Info")

    for raw in stdout.splitlines():
        m = _PLUS_RE.match(raw.strip())
        if not m:
            continue
        text = m.group(1).strip()
        if not text or text.startswith(skip_prefixes):
            continue

        refs = sorted(set(_OSVDB_RE.findall(text)))
        pm = _PATH_RE.match(text)
        path = pm.group(1) if pm else ""
        message = pm.group(2) if pm else text

        low = text.lower()
        if any(k in low for k in ("outdated", "vulnerab", "exploit", "remote", "injection",
                                  "traversal", "backdoor")):
            sev = "high"
        elif any(k in low for k in ("directory indexing", "admin", "backup", "config",
                                    "password", "phpinfo", "exposed")):
            sev = "medium"
        elif any(k in low for k in ("header", "cookie", "method", "not present", "uncommon")):
            sev = "low"
        else:
            sev = "info"

        out.append(finding(host, "web", {
            "path": path, "message": message[:1500], "severity": sev,
            "refs": refs, "raw": text[:1500],
        }))
    return out
