"""whatweb - identify what a website is built with."""
from __future__ import annotations

import json

from .. import validate
from .base import BuildResult, Card, Goal, Option, Tool, Warning_, RAW_FLAGS, finding

TOOL = Tool(
    id="whatweb",
    name="whatweb",
    binary="whatweb",
    category="Web technology fingerprinting",
    card=Card(
        what=("whatweb looks at a website's headers, HTML, cookies and scripts and tells "
              "you what it is made of: which web server, which CMS, which JavaScript "
              "libraries, which analytics, sometimes which exact version."),
        why=("Knowing the stack is what makes every later step targeted. 'WordPress 6.2 "
             "behind nginx' tells you which nuclei tags to run and which CVE list to "
             "read. Without it you are guessing."),
        when=("The first thing to run against any web target - before nikto, before "
              "nuclei, before directory brute-forcing."),
        noise=("Very quiet at the default aggression level: it makes roughly one request, "
               "like a browser would. Higher levels send extra probing requests and stop "
               "being quiet."),
        safe_default="Aggression level 1 (passive) - one normal-looking request.",
        docs="https://github.com/urbanadventurer/WhatWeb",
    ),
    goals=[
        Goal(
            id="fingerprint", label="Identify the technology stack",
            blurb="Find out what server, CMS, framework and libraries a site is built on.",
            detail=("Each result is a plugin name plus what it found, e.g. "
                    "'HTTPServer[Apache/2.4.41]' or 'WordPress[6.2]'. Version numbers are "
                    "the valuable part: they are what you search for in a CVE database. "
                    "Note that a site can lie about its headers, so treat versions as "
                    "strong hints rather than proof."),
            options=[
                Option(id="aggression", label="How hard to probe", type="select", default="1",
                       help=("Level 1 makes a single normal request and reads the reply. "
                             "Level 3 sends extra requests to confirm guesses - more accurate, "
                             "no longer passive, and visible in the target's logs."),
                       choices=[
                           {"value": "1", "label": "1 - passive (default)", "help": "One request. Looks like an ordinary browser visit."},
                           {"value": "3", "label": "3 - aggressive", "help": "Follows up on guesses with extra requests. More versions identified, more noise."},
                       ]),
                Option(id="follow", label="Follow redirects", type="bool", default=True,
                       help="If the site sends you elsewhere (http to https, / to /home), go there and fingerprint the real page."),
                RAW_FLAGS,
            ],
            target_types=("ip", "host", "url"),
            typical_duration="a few seconds",
        ),
    ],
    flag_help={
        "whatweb": "The program itself - a web technology fingerprinter.",
        "-a": "Aggression level: 1 is passive, 3 sends extra confirming requests.",
        "--log-json=-": "Write results as JSON to standard output, so they can be parsed reliably.",
        "--follow-redirect=always": "Follow HTTP redirects and fingerprint the page you end up on.",
        "--follow-redirect=never": "Report on exactly the URL given, even if it redirects.",
        "--no-errors": "Do not clutter the output with connection error chatter.",
        "--colour=never": "Plain text with no terminal colour codes.",
    },
)


HINTS = [
    (r"cannot load such file|LoadError|ruby",
     "whatweb is a Ruby program and something it needs is missing. On Kali: sudo apt install "
     "-y whatweb"),
    (r"Connection refused|Failed to open TCP|timed out",
     "Nothing answered on that URL. Check the host and port, and whether the site speaks HTTP "
     "or HTTPS."),
]


def build(goal_id: str, target: str, opts: dict) -> BuildResult:
    if goal_id != "fingerprint":
        raise validate.ValidationError(f"Unknown whatweb goal {goal_id!r}.")

    url = target if target.lower().startswith(("http://", "https://")) else f"http://{target}"
    validate.classify(url)

    aggression = validate.validate_choice(str(opts.get("aggression", "1")), ["1", "3"], "aggression level")
    follow = "always" if opts.get("follow", True) else "never"

    args = ["-a", aggression, f"--follow-redirect={follow}", "--colour=never",
            "--log-json=-", "--no-errors"]
    args += validate.validate_raw_flags(opts.get("raw_flags", ""))
    args += [url]

    warns: list[Warning_] = []
    if aggression == "3":
        warns.append(Warning_(
            "info", "Level 3 is no longer passive",
            "whatweb will send extra requests to confirm what it suspects - for example "
            "asking for a file that only exists in one CMS. Useful, but it now shows up in "
            "the target's logs as probing rather than browsing."))

    notes = []
    if not target.lower().startswith(("http://", "https://")):
        notes.append(f"No scheme given, so http:// was assumed: {url}.")
    return BuildResult(args=args, warnings=warns, notes=notes, est_seconds=15)


def parse(stdout: str, stderr: str, target: str) -> list[dict]:
    out: list[dict] = []
    text = stdout.strip()
    records: list[dict] = []

    start = text.find("[")
    if start >= 0:
        try:
            data = json.loads(text[start:])
            records = data if isinstance(data, list) else [data]
        except ValueError:
            records = []
    if not records:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except ValueError:
                    pass

    for rec in records:
        target_url = rec.get("target") or target
        status = rec.get("http_status")
        plugins = rec.get("plugins") or {}
        if status:
            out.append(finding(target_url, "web", {
                "kind": "status", "message": f"HTTP {status}",
                "severity": "info", "path": "",
            }))
        for name, detail in sorted(plugins.items()):
            bits: list[str] = []
            if isinstance(detail, dict):
                for key in ("string", "version", "module", "account", "os"):
                    vals = detail.get(key)
                    if vals:
                        bits.extend(str(v) for v in (vals if isinstance(vals, list) else [vals]))
            value = ", ".join(dict.fromkeys(bits))[:400]
            out.append(finding(target_url, "tech", {
                "plugin": name, "value": value,
                "has_version": any(ch.isdigit() for ch in value),
                "severity": "info",
            }))
    return out
