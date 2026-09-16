"""nuclei - template-driven checks for known issues."""
from __future__ import annotations

import json

from .. import validate
from .base import BuildResult, Card, Goal, Option, Tool, Warning_, RAW_FLAGS, finding

SEVERITY = Option(
    id="severity", label="Report findings of at least", type="select", default="low",
    help=("Every nuclei template carries a severity. Filtering to 'medium and up' cuts "
          "the noise a lot; keeping 'info' shows you everything it noticed, including "
          "harmless facts like which web server is in use."),
    choices=[
        {"value": "info", "label": "info and up (everything)", "help": "Includes purely informational detections. Noisy but educational."},
        {"value": "low", "label": "low and up (default)", "help": "Skips pure information, keeps real findings."},
        {"value": "medium", "label": "medium and up", "help": "Focus on things likely to matter."},
        {"value": "high", "label": "high and critical only", "help": "Only the serious stuff."},
    ],
)

RATE = Option(
    id="rate", label="Requests per second", type="number", default=50,
    help=("How hard nuclei hits the target. 50/s is polite for a lab. Turning this up "
          "makes the scan faster and much more likely to trip rate limits or look like "
          "an attack in the target's logs."),
    min=1, max=1000, advanced=True,
)

TAGS = Option(
    id="tags", label="Only run templates tagged", type="text", default="",
    help=("Optional filter, comma separated. Examples: cve · exposure · misconfig · "
          "wordpress · apache. Leave blank to run everything that matches your severity "
          "filter."),
    placeholder="cve,misconfig", advanced=True,
)

TOOL = Tool(
    id="nuclei",
    name="nuclei",
    binary="nuclei",
    category="Template-based vulnerability scanning",
    card=Card(
        what=("nuclei checks a target against a large community library of YAML 'templates'. "
              "Each template is a recipe: send this request, and if the reply looks like "
              "this, report this issue. Thousands of them ship with the tool, covering "
              "known CVEs, exposed admin panels, default credentials pages, leaked config "
              "files and misconfigurations."),
        why=("It is the fastest way to answer 'does this target have any of the "
             "well-known problems?' - the checks are maintained by a large community, so "
             "coverage of recent CVEs is good."),
        when=("After you know a web service is running and what it is. Point it at the "
              "URL. Running it before you know what is there works, but wastes time."),
        noise=("Loud. It sends a lot of requests with obviously suspicious paths. Any web "
               "application firewall will notice, and some will block you mid-scan."),
        safe_default="Low-and-up severity, 50 requests/second, against one URL.",
        docs="https://docs.projectdiscovery.io/tools/nuclei",
    ),
    goals=[
        Goal(
            id="known_vulns", label="Check for known vulnerabilities",
            blurb="Run the template library against a target and report what matches.",
            detail=("Findings come with a severity and usually a CVE reference. A match "
                    "means the template's conditions were met - it is strong evidence, not "
                    "absolute proof, so always read the matched request/response before you "
                    "write it up. nuclei detects; it does not exploit."),
            options=[SEVERITY, RATE, TAGS, RAW_FLAGS],
            target_types=("ip", "host", "url"),
            typical_duration="2-15 minutes per target",
        ),
        Goal(
            id="tech_detect", label="Identify the technology stack",
            blurb="Use only the fingerprinting templates to see what the target is built with.",
            detail=("The 'tech' tag templates identify servers, frameworks, CMSs and "
                    "libraries without testing for any weakness. Quiet, quick, and a good "
                    "way to decide which deeper checks are worth running."),
            options=[RATE, RAW_FLAGS],
            target_types=("ip", "host", "url"),
            typical_duration="under a minute",
        ),
    ],
    flag_help={
        "nuclei": "The program itself - a template-based vulnerability scanner.",
        "-u": "The target URL or host to scan.",
        "-severity": "Only run templates of these severities.",
        "-tags": "Only run templates carrying these tags.",
        "-rate-limit": "Maximum requests per second.",
        "-jsonl": "Print one JSON object per finding, so the results can be parsed reliably instead of scraped from text.",
        "-silent": "Print findings only - no banner or progress chatter.",
        "-no-color": "Plain text output with no terminal colour codes.",
        "-duc": "Do not auto-update the template library mid-scan (keeps an offline run predictable).",
        "-stats": "Print periodic progress statistics while running.",
    },
)

# Recognisable failures, turned into something a beginner can act on.
HINTS = [
    (r"no templates provided|could not find templates|templates directory.*not found",
     "nuclei is installed but has no template library yet - the binary ships without one. "
     "Download it once with:  nuclei -update-templates  (about 50 MB, needs internet). "
     "ReconScan passes -duc so nuclei never downloads templates mid-scan behind your back, "
     "which is why this does not fix itself."),
    (r"could not create client|no address found|dial tcp.*connect",
     "nuclei could not reach the target. Check the host is up and that you used the right "
     "scheme - http:// and https:// are different ports, and a target that only speaks HTTPS "
     "will refuse a plain http:// request."),
    (r"context deadline exceeded|timeout",
     "nuclei timed out waiting for the target. The host may be slow, firewalled, or rate "
     "limiting you part-way through. Try a lower requests-per-second setting."),
]

_SEV_CHAIN = {
    "info": "info,low,medium,high,critical",
    "low": "low,medium,high,critical",
    "medium": "medium,high,critical",
    "high": "high,critical",
}


def build(goal_id: str, target: str, opts: dict) -> BuildResult:
    url = target if target.lower().startswith(("http://", "https://")) else f"http://{target}"
    validate.classify(url)

    rate = validate.validate_int(opts.get("rate", 50), 1, 1000, "Requests per second")
    args = ["-u", url, "-jsonl", "-silent", "-no-color", "-duc", "-rate-limit", str(rate)]
    warns: list[Warning_] = []
    notes: list[str] = []

    if goal_id == "known_vulns":
        sev = validate.validate_choice(
            opts.get("severity", "low"), list(_SEV_CHAIN), "severity filter")
        args += ["-severity", _SEV_CHAIN[sev]]
        tags = (opts.get("tags") or "").strip()
        if tags:
            for t in tags.split(","):
                if not t.strip().replace("-", "").replace("_", "").isalnum():
                    raise validate.ValidationError(
                        f"{t.strip()!r} is not a valid template tag (letters, digits, - and _ only).")
            args += ["-tags", ",".join(t.strip() for t in tags.split(",") if t.strip())]
        est = 300
        warns.append(Warning_(
            "caution", "nuclei sends thousands of deliberately odd requests",
            "That is how the checks work, but it means the target's logs will fill with "
            "requests for admin panels, backup files and exploit paths. On a monitored "
            "network this is the single most obvious thing in this toolkit. Make sure the "
            "target is in scope and that someone expects the traffic."))
    elif goal_id == "tech_detect":
        args += ["-tags", "tech", "-severity", "info,low,medium,high,critical"]
        est = 45
    else:
        raise validate.ValidationError(f"Unknown nuclei goal {goal_id!r}.")

    args += validate.validate_raw_flags(opts.get("raw_flags", ""))

    if not target.lower().startswith(("http://", "https://")):
        notes.append(f"No scheme given, so http:// was assumed: {url}. "
                     "If the service is HTTPS, enter the full https:// URL instead.")
    notes.append("-duc keeps nuclei from updating its templates mid-run. If your template "
                 "library is old, update it deliberately with 'nuclei -update-templates'.")
    return BuildResult(args=args, warnings=warns, notes=notes, est_seconds=est)


def parse(stdout: str, stderr: str, target: str) -> list[dict]:
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        info = rec.get("info") or {}
        classification = info.get("classification") or {}
        cves = [c for c in (classification.get("cve-id") or []) if c]
        out.append(finding(rec.get("host") or target, "vuln", {
            "template": rec.get("template-id") or rec.get("templateID") or "",
            "name": info.get("name") or "",
            "severity": (info.get("severity") or "info").lower(),
            "cves": cves,
            "tags": info.get("tags") or [],
            "matched": rec.get("matched-at") or rec.get("matched") or "",
            "description": (info.get("description") or "").strip()[:2000],
            "reference": info.get("reference") or [],
            "extracted": rec.get("extracted-results") or [],
            "output": (rec.get("request", "") + "\n\n" + rec.get("response", ""))[:4000].strip(),
        }))
    return out
