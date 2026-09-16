"""The tool catalog, and the single place a ScanPlan is created.

plan() is the only way to produce a command in this application. The argv it
returns is what the preview shows AND what the runner executes - there is no
second path, so the preview cannot drift from reality (PRD G2).
"""
from __future__ import annotations

from .. import validate
from . import gobuster, masscan, nikto, nmap, nuclei, whatweb
from .base import ScanPlan, Tool, Warning_

MODULES = {
    m.TOOL.id: m for m in (nmap, masscan, nuclei, whatweb, gobuster, nikto)
}
ORDER = ["nmap", "masscan", "nuclei", "whatweb", "gobuster", "nikto"]

# Goals offered in the guided builder, in the order a beginner should meet them.
# Each entry points at (tool_id, goal_id) and is phrased as a question about the
# target rather than as a tool name.
GUIDED = [
    {"id": "alive", "tool": "nmap", "goal": "discover",
     "label": "Which machines in this range are alive?",
     "icon": "radar", "step": "Start here for a range"},
    {"id": "ports", "tool": "nmap", "goal": "quick_ports",
     "label": "What ports are open on this host?",
     "icon": "door", "step": "Start here for one host"},
    {"id": "fast", "tool": "masscan", "goal": "fast_sweep",
     "label": "Sweep a whole range for open ports, fast",
     "icon": "bolt", "step": "When the scope is big"},
    {"id": "services", "tool": "nmap", "goal": "services",
     "label": "What software is behind those open ports?",
     "icon": "tag", "step": "After you have open ports"},
    {"id": "os", "tool": "nmap", "goal": "os_detect",
     "label": "What operating system is this?",
     "icon": "chip", "step": "After you have open ports"},
    {"id": "udp", "tool": "nmap", "goal": "udp",
     "label": "Are there UDP services a TCP scan missed?",
     "icon": "wave", "step": "Easy to forget"},
    {"id": "webtech", "tool": "whatweb", "goal": "fingerprint",
     "label": "What is this website built with?",
     "icon": "layers", "step": "Start here for a web target"},
    {"id": "webvuln", "tool": "nuclei", "goal": "known_vulns",
     "label": "Does this target have known vulnerabilities?",
     "icon": "shield", "step": "After you know the stack"},
    {"id": "nsevuln", "tool": "nmap", "goal": "vuln_nse",
     "label": "Do these services have known vulnerabilities? (nmap scripts)",
     "icon": "shield", "step": "After you know the services"},
    {"id": "webserver", "tool": "nikto", "goal": "web_server_scan",
     "label": "Is this web server misconfigured?",
     "icon": "server", "step": "After you know the stack"},
    {"id": "hidden", "tool": "gobuster", "goal": "dir_discovery",
     "label": "What pages exist that nothing links to?",
     "icon": "search", "step": "After you know the stack"},
]


def tool(tool_id: str) -> Tool:
    try:
        return MODULES[tool_id].TOOL
    except KeyError as exc:
        raise validate.ValidationError(f"Unknown tool {tool_id!r}.") from exc


def catalog() -> list[dict]:
    return [MODULES[t].TOOL.as_json() for t in ORDER]


def explain_argv(t: Tool, argv: list[str]) -> list[dict]:
    """Attach a plain-English note to each token of the command preview."""
    help_map = t.flag_help
    out: list[dict] = []
    for i, token in enumerate(argv):
        note = help_map.get(token, "")
        if not note and token.startswith("-"):
            base = token.split("=", 1)[0]
            note = help_map.get(base, "")
        if not note and i > 0 and not token.startswith("-"):
            prev = argv[i - 1]
            if prev.startswith("-") and prev in help_map:
                note = f"The value for {prev}."
            elif i == len(argv) - 1:
                note = "The target you are scanning."
        out.append({"token": token, "help": note})
    return out


def plan(tool_id: str, goal_id: str, target: str, opts: dict | None = None) -> ScanPlan:
    """Build the one immutable plan: preview and execution come from this argv."""
    opts = opts or {}
    t = tool(tool_id)
    goal = t.goal(goal_id)

    value, ttype = validate.validate_target(target)
    if ttype not in goal.target_types:
        nice = {"ip": "an IP address", "cidr": "a CIDR range", "range": "an address range",
                "host": "a hostname", "url": "a URL"}
        raise validate.ValidationError(
            f"'{goal.label}' cannot take {nice.get(ttype, ttype)}. "
            f"It accepts: {', '.join(goal.target_types)}.")

    # Every option's declared default applies unless the caller overrode it, so a
    # partial option set (or none at all, as when re-running a past scan) still
    # produces the same safe command the guided form would have built.
    merged = {o.id: o.default for o in goal.options}
    merged.update({k: v for k, v in opts.items() if v is not None and v != ""})

    result = MODULES[tool_id].build(goal_id, value, merged)
    argv = [t.binary, *result.args]

    warnings = list(result.warnings)
    if goal.root_recommended or t.needs_root:
        warnings.append(Warning_(
            "info", "This scan wants root privileges",
            "Raw packet features (SYN scans, OS detection, UDP scans) need root. On Kali "
            "that means running ReconScan with sudo. Without it the tool will either fall "
            "back to a slower technique or refuse - it will say which."))

    return ScanPlan(
        tool_id=t.id, tool_name=t.name, binary=t.binary,
        goal_id=goal.id, goal_label=goal.label, target=value,
        argv=argv, warnings=warnings, notes=result.notes,
        explained=explain_argv(t, argv),
        host_count=validate.host_count(validate.scan_host_part(value)),
        est_seconds=result.est_seconds,
        needs_root=goal.root_recommended or t.needs_root,
    )


def parse(tool_id: str, goal_id: str, stdout: str, stderr: str, target: str) -> list[dict]:
    try:
        return MODULES[tool_id].parse(stdout, stderr, target)
    except Exception:  # a parser bug must never lose the raw evidence
        return []


def hint_for(tool_id: str, text: str) -> str | None:
    """Turn a recognised tool failure into something a beginner can act on.

    Tools report problems in their own idiom - '[FTL] no templates provided for
    scan' is perfectly clear if you already know nuclei, and meaningless if you
    do not. Each tool module lists the failures worth translating.
    """
    import re
    mod = MODULES.get(tool_id)
    for pattern, message in getattr(mod, "HINTS", []):
        if re.search(pattern, text, re.IGNORECASE):
            return message
    return None
