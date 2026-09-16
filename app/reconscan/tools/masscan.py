"""masscan - very fast port sweeps across many hosts."""
from __future__ import annotations

import re

from .. import validate
from .base import BuildResult, Card, Goal, Option, Tool, Warning_, RAW_FLAGS, finding

RATE = Option(
    id="rate", label="Packets per second", type="number", default=1000,
    help=("masscan's speed dial, and the only setting that really matters. 1,000/s is "
          "gentle and safe on a lab network. 10,000+ can saturate a small network or "
          "knock over cheap switches and VPNs - including your own. The tool's author "
          "notes that the default of 100 is deliberately timid for a reason."),
    min=10, max=100000,
)

PORTS = Option(
    id="ports", label="Ports to sweep", type="text", default="1-1000",
    help=("masscan has no 'top ports' database - you tell it exactly which ports to try. "
          "1-1000 covers the well-known services; 1-65535 is the full sweep it was built for."),
    placeholder="1-1000",
)

TOOL = Tool(
    id="masscan",
    name="masscan",
    binary="masscan",
    category="Ultra-fast port discovery",
    needs_root=True,
    card=Card(
        what=("masscan does one job: find open TCP ports, very fast, across very large "
              "address ranges. It writes its own packets instead of using the operating "
              "system's networking, which is why it can sweep an entire subnet in the "
              "time nmap takes to finish one host."),
        why=("When your scope is a whole range rather than one machine, masscan turns "
             "'65,535 ports x 254 hosts' into a short list of interesting places to point "
             "nmap at. It is a scoping tool, not an analysis tool."),
        when=("Use it as a first pass over a range, then hand the open ports it finds to "
              "nmap -sV for the detail. For a single host, just use nmap."),
        noise=("Loud by design. It is unmistakable on any monitored network, and at high "
               "rates it can disrupt the network you are scanning from as well as the "
               "one you are scanning."),
        safe_default="1,000 packets/second over ports 1-1000.",
        docs="https://github.com/robertdavidgraham/masscan",
    ),
    goals=[
        Goal(
            id="fast_sweep", label="Sweep a range for open ports (fast)",
            blurb="Find open ports across many hosts quickly, with no service detail.",
            detail=("masscan reports 'port 445 is open on 10.0.0.7' and nothing more - no "
                    "version, no OS, no scripts. That is the trade for the speed. Treat the "
                    "output as a to-do list for nmap."),
            options=[
                PORTS, RATE,
                Option(id="banners", label="Try to grab banners (--banners)", type="bool",
                       default=False,
                       help=("Ask each open port for its greeting line, which often names the "
                             "software. It makes masscan slower and needs extra setup on some "
                             "systems - nmap -sV does this far better."),
                       advanced=True),
                RAW_FLAGS,
            ],
            target_types=("ip", "cidr", "range"),
            root_recommended=True,
            typical_duration="seconds to a few minutes for a /24",
        ),
    ],
    flag_help={
        "masscan": "The program itself - a mass IP port scanner.",
        "-p": "The ports to sweep. masscan needs this spelled out; it has no 'top ports' list.",
        "--rate": "Packets per second. The speed and the risk dial in one number.",
        "--banners": "Also collect the greeting text each open port sends.",
        "--wait": "Seconds to keep listening after the last packet is sent, so late replies still count.",
        "-oL": "Write results in masscan's simple list format.",
    },
)


HINTS = [
    (r"FAIL: permission denied|must be root|Operation not permitted",
     "masscan needs root because it writes raw network packets. On Kali, start ReconScan with "
     "sudo."),
    (r"could not determine default interface|no interface|adapter",
     "masscan could not work out which network interface to use. Pass one explicitly under "
     "Advanced, for example: --adapter eth0"),
    (r"bad IP address|CIDR",
     "masscan did not understand the target. It needs an IP, range or CIDR - it does not "
     "resolve hostnames. Run nmap against the name first to learn its address."),
]


def build(goal_id: str, target: str, opts: dict) -> BuildResult:
    if goal_id != "fast_sweep":
        raise validate.ValidationError(f"Unknown masscan goal {goal_id!r}.")

    host = validate.scan_host_part(target)
    ttype = validate.classify(host)
    if ttype == "host":
        raise validate.ValidationError(
            "masscan needs an IP, range or CIDR - it does not resolve hostnames. "
            "Run nmap against the name first to learn its address.")

    ports = validate.validate_ports(opts.get("ports", "1-1000"))
    rate = validate.validate_int(opts.get("rate", 1000), 10, 100000, "Packets per second")
    hosts = validate.host_count(host)
    nports = validate.port_count(ports)

    args = ["-p", ports, "--rate", str(rate), "--wait", "3"]
    if opts.get("banners"):
        args += ["--banners"]
    args += validate.validate_raw_flags(opts.get("raw_flags", ""))
    args += [host]

    warns = [Warning_(
        "caution", "masscan is loud and it is not gentle",
        "It bypasses the operating system's networking to send packets as fast as you let "
        "it. Anything monitoring this network will see it immediately, and a high rate can "
        "degrade the network for everyone on it. Only point it at a range you are "
        "authorized to scan.")]
    if rate > 10000:
        warns.append(Warning_(
            "danger", f"{rate:,} packets/second is very high",
            "At this rate you can overwhelm small switches, VPN links and virtual lab "
            "networks - including the one your own machine is on. Unless you know the "
            "network can take it, 1,000-5,000 is plenty for a lab."))
    total = hosts * nports
    if total > 2_000_000:
        warns.append(Warning_(
            "caution", f"That is {total:,} probes",
            f"{hosts:,} host(s) x {nports:,} port(s). Roughly "
            f"{int(total / rate / 60) + 1} minute(s) at {rate:,}/s."))

    return BuildResult(
        args=args, warnings=warns,
        notes=["masscan needs root (it crafts raw packets), and on some systems it also "
               "needs the host firewall told to leave its replies alone."],
        est_seconds=int(max(10, total / rate) + 5),
    )


_LINE_RE = re.compile(
    r"Discovered open port (\d{1,5})/(tcp|udp) on ([\d.]+)")
_BANNER_RE = re.compile(
    r"Banner on port (\d{1,5})/(tcp|udp) on ([\d.]+):\s*\[(\w+)\]\s*(.*)")


def parse(stdout: str, stderr: str, target: str) -> list[dict]:
    out: list[dict] = []
    for line in stdout.splitlines():
        m = _LINE_RE.search(line)
        if m:
            port, proto, ip = m.groups()
            out.append(finding(ip, "port", {
                "port": int(port), "proto": proto, "state": "open",
                "service": "", "version": "",
            }))
            continue
        m = _BANNER_RE.search(line)
        if m:
            port, proto, ip, kind, text = m.groups()
            out.append(finding(ip, "service", {
                "port": int(port), "proto": proto, "banner_type": kind,
                "version": text.strip()[:500],
            }))
    return out
