"""nmap - the Swiss-army knife of scanning."""
from __future__ import annotations

import re

from .. import validate
from .base import BuildResult, Card, Goal, Option, Tool, Warning_, RAW_FLAGS, finding

TIMING = Option(
    id="timing", label="Speed / stealth", type="select", default="T4",
    help=("How fast nmap sends packets. Slower is quieter and more accurate on flaky "
          "networks; faster finishes sooner but is easier for a defender to notice and "
          "can miss ports. T3 is nmap's own default; T4 is the usual choice on a fast "
          "local lab network."),
    choices=[
        {"value": "T1", "label": "T1 - sneaky (very slow)", "help": "Minutes to hours. Used to stay under intrusion-detection thresholds."},
        {"value": "T2", "label": "T2 - polite", "help": "Slower, gentle on fragile hosts and low-bandwidth links."},
        {"value": "T3", "label": "T3 - normal (nmap default)", "help": "Balanced. A safe choice when you are unsure."},
        {"value": "T4", "label": "T4 - aggressive (lab default)", "help": "Fast, assumes a reliable network. Fine on a LAN or a lab VM."},
        {"value": "T5", "label": "T5 - insane (may miss things)", "help": "Fastest and loudest. Frequently drops results. Rarely the right answer."},
    ],
)

PORT_SELECTION = Option(
    id="port_mode", label="Which ports to check", type="select", default="top1000",
    help=("A port is a numbered door on a machine; there are 65,535 of them per protocol. "
          "Checking all of them is thorough but slow. The 'top 1000' are the ports that "
          "are actually open in the real world often enough to be worth checking first."),
    choices=[
        {"value": "top100", "label": "Top 100 (fastest)", "help": "The 100 most common ports. Good first look."},
        {"value": "top1000", "label": "Top 1000 (nmap default)", "help": "nmap's default set. The usual starting point."},
        {"value": "all", "label": "All 65,535 ports (-p-)", "help": "Thorough and slow. Finds services hidden on unusual ports."},
        {"value": "custom", "label": "Specific ports...", "help": "Type your own list, e.g. 22,80,443 or 1-1024."},
    ],
)

CUSTOM_PORTS = Option(
    id="ports", label="Port list", type="text", default="22,80,443",
    help="Numbers, commas and dashes only. Example: 22,80,443,8080 or 1-1024.",
    placeholder="22,80,443",
)

SCAN_TYPE = Option(
    id="scan_type", label="Scan technique", type="select", default="syn",
    help=("How nmap tests whether a port is open. SYN (-sS) sends half a handshake and "
          "never completes it - fast and relatively quiet, but needs root. Connect (-sT) "
          "completes a normal TCP connection: no root needed, but slower and more likely "
          "to be logged by the target application."),
    choices=[
        {"value": "syn", "label": "SYN / half-open (-sS) - needs root", "help": "Default for a privileged scan. Fast and quiet."},
        {"value": "connect", "label": "TCP connect (-sT) - no root needed", "help": "Works as a normal user. Slower, and the target app usually logs it."},
    ],
    advanced=True,
)

SERVICE_INTENSITY = Option(
    id="version_intensity", label="Version-detection effort", type="number", default=7,
    help=("0-9. Higher tries more probes against each open port, so it identifies more "
          "software but takes longer and sends more traffic. 7 is nmap's default."),
    min=0, max=9, advanced=True,
)

SKIP_PING = Option(
    id="skip_ping", label="Skip host discovery (-Pn)", type="bool", default=False,
    help=("By default nmap first pings a host and skips it if there is no reply - which "
          "wastes time when a firewall silently drops pings even though the host is up. "
          "-Pn says 'assume it is alive, scan it anyway'. Slower against dead hosts, but "
          "it is the fix when nmap reports 'host seems down' for a machine you know exists."),
)

REASON = Option(
    id="reason", label="Show why each port got its verdict (--reason)", type="bool", default=False,
    help="Adds a column explaining the evidence, e.g. 'syn-ack' for open or 'reset' for closed. Great for learning.",
    advanced=True,
)

TOOL = Tool(
    id="nmap",
    name="nmap",
    binary="nmap",
    category="Port, service and OS scanning",
    needs_root=False,
    card=Card(
        what=("nmap ('Network Mapper') is the standard tool for finding out what is "
              "listening on a machine. It knocks on numbered doors (ports) and reports "
              "which ones answer, what software is behind them, and - with scripts - "
              "whether that software has known problems."),
        why=("After recon tells you which machines exist, nmap tells you what those "
             "machines actually offer. Almost every later step of a test starts from "
             "an nmap result."),
        when=("First thing you run against a host once it is in scope. Start with a quick "
              "port scan, then follow up with version detection on whatever you found."),
        noise=("A default SYN scan is moderately loud: firewalls and IDS products detect "
               "it easily. -T1/-T2 are quieter; -T5 and full-range scans are very loud."),
        safe_default="A -T4 SYN scan of the top 1000 TCP ports on a single host.",
        docs="https://nmap.org/book/man.html",
    ),
    goals=[
        Goal(
            id="discover", label="Find which hosts are alive",
            blurb="Sweep a range and list the machines that answer, without scanning any ports.",
            detail=("A 'ping sweep' (-sn). nmap sends a few different probes to each address "
                    "and reports which ones respond. Use it to turn a subnet like "
                    "192.168.1.0/24 into a short list of real machines before you spend time "
                    "scanning ports. It is the quickest and quietest thing in this tool."),
            options=[TIMING, RAW_FLAGS],
            target_types=("ip", "cidr", "range", "host"),
            typical_duration="seconds for a /24",
        ),
        Goal(
            id="quick_ports", label="Find open ports",
            blurb="Check a host's common ports and report which ones are open.",
            detail=("The bread-and-butter scan. An 'open' port means a program on that "
                    "machine is listening and will talk to you. 'Closed' means the machine "
                    "answered but nothing is listening. 'Filtered' means something (usually "
                    "a firewall) ate the probe so nmap cannot tell."),
            options=[PORT_SELECTION, CUSTOM_PORTS, TIMING, SKIP_PING, SCAN_TYPE, REASON, RAW_FLAGS],
            target_types=("ip", "cidr", "range", "host", "url"),
            root_recommended=True,
            typical_duration="10-60 seconds per host (top 1000)",
        ),
        Goal(
            id="services", label="Identify services and versions",
            blurb="For each open port, work out what software and which version is running.",
            detail=("-sV talks to each open port and matches the reply against a database of "
                    "thousands of service fingerprints. This is the step that turns "
                    "'port 22 is open' into 'OpenSSH 8.2p1 on Ubuntu' - which is what lets "
                    "you look up whether that exact version has known vulnerabilities."),
            options=[PORT_SELECTION, CUSTOM_PORTS, TIMING, SKIP_PING, SERVICE_INTENSITY, SCAN_TYPE, RAW_FLAGS],
            target_types=("ip", "cidr", "range", "host", "url"),
            root_recommended=True,
            typical_duration="1-3 minutes per host",
        ),
        Goal(
            id="os_detect", label="Guess the operating system",
            blurb="Fingerprint the network stack to guess Windows vs Linux and which version.",
            detail=("-O sends a series of unusual packets and compares the exact way the host "
                    "replies against a database. Operating systems differ in tiny details of "
                    "how they build responses, which makes a usable fingerprint. It is a "
                    "guess with a confidence percentage, not a fact, and it needs root."),
            options=[TIMING, SKIP_PING, RAW_FLAGS],
            target_types=("ip", "cidr", "range", "host"),
            root_recommended=True,
            typical_duration="under a minute per host",
        ),
        Goal(
            id="vuln_nse", label="Check for known vulnerabilities (NSE)",
            blurb="Run nmap's vulnerability scripts against the services it finds.",
            detail=("NSE is nmap's scripting engine - small programs that do a focused check, "
                    "such as 'is this SMB server vulnerable to MS17-010?'. The 'vuln' category "
                    "checks for known issues. These scripts look, they do not exploit, but "
                    "some are intrusive enough to crash fragile services, so run them "
                    "knowingly and only in scope."),
            options=[
                Option(
                    id="script_set", label="Which scripts", type="select", default="vuln",
                    help="Script categories to run. 'safe' is the gentlest; 'vuln' is the useful default for this phase.",
                    choices=[
                        {"value": "safe", "label": "safe - cannot disrupt the target", "help": "Scripts nmap classifies as harmless. Good first pass."},
                        {"value": "default", "label": "default (-sC) - the standard set", "help": "What -sC runs: useful, mostly safe information gathering."},
                        {"value": "vuln", "label": "vuln - look for known vulnerabilities", "help": "The point of this goal. Checks services against known-issue scripts."},
                        {"value": "safe,vuln", "label": "safe + vuln", "help": "Broadest gentle coverage."},
                    ],
                ),
                PORT_SELECTION, CUSTOM_PORTS, TIMING, SKIP_PING, RAW_FLAGS,
            ],
            target_types=("ip", "cidr", "range", "host", "url"),
            root_recommended=True,
            typical_duration="2-10 minutes per host",
        ),
        Goal(
            id="udp", label="Find open UDP ports",
            blurb="Check UDP services like DNS, SNMP and TFTP, which normal TCP scans miss.",
            detail=("UDP has no handshake, so a silent port is ambiguous: it might be open, or "
                    "the reply might just have been dropped. That makes UDP scanning slow and "
                    "noisy in its results ('open|filtered' means nmap genuinely cannot tell). "
                    "Worth doing on the top ports because UDP services are often overlooked "
                    "and under-patched. Needs root."),
            options=[
                Option(id="udp_top", label="How many UDP ports", type="number", default=50,
                       help="UDP scanning is slow - around 1 second per port per host. 50-100 is a sensible lab budget.",
                       min=1, max=1000),
                TIMING, SKIP_PING, RAW_FLAGS,
            ],
            target_types=("ip", "cidr", "range", "host"),
            root_recommended=True,
            typical_duration="1-5 minutes per host",
        ),
    ],
    flag_help={
        "nmap": "The program itself - the Network Mapper.",
        "-sn": "Ping scan: find live hosts but do NOT scan any ports.",
        "-sS": "SYN / half-open scan. Starts a TCP handshake and never finishes it. Fast, relatively quiet, needs root.",
        "-sT": "TCP connect scan. Completes a full connection using the OS. No root needed, but slower and usually logged by the target app.",
        "-sU": "UDP scan. Probes UDP services (DNS, SNMP, TFTP...). Slow, and needs root.",
        "-sV": "Version detection: ask each open port what software and version it is running.",
        "-O": "OS detection: guess the operating system from the exact shape of its network replies. Needs root.",
        "-p-": "Every port from 1 to 65535. Thorough, slow.",
        "-Pn": "Skip host discovery - treat the host as alive even if it does not answer pings.",
        "--reason": "Show the evidence behind each port verdict, e.g. 'syn-ack' or 'reset'.",
        "--open": "Only show open ports, hiding the closed/filtered noise.",
        "-v": "Verbose: print progress while the scan runs instead of only at the end.",
        "-T1": "Timing 'sneaky': very slow, designed to stay under detection thresholds.",
        "-T2": "Timing 'polite': slow and gentle on the target.",
        "-T3": "Timing 'normal': nmap's own default speed.",
        "-T4": "Timing 'aggressive': fast, assumes a reliable network. Usual lab choice.",
        "-T5": "Timing 'insane': fastest and loudest, and it often misses open ports.",
        "-sC": "Run nmap's default script set - handy extra detail about each service.",
        "-n": "Do not do reverse-DNS lookups. Faster, and it avoids tipping off a DNS server.",
    },
)


HINTS = [
    (r"requires root privileges|you requested a scan type which requires root|"
     r"TCP/IP fingerprinting.*requires root|only root",
     "This scan technique needs root. On Kali, start ReconScan with sudo. Or pick options "
     "that do not need raw packets: under Advanced, choose 'TCP connect (-sT)' instead of a "
     "SYN scan, and avoid OS detection and UDP scans."),
    (r"Failed to resolve|Temporary failure in name resolution",
     "nmap could not turn that name into an address. Check the spelling, and check this "
     "machine can reach a DNS server - a lab network is often isolated from the internet."),
    (r"Note: Host seems down",
     "nmap decided the host is down because it did not answer a ping. That is often wrong: "
     "many machines are configured to ignore pings. Turn on 'Skip host discovery (-Pn)' to "
     "scan it anyway."),
    (r"dnet: Failed to open device|WinPcap|Npcap",
     "nmap cannot open the network device it needs for raw packets. On Windows that means "
     "Npcap is missing - install it from npcap.com. On Linux, run with sudo."),
]


def build(goal_id: str, target: str, opts: dict) -> BuildResult:
    goal = TOOL.goal(goal_id)
    args: list[str] = []
    warns: list[Warning_] = []
    notes: list[str] = []

    host = validate.scan_host_part(target)
    hosts = validate.host_count(host)
    est = 30

    def timing() -> str:
        return validate.validate_choice(
            opts.get("timing", "T4"), ["T1", "T2", "T3", "T4", "T5"], "timing")

    def ports_args() -> tuple[list[str], int]:
        mode = validate.validate_choice(
            opts.get("port_mode", "top1000"),
            ["top100", "top1000", "all", "custom"], "port selection")
        if mode == "top100":
            return ["-F"], 100
        if mode == "top1000":
            return [], 1000
        if mode == "all":
            return ["-p-"], 65535
        spec = validate.validate_ports(opts.get("ports", ""))
        return ["-p", spec], validate.port_count(spec)

    if goal_id == "discover":
        args += ["-sn"]
        t = timing()
        args += [f"-{t}"]
        est = max(5, hosts // 20)

    elif goal_id in ("quick_ports", "services", "vuln_nse"):
        stype = validate.validate_choice(
            opts.get("scan_type", "syn"), ["syn", "connect"], "scan technique")
        args += ["-sS"] if stype == "syn" else ["-sT"]
        pargs, nports = ports_args()
        args += pargs
        if goal_id in ("services", "vuln_nse"):
            args += ["-sV"]
            intensity = validate.validate_int(
                opts.get("version_intensity", 7), 0, 9, "Version-detection effort")
            if intensity != 7:
                args += ["--version-intensity", str(intensity)]
        if goal_id == "vuln_nse":
            script_set = validate.validate_choice(
                opts.get("script_set", "vuln"),
                ["safe", "default", "vuln", "safe,vuln"], "script set")
            args += ["--script", script_set]
            warns.append(Warning_(
                "caution", "NSE scripts talk to the service, not just the port",
                "Vulnerability scripts send real requests to the software they are testing. "
                "They do not exploit anything, but a fragile or badly written service can "
                "still crash under the unusual input. Only run these against machines you "
                "are authorized to test and can afford to have hiccup."))
        if opts.get("skip_ping"):
            args += ["-Pn"]
        if opts.get("reason"):
            args += ["--reason"]
        args += ["--open", f"-{timing()}"]
        per_host = nports / 400 + (30 if goal_id != "quick_ports" else 0)
        est = int(max(10, per_host * hosts))

        if nports > 20000:
            warns.append(Warning_(
                "caution", "That is a full 65,535-port scan",
                f"Scanning every port on {hosts} host(s) is thorough but slow - think minutes "
                "per host, not seconds - and it is very visible to anything watching the "
                "network. It is the right call when you suspect a service is hiding on an "
                "unusual port, and overkill as a first look."))
        if timing() == "T5":
            warns.append(Warning_(
                "danger", "T5 usually makes results worse",
                "'Insane' timing fires packets faster than most networks answer, so nmap "
                "gives up on ports that are actually open. It is also the loudest setting. "
                "T4 is almost always the better choice."))

    elif goal_id == "os_detect":
        args += ["-O"]
        if opts.get("skip_ping"):
            args += ["-Pn"]
        args += [f"-{timing()}"]
        est = int(max(15, 20 * hosts))
        notes.append("OS detection needs root. Without it nmap will refuse and say so.")

    elif goal_id == "udp":
        top = validate.validate_int(opts.get("udp_top", 50), 1, 1000, "UDP port count")
        args += ["-sU", "--top-ports", str(top)]
        if opts.get("skip_ping"):
            args += ["-Pn"]
        args += ["--open", f"-{timing()}"]
        est = int(max(30, top * 1.2 * hosts))
        warns.append(Warning_(
            "caution", "UDP scans are slow by nature",
            f"Roughly a second per port per host, so {top} ports x {hosts} host(s) is about "
            f"{int(top * 1.2 * hosts / 60) + 1} minute(s). That is normal, not a hang. "
            "Results marked 'open|filtered' mean nmap got no answer and genuinely cannot "
            "tell the difference between a live service and a dropped packet."))

    else:
        raise validate.ValidationError(f"Unknown nmap goal {goal_id!r}.")

    if hosts > 64:
        warns.append(Warning_(
            "caution", f"This target expands to {hosts:,} addresses",
            "Every one of them gets scanned. Make sure that whole range really is inside "
            "your authorized scope, and expect the scan to take a while."))

    args += ["-v"]
    args += validate.validate_raw_flags(opts.get("raw_flags", ""))
    args += [host]

    if target != host:
        notes.append(f"nmap scans hosts, not URLs, so {target} was reduced to {host}.")
    if goal.root_recommended:
        notes.append("Runs best as root. If you are not root, nmap falls back to a "
                     "connect scan or refuses OS detection - it will tell you either way.")
    return BuildResult(args=args, warnings=warns, notes=notes, est_seconds=est)


# --- parsing ----------------------------------------------------------------
_HOST_RE = re.compile(r"^Nmap scan report for (?:(\S+) \(([\d.]+)\)|(\S+))")
_PORT_RE = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(open|closed|filtered|open\|filtered|closed\|filtered)\s+(\S+)(?:\s+(.*))?$")
_OS_RE = re.compile(r"^(?:OS details|Running|Aggressive OS guesses):\s*(.+)$")
# A script header sits flush against the pipe ("| ftp-anon:" / "|_http-title:").
# Allowing more whitespace would also match the indented reference URLs inside a
# script's own output ("|_    https://cve.mitre.org/..."), inventing scripts named
# "https" and "http", so the leading space budget here is deliberately one.
_SCRIPT_HEAD_RE = re.compile(r"^\|_?[ ]?([a-z0-9][a-z0-9_.-]*):\s*(.*)$")
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})")
_STATE_RE = re.compile(r"\b(VULNERABLE|LIKELY VULNERABLE|NOT VULNERABLE)\b", re.I)


def parse(stdout: str, stderr: str, target: str) -> list[dict]:
    out: list[dict] = []
    host = validate.scan_host_part(target)
    current = host
    script_name: str | None = None
    script_buf: list[str] = []
    script_port: str | None = None
    last_port: str | None = None

    def flush_script() -> None:
        nonlocal script_name, script_buf, script_port
        if script_name and script_buf:
            body = "\n".join(script_buf).strip()
            if body:
                sev = "info"
                m = _STATE_RE.search(body)
                if m and m.group(1).upper().startswith("VULNERABLE"):
                    sev = "high"
                elif m and m.group(1).upper().startswith("LIKELY"):
                    sev = "medium"
                cves = sorted(set(_CVE_RE.findall(body)))
                if cves and sev == "info":
                    sev = "medium"
                out.append(finding(current, "vuln" if sev != "info" else "script", {
                    "script": script_name, "port": script_port,
                    "severity": sev, "cves": cves, "output": body[:4000],
                }))
        script_name, script_buf, script_port = None, [], None

    for raw in stdout.splitlines():
        line = raw.rstrip()

        m = _HOST_RE.match(line)
        if m:
            flush_script()
            current = m.group(2) or m.group(1) or m.group(3) or host
            if m.group(1) and m.group(2):
                out.append(finding(m.group(2), "host", {
                    "hostname": m.group(1), "ip": m.group(2), "state": "up"}))
            else:
                out.append(finding(current, "host", {"ip": current, "state": "up"}))
            last_port = None
            continue

        m = _PORT_RE.match(line)
        if m:
            flush_script()
            port, proto, state, service, version = m.groups()
            last_port = f"{port}/{proto}"
            out.append(finding(current, "port", {
                "port": int(port), "proto": proto, "state": state,
                "service": service, "version": (version or "").strip(),
            }))
            continue

        m = _OS_RE.match(line)
        if m:
            flush_script()
            out.append(finding(current, "os", {"guess": m.group(1).strip()}))
            continue

        if line.startswith("|"):
            m = _SCRIPT_HEAD_RE.match(line)
            if m and not line.startswith("|  "):
                flush_script()
                script_name = m.group(1)
                script_port = last_port
                if m.group(2).strip():
                    script_buf.append(m.group(2).strip())
            else:
                script_buf.append(line.lstrip("|_ ").rstrip())
            continue

        if line.startswith("MAC Address:"):
            out.append(finding(current, "host", {"mac": line.split(":", 1)[1].strip()}))
            continue

        flush_script()

    flush_script()
    return out
