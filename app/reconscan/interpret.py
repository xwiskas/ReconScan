"""The interpretation layer (PRD F7) - what a finding means and what to do next.

Every suggested next step stays inside the scanning/enumeration boundary the PRD
sets. Nothing here suggests exploiting anything, and where a next step would
cross that line we say so explicitly instead.
"""
from __future__ import annotations

import re

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

# --- what a port usually means ---------------------------------------------
# what:  plain-English description of the service
# note:  why a tester cares about it
# next:  the logical next step, still within scanning/enumeration
PORTS: dict[int, dict] = {
    21: {"name": "FTP", "what": "File Transfer Protocol - an old way of moving files around.",
         "note": "FTP usually sends usernames and passwords in plain text, so anyone on the network path can read them. Many FTP servers also allow 'anonymous' login.",
         "next": "Run nmap's ftp-anon script to check whether anonymous login is allowed, and -sV to get the exact server version.", "weight": "medium"},
    22: {"name": "SSH", "what": "Secure Shell - encrypted remote command-line access.",
         "note": "SSH itself is solid; what matters is the version (old ones have known flaws) and whether weak passwords are accepted.",
         "next": "Get the exact version with nmap -sV, then look it up. Password guessing is a credential attack and is outside this tool's scope.", "weight": "low"},
    23: {"name": "Telnet", "what": "Unencrypted remote command-line access - the ancestor of SSH.",
         "note": "Everything, including the password, travels in clear text. Finding telnet open in 2026 is itself a finding worth writing up.",
         "next": "Grab the banner with nmap -sV and record it as a finding: cleartext administrative access.", "weight": "high"},
    25: {"name": "SMTP", "what": "The protocol mail servers use to send mail.",
         "note": "Misconfigured SMTP can relay mail for strangers, or leak valid usernames through VRFY.",
         "next": "Run nmap's smtp-commands and smtp-open-relay scripts to see what the server allows.", "weight": "medium"},
    53: {"name": "DNS", "what": "Domain Name System - turns names into IP addresses.",
         "note": "A DNS server that allows a zone transfer will hand you a complete list of the names it knows about.",
         "next": "Try nmap's dns-zone-transfer script (a read-only request) to see if the server is too generous.", "weight": "medium"},
    69: {"name": "TFTP", "what": "Trivial FTP - file transfer with no authentication at all.",
         "note": "By design it has no login. Network devices often use it for config backups, which is exactly what you would not want readable.",
         "next": "Note it as a finding. Any file retrieval here is enumeration - keep it to what your scope allows.", "weight": "high"},
    80: {"name": "HTTP", "what": "A web server, unencrypted.",
         "note": "A whole application lives behind this port. It is usually the largest attack surface on a host.",
         "next": "Fingerprint it with whatweb, then run nikto and gobuster against it.", "weight": "medium"},
    110: {"name": "POP3", "what": "An old protocol for downloading email.",
          "note": "Often unencrypted, so credentials can be read off the wire.",
          "next": "Check with nmap -sV whether STARTTLS is offered.", "weight": "medium"},
    111: {"name": "RPCbind", "what": "A directory of other RPC services on the machine.",
          "note": "It tells you which other services exist and on which ports - useful information disclosure, and often a path to NFS.",
          "next": "Run nmap's rpcinfo script to list the registered services.", "weight": "medium"},
    135: {"name": "MSRPC", "what": "Windows remote procedure call endpoint mapper.",
          "note": "A strong sign this is a Windows machine, and a starting point for Windows enumeration.",
          "next": "Combine with ports 139/445 and run nmap -O to confirm the Windows version.", "weight": "medium"},
    139: {"name": "NetBIOS", "what": "Legacy Windows file and printer sharing.",
          "note": "The old sibling of port 445. Where it is open, SMB enumeration is usually possible.",
          "next": "Run nmap's smb-os-discovery and smb-enum-shares scripts.", "weight": "medium"},
    143: {"name": "IMAP", "what": "A protocol for reading email on the server.",
          "note": "Like POP3, it matters whether the connection is encrypted.",
          "next": "Check the version and TLS support with nmap -sV.", "weight": "low"},
    161: {"name": "SNMP", "what": "Simple Network Management Protocol - remote monitoring of devices.",
          "note": "A genuine favourite. Devices are routinely left with the default community string 'public', which reads out interfaces, routes, processes and sometimes configurations.",
          "next": "Run nmap's snmp-info script. This is enumeration, so check it is inside your scope first.", "weight": "high"},
    389: {"name": "LDAP", "what": "Directory service - usually Active Directory on a Windows network.",
          "note": "LDAP that allows anonymous binding will describe the whole directory: users, groups, computers.",
          "next": "Run nmap's ldap-rootdse script to see what an unauthenticated client is shown.", "weight": "high"},
    443: {"name": "HTTPS", "what": "A web server, encrypted with TLS.",
          "note": "Same large attack surface as port 80, plus the TLS configuration itself (old protocol versions, expired or self-signed certificates).",
          "next": "Fingerprint with whatweb over https://, and check the TLS setup with nmap's ssl-enum-ciphers script.", "weight": "medium"},
    445: {"name": "SMB", "what": "Windows file sharing (and much more besides).",
          "note": "One of the highest-value ports on any network. Historically the home of EternalBlue/MS17-010, and very often left with readable shares.",
          "next": "Enumerate shares with nmap's smb-enum-shares script and check smb-vuln-ms17-010. Both look only - they do not exploit.", "weight": "high"},
    514: {"name": "Syslog", "what": "Remote logging.",
          "note": "Usually UDP and unauthenticated - logs can be read or forged.",
          "next": "Note it and move on; it is rarely the way in, but it is worth recording.", "weight": "low"},
    587: {"name": "SMTP submission", "what": "The port mail clients use to send mail.",
          "note": "Should require authentication and TLS. If it does not, that is the finding.",
          "next": "Check with nmap's smtp-commands script.", "weight": "medium"},
    1433: {"name": "Microsoft SQL Server", "what": "A database server.",
           "note": "Databases should almost never be reachable from a general network. Old versions and default credentials are common.",
           "next": "Get the version with nmap's ms-sql-info script and record that the database is network-reachable.", "weight": "high"},
    1521: {"name": "Oracle DB", "what": "An Oracle database listener.",
           "note": "Same reasoning as any exposed database, plus Oracle has a long history of listener issues.",
           "next": "Run nmap's oracle-tns-version script.", "weight": "high"},
    2049: {"name": "NFS", "what": "Unix network file sharing.",
           "note": "Exported shares are frequently world-readable, and sometimes world-writable.",
           "next": "List the exports with nmap's nfs-showmount script.", "weight": "high"},
    3306: {"name": "MySQL / MariaDB", "what": "A database server.",
           "note": "Should be bound to localhost in almost every sane deployment. Reachable over the network is itself worth reporting.",
           "next": "Get the version with nmap's mysql-info script.", "weight": "high"},
    3389: {"name": "RDP", "what": "Windows Remote Desktop.",
           "note": "Direct graphical access to the machine if you have credentials. Old versions had BlueKeep (CVE-2019-0708).",
           "next": "Check the version and encryption with nmap's rdp-ntlm-info and rdp-enum-encryption scripts.", "weight": "high"},
    5432: {"name": "PostgreSQL", "what": "A database server.",
           "note": "As with any exposed database, being network-reachable is the finding.",
           "next": "Confirm the version with nmap -sV.", "weight": "high"},
    5900: {"name": "VNC", "what": "Remote graphical desktop access.",
           "note": "VNC has historically shipped with weak or absent authentication, and its passwords are limited to 8 characters.",
           "next": "Run nmap's vnc-info script to see which authentication types are offered.", "weight": "high"},
    6379: {"name": "Redis", "what": "An in-memory data store.",
           "note": "Redis has no authentication by default. An exposed Redis is usually fully readable and writable by anyone who can reach it.",
           "next": "Confirm with nmap's redis-info script and report it as a critical exposure.", "weight": "high"},
    8080: {"name": "HTTP alternate", "what": "A web server on a non-standard port.",
           "note": "Very often an admin interface, a proxy, a Tomcat manager or a development copy of the main application - things that were never meant to be public.",
           "next": "Treat it exactly like port 80: whatweb, then nikto and gobuster.", "weight": "medium"},
    8443: {"name": "HTTPS alternate", "what": "An encrypted web server on a non-standard port.",
           "note": "Same as 8080 - usually a management console.",
           "next": "Fingerprint over https:// with whatweb.", "weight": "medium"},
    9200: {"name": "Elasticsearch", "what": "A search and analytics database.",
           "note": "Historically unauthenticated by default. An exposed instance often means the whole dataset is readable.",
           "next": "Confirm the version with nmap -sV and report the exposure.", "weight": "high"},
    27017: {"name": "MongoDB", "what": "A document database.",
            "note": "Older versions listened on all interfaces with no authentication - the cause of a long run of public data leaks.",
            "next": "Run nmap's mongodb-info script.", "weight": "high"},
}

SERVICE_HINTS = {
    "http": 80, "https": 443, "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25,
    "domain": 53, "microsoft-ds": 445, "netbios-ssn": 139, "ms-wbt-server": 3389,
    "mysql": 3306, "postgresql": 5432, "vnc": 5900, "redis": 6379, "snmp": 161,
    "ldap": 389, "nfs": 2049, "rpcbind": 111, "msrpc": 135, "imap": 143, "pop3": 110,
}

_OLD_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)")


def _port_knowledge(port: int, service: str) -> dict | None:
    if port in PORTS:
        return PORTS[port]
    guess = SERVICE_HINTS.get((service or "").lower())
    if guess and guess in PORTS:
        return PORTS[guess]
    return None


def interpret(f: dict) -> dict:
    """Add interpretation, suggested_next_step, severity and title to a finding."""
    ftype = f.get("type")
    d = f.get("data") or {}
    out = dict(f)
    sev = (d.get("severity") or "").lower()
    title = ""
    text = ""
    nxt = ""

    if ftype == "port":
        port = int(d.get("port") or 0)
        proto = d.get("proto", "tcp")
        state = d.get("state", "open")
        service = d.get("service") or ""
        version = d.get("version") or ""
        k = _port_knowledge(port, service)
        label = k["name"] if k else (service or "unknown service")
        title = f"{port}/{proto} {state} - {label}"

        if state.startswith("open|"):
            text = (f"Port {port}/{proto} is 'open|filtered', which means nmap sent a probe and "
                    f"got no answer at all. With UDP that is ambiguous by design: a service "
                    f"that simply does not reply looks identical to a firewall dropping the "
                    f"packet. It is not a confirmed open port.")
            nxt = ("Re-probe just this port with version detection (-sUV -p "
                   f"{port}) - if a service is really there, a protocol-specific probe "
                   "usually gets a response.")
            sev = "info"
        elif state == "filtered":
            text = (f"Port {port}/{proto} is filtered: something between you and the host - "
                    f"almost always a firewall - is swallowing the probes, so nmap cannot "
                    f"tell whether anything is listening.")
            nxt = "Note the filtering itself; a firewall that blocks some ports but not others tells you about the network's design."
            sev = "info"
        else:
            text = f"Port {port}/{proto} is open, so a program on this host is listening and will talk to you. "
            if k:
                text += f"{k['what']} {k['note']}"
            else:
                text += ("This is not one of the well-known ports, which makes it interesting in "
                         "its own right - unusual ports often mean custom or forgotten software.")
            if version:
                text += f" Version detection reported: {version}."
            nxt = k["next"] if k else (
                f"Find out what it actually is: nmap -sV -p {port} against this host.")
            sev = k["weight"] if k else "low"
            if not version:
                nxt += " (You have the port but not the software version yet.)"

    elif ftype == "service":
        port = d.get("port")
        title = f"Banner on port {port}"
        text = (f"The service on port {port} identified itself as: {d.get('version','')}. "
                "Banners are self-reported, so they can be wrong or deliberately faked, but "
                "they are usually accurate and the version string is what you search a CVE "
                "database for.")
        nxt = "Search the exact version string for known vulnerabilities, and confirm it with nmap -sV."
        sev = sev or "info"

    elif ftype == "os":
        guess = d.get("guess", "")
        title = f"OS guess: {guess[:80]}"
        text = (f"nmap's fingerprinting suggests: {guess}. This is a guess based on small "
                "quirks in how the host builds its network replies, matched against a "
                "database. It is usually right about the family (Windows vs Linux) and "
                "often vague about the exact version. Treat it as a strong hint.")
        nxt = "Confirm it from a service banner - an SSH or SMB version usually names the distribution outright."
        sev = sev or "info"

    elif ftype == "host":
        ip = d.get("ip") or f.get("target")
        title = f"Host {ip} is up"
        name = d.get("hostname")
        text = f"{ip} responded, so the machine exists and is reachable from here."
        if name:
            text += f" It also has the name {name}, which often hints at its role (a host called 'dc01' is usually a domain controller)."
        nxt = "Scan its ports next to find out what it offers."
        sev = "info"

    elif ftype == "vuln":
        name = d.get("name") or d.get("script") or d.get("template") or "Finding"
        cves = d.get("cves") or []
        title = name if not cves else f"{name} ({', '.join(cves[:3])})"
        sev = sev or "medium"
        desc = (d.get("description") or "").strip()
        text = (desc + " ") if desc else ""
        if cves:
            text += (f"This is linked to {', '.join(cves)}. A CVE is a public catalogue number "
                     "for one specific flaw - searching it gives you the official description, "
                     "the affected versions and the fix. ")
        text += ("The scanner matched a pattern that indicates this issue is present. That is "
                 "evidence, not proof: read the matched output below and confirm the version "
                 "really is in the affected range before you put it in a report.")
        nxt = ("Verify it by hand: check the exact version against the CVE's affected range. "
               "Actually exploiting it belongs to the next phase of the engagement and is "
               "outside what ReconScan does.")

    elif ftype == "script":
        title = f"nmap script: {d.get('script','')}"
        text = ("An nmap script returned information about this service. Script output is "
                "raw detail - certificate names, share lists, supported ciphers, HTTP titles "
                "- and it is often where the useful context lives.")
        nxt = "Read the output below and note anything that names software, users or shares."
        sev = sev or "info"

    elif ftype == "tech":
        plugin = d.get("plugin", "")
        value = d.get("value", "")
        title = f"{plugin}{f' - {value}' if value else ''}"
        text = (f"The site is using {plugin}" + (f" ({value})." if value else ".") + " ")
        if d.get("has_version"):
            text += ("There is a version number here, which is the valuable part: a specific "
                     "version can be looked up against a vulnerability database, and it also "
                     "tells you whether the software is being kept up to date.")
            sev = "low"
        else:
            text += ("No version was exposed, which is mildly good practice on the target's part.")
            sev = "info"
        nxt = ("Search this exact product and version for known issues, and use it to choose "
               "which nuclei tags are worth running.")

    elif ftype == "web":
        kind = d.get("kind")
        if kind == "path":
            path = d.get("path", "")
            status = d.get("status")
            title = f"{path} (HTTP {status})"
            meaning = {
                200: "exists and returned content",
                204: "exists and returned nothing",
                301: "exists and redirects elsewhere - a 301 on a bare name almost always means a real directory",
                302: "exists and redirects elsewhere",
                401: "exists but requires authentication - the server is telling you there is something here worth protecting",
                403: "exists but access is forbidden - often the most interesting result, because the server confirmed the path is real while refusing to show it",
                500: "exists and crashed the server, which suggests it takes input it does not handle well",
            }.get(status, f"answered with status {status}")
            text = f"The path {path} {meaning}. It was found by guessing names, so nothing on the site links to it."
            nxt = ("Open it in a browser and see what it is. If it is a login page, note it; "
                   "guessing credentials is a credential attack and outside this tool's scope.")
            sev = d.get("severity", "info")
        else:
            msg = d.get("message") or d.get("raw") or ""
            title = msg[:90]
            text = (f"{msg} This came from nikto's checklist of known web server issues. "
                    "nikto is thorough and somewhat trigger-happy - confirm anything you "
                    "intend to report by looking at it yourself.")
            refs = d.get("refs") or []
            if refs:
                text += f" Referenced as: {', '.join(refs)}."
            nxt = "Reproduce it manually in a browser or with curl before writing it up."
            sev = d.get("severity", "info")

    else:
        title = ftype or "Finding"
        text = "Raw output from the tool - see the evidence below."
        sev = sev or "info"

    out["title"] = title
    out["interpretation"] = text.strip()
    out["suggested_next_step"] = nxt.strip()
    out["severity"] = sev or "info"
    return out


def summarise(findings: list[dict]) -> dict:
    """The plain-English 'what did this scan actually tell me' block."""
    ports = [f for f in findings if f["type"] == "port" and (f["data"].get("state") == "open")]
    vulns = [f for f in findings if f["type"] == "vuln"]
    hosts = sorted({f["target"] for f in findings})
    webs = [f for f in findings if f["type"] == "web"]
    techs = [f for f in findings if f["type"] == "tech"]
    oss = [f for f in findings if f["type"] == "os"]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[(f.get("severity") or "info")] = counts.get(f.get("severity") or "info", 0) + 1

    lines: list[str] = []
    if hosts:
        lines.append(f"Results cover {len(hosts)} host(s): {', '.join(hosts[:6])}"
                     + (" and others." if len(hosts) > 6 else "."))
    if ports:
        names = []
        for f in ports[:8]:
            p = f["data"]["port"]
            k = _port_knowledge(p, f["data"].get("service", ""))
            names.append(f"{p} ({k['name'] if k else f['data'].get('service') or 'unknown'})")
        lines.append(f"{len(ports)} open port(s) found: {', '.join(names)}"
                     + (", plus more below." if len(ports) > 8 else "."))
        lines.append("Every open port is a program willing to talk to you, and therefore "
                     "something to investigate.")
    if oss:
        lines.append(f"Operating system guess: {oss[0]['data'].get('guess','')[:120]}")
    if techs:
        lines.append(f"{len(techs)} technology component(s) identified on the web target.")
    if webs:
        lines.append(f"{len(webs)} web finding(s) - paths, headers or server issues.")
    if vulns:
        worst = sorted(vulns, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5))[0]
        lines.append(f"{len(vulns)} potential vulnerability finding(s); the most severe is "
                     f"'{worst.get('title','')}' ({worst.get('severity')}).")
        lines.append("These are detections, not confirmations - verify each one before reporting it.")
    if not findings:
        lines.append("No structured findings were parsed from this run. That can mean the "
                     "target had nothing to report, the scan was blocked, or it ended early "
                     "- check the raw output tab to see which.")

    nexts = [f["suggested_next_step"] for f in
             sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5))
             if f.get("suggested_next_step")]
    seen: list[str] = []
    for n in nexts:
        if n not in seen:
            seen.append(n)

    return {"text": " ".join(lines), "counts": counts, "next_steps": seen[:5],
            "open_ports": len(ports), "hosts": len(hosts), "vulns": len(vulns)}
