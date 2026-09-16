"""Plain-English definitions (PRD F10). Linked from every '?' in the UI."""
from __future__ import annotations

TERMS: list[dict] = [
    {"term": "Port", "tags": ["basics"],
     "short": "A numbered door on a machine that a program can listen behind.",
     "long": ("A single IP address can run many services at once, so each one claims a number "
              "from 1 to 65535. Web servers conventionally take 80 and 443, SSH takes 22. "
              "'Port 22 is open' means a program has claimed door 22 and is answering knocks.")},
    {"term": "Open / closed / filtered", "tags": ["basics", "nmap"],
     "short": "The three answers a port scan can give you, and they are not the same thing.",
     "long": ("Open: a program is listening and replied. Closed: the machine replied, but "
              "nothing is listening there. Filtered: nothing came back at all, so a firewall "
              "is probably dropping your probes and the scanner genuinely cannot tell. "
              "Filtered is not 'safe' - it means you have no information.")},
    {"term": "Service", "tags": ["basics"],
     "short": "The actual program listening on a port.",
     "long": ("nmap guesses the service from the port number alone, which is just convention. "
              "-sV goes further and talks to the port to find out what is really there - "
              "occasionally something completely different from what the number implies.")},
    {"term": "Banner", "tags": ["basics"],
     "short": "The greeting text a service sends when you connect.",
     "long": ("Many services announce themselves: 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5'. "
              "That string is self-reported and can be changed or faked, but it is usually "
              "honest and it is the fastest route to a version number.")},
    {"term": "IP address", "tags": ["basics"],
     "short": "The numeric address of a machine on a network.",
     "long": ("IPv4 addresses look like 192.168.1.10 - four numbers from 0 to 255. Private "
              "ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are reused inside local networks "
              "and are not reachable from the internet.")},
    {"term": "CIDR", "tags": ["basics", "scope"],
     "short": "A compact way to write a block of addresses: 192.168.1.0/24.",
     "long": ("The number after the slash says how many leading bits are fixed. /24 fixes the "
              "first three numbers, leaving 256 addresses (192.168.1.0-255). /16 leaves 65,536. "
              "/32 is a single address. Smaller number after the slash means a bigger block.")},
    {"term": "Host discovery", "tags": ["nmap"],
     "short": "Finding which addresses in a range have a machine behind them.",
     "long": ("nmap -sn sends a few probes to every address and lists the ones that answer. It "
              "turns '256 possible addresses' into 'these 7 real machines', which is where you "
              "then spend your time. Note that a host configured to ignore pings can be missed "
              "- that is what -Pn is for.")},
    {"term": "SYN scan (-sS)", "tags": ["nmap"],
     "short": "Starts a TCP handshake and deliberately never finishes it.",
     "long": ("A normal TCP connection is a three-step handshake: SYN, SYN-ACK, ACK. A SYN scan "
              "sends the first step and reads the reply: SYN-ACK means open, RST means closed. "
              "Then it walks away instead of completing the connection. Faster than a full "
              "connect, and the target application often never logs it - but it needs root "
              "because it writes raw packets.")},
    {"term": "Connect scan (-sT)", "tags": ["nmap"],
     "short": "Completes a normal, full TCP connection to test each port.",
     "long": ("Uses the operating system's ordinary networking, so it needs no special "
              "privileges. The trade-off: it is slower, and because the connection completes, "
              "the application on the other end usually writes a log entry about you.")},
    {"term": "UDP scan (-sU)", "tags": ["nmap"],
     "short": "Probing UDP services, which is slow and inherently ambiguous.",
     "long": ("UDP has no handshake, so silence could mean 'open and not chatty' or 'the packet "
              "was dropped'. nmap reports that honestly as 'open|filtered'. It is slow - about a "
              "second per port - but worth doing, because UDP services like SNMP and TFTP are "
              "frequently forgotten and unpatched.")},
    {"term": "Version detection (-sV)", "tags": ["nmap"],
     "short": "Asking each open port what software and version it runs.",
     "long": ("nmap sends a series of probes and matches the replies against thousands of known "
              "fingerprints. This is the step that converts a port number into an actionable "
              "fact, because vulnerabilities belong to specific versions, not to ports.")},
    {"term": "OS detection (-O)", "tags": ["nmap"],
     "short": "Guessing the operating system from quirks in its network replies.",
     "long": ("Operating systems differ in tiny implementation details - initial sequence "
              "numbers, window sizes, how they answer malformed packets. nmap sends deliberately "
              "odd probes and matches the pattern. You get a guess with a confidence percentage, "
              "not a certainty. Needs root.")},
    {"term": "NSE", "tags": ["nmap"],
     "short": "nmap's Scripting Engine - small programs that extend what nmap can check.",
     "long": ("Scripts are grouped into categories: 'safe' cannot disrupt the target, 'default' "
              "is the standard useful set (-sC), 'vuln' checks for known vulnerabilities, "
              "'intrusive' may disrupt things. They run against the services nmap finds and are "
              "how nmap does far more than count ports.")},
    {"term": "CVE", "tags": ["vuln"],
     "short": "A public catalogue number for one specific security flaw.",
     "long": ("CVE-2021-44228 is Log4Shell, for example. The numbering exists so that everyone "
              "- vendors, scanners, researchers - refers to the same flaw by the same name. "
              "Looking one up gives you the official description, the affected version range "
              "and the fix.")},
    {"term": "CVSS / severity", "tags": ["vuln"],
     "short": "A 0-10 score for how bad a vulnerability is, usually shown as a word.",
     "long": ("Critical (9-10), High (7-8.9), Medium (4-6.9), Low (0.1-3.9). The score rates the "
              "flaw in the abstract, not its impact on this particular target - a critical flaw "
              "in a service nobody can reach matters less than a medium one on your front door. "
              "Use it to sort, not to conclude.")},
    {"term": "False positive", "tags": ["vuln"],
     "short": "A scanner saying something is vulnerable when it is not.",
     "long": ("Scanners match patterns - a version string, a response shape - and patterns "
              "mislead. A backported security fix, for instance, leaves the version number "
              "unchanged. Confirming findings by hand before reporting them is most of what "
              "separates a professional report from a tool dump.")},
    {"term": "Scope", "tags": ["scope", "legal"],
     "short": "The explicit list of systems you are permitted to test.",
     "long": ("Scope is a legal boundary, not a suggestion. Anything outside it is unauthorized "
              "access to a computer system, which is a crime in most countries regardless of "
              "your intentions or whether you caused harm. ReconScan blocks scans of targets "
              "you have not declared in scope, and that guardrail is there for your protection.")},
    {"term": "Authorization", "tags": ["legal"],
     "short": "Written permission from someone with the authority to grant it.",
     "long": ("'The owner said it was fine' needs to be in writing, from a person entitled to "
              "authorise it, naming the systems and the dates. For a class, that is your "
              "instructor's lab brief. For practice on your own, use your own VMs or a site "
              "that publishes permission, such as scanme.nmap.org.")},
    {"term": "scanme.nmap.org", "tags": ["legal", "practice"],
     "short": "A host the nmap project maintains specifically so people can practise scanning it.",
     "long": ("Permission is published by its operators, with the request that you keep it to a "
              "few scans a day and do not run heavy tooling against it. It is one of the very "
              "few internet hosts you may legally scan without a personal agreement.")},
    {"term": "Noise / detection", "tags": ["opsec"],
     "short": "How obvious your scanning is to anyone watching the network.",
     "long": ("Speed is the main dial. A -T5 nmap scan or a gobuster run generates a pattern no "
              "monitoring system can miss. On an authorized test that is often fine - and "
              "sometimes the point, if the client wants to know whether their monitoring "
              "notices. Decide deliberately rather than by accident.")},
    {"term": "Wordlist", "tags": ["web"],
     "short": "A file of candidate names, one per line, used for guessing.",
     "long": ("Directory discovery tries every name in the list against the server. Kali ships "
              "several under /usr/share/wordlists - dirb/common.txt (~4,600 entries) is the "
              "usual starting point. Bigger lists find more and take proportionally longer.")},
    {"term": "Directory / content discovery", "tags": ["web"],
     "short": "Finding pages on a web server that nothing links to.",
     "long": ("A crawler can only follow links. Content discovery guesses instead, which is how "
              "you find /admin, /backup.zip, /.git and /old-site. Note this brute-forces "
              "names, not passwords - it never tries to log in.")},
    {"term": "HTTP status code", "tags": ["web"],
     "short": "The three-digit verdict a web server gives each request.",
     "long": ("200 OK, 301/302 redirect, 401 needs authentication, 403 forbidden, 404 not found, "
              "500 server error. During content discovery, 403 is often the most interesting: "
              "the server has confirmed the path exists while refusing to show it.")},
    {"term": "Fingerprinting", "tags": ["web"],
     "short": "Working out what software a target is built from.",
     "long": ("Headers, cookie names, HTML comments, script paths and error pages all leak "
              "identity. whatweb reads them and names the stack. Knowing the stack is what makes "
              "every later check targeted instead of speculative.")},
    {"term": "SMB", "tags": ["services"],
     "short": "Windows file and printer sharing, on ports 139 and 445.",
     "long": ("Among the highest-value findings on a Windows network. Shares are frequently "
              "readable by everyone, the protocol leaks the OS version and domain name freely, "
              "and unpatched versions have had severe flaws such as MS17-010 (EternalBlue).")},
    {"term": "Enumeration", "tags": ["methodology"],
     "short": "The phase after scanning: extracting detail from services you found.",
     "long": ("Scanning finds a share; enumeration lists what is in it. Scanning finds LDAP; "
              "enumeration pulls the user list. It is still read-only, but it is more intrusive "
              "than scanning, so make sure it is inside your scope. ReconScan covers the lighter "
              "end of enumeration and stops before exploitation.")},
    {"term": "Exploitation", "tags": ["methodology"],
     "short": "Actually using a vulnerability to gain access. Out of scope here.",
     "long": ("The phase after enumeration, and deliberately outside what ReconScan does. This "
              "tool takes you up to 'here is a likely weakness, verified as best we can from "
              "the outside' and stops. That boundary is the difference between an assessment "
              "and an intrusion.")},
    {"term": "Demo mode", "tags": ["reconscan"],
     "short": "The whole app driven by realistic saved output, with no packets sent.",
     "long": ("Every screen, parser and report works exactly as it does for real, but the tool "
              "output comes from stored fixtures. Nothing is sent to any network. Use it to "
              "learn the workflow, and to try a tool before you point it at something real.")},
    {"term": "Command injection", "tags": ["reconscan", "security"],
     "short": "Tricking a program into running a command you did not intend.",
     "long": ("If an app built 'nmap ' + whatever_you_typed and handed it to a shell, typing "
              "'; rm -rf /' would be catastrophic. ReconScan never builds a shell string: "
              "commands are lists of separate arguments handed straight to the operating "
              "system, and every value is pattern-checked first. It is worth understanding, "
              "because it is the same class of bug you will be looking for in targets.")},
    {"term": "Rate limiting", "tags": ["opsec", "web"],
     "short": "A server slowing you down or blocking you for making too many requests.",
     "long": ("If a scan suddenly returns nothing but errors, you have probably been rate "
              "limited or blocked rather than run out of things to find. Lower the thread count "
              "or request rate and try again - and note the behaviour, because it tells you "
              "the target has defences.")},
]


def search(q: str) -> list[dict]:
    q = (q or "").strip().lower()
    if not q:
        return TERMS
    return [t for t in TERMS
            if q in t["term"].lower() or q in t["short"].lower()
            or q in t["long"].lower() or any(q in tag for tag in t["tags"])]
