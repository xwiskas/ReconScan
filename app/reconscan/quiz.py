"""Interactive quizzes (Phase 2).

Two sources of questions:

1. A fixed bank covering methodology, tool choice, reading results, and the legal
   and safety rules. These are the things a beginner gets asked in a viva.
2. Questions generated from your own scans. "You found 3306/MySQL open on
   10.10.10.42 - what is the right next step?" is a far better question than an
   abstract one, because you have the evidence in front of you.

Every question carries an explanation for the right answer AND for why the
tempting wrong answers are wrong, because that is where the learning is.
"""
from __future__ import annotations

import json
import random

from . import db, interpret

# --- the fixed bank ---------------------------------------------------------
# answer: index into options. why: shown after answering, for every option.
BANK: list[dict] = [
    {
        "id": "methodology-order",
        "topic": "Methodology",
        "q": "You have a list of IP addresses from recon. What do you do first?",
        "options": [
            "Run a full 65,535-port scan with version detection on every address",
            "Check which addresses actually have a machine behind them",
            "Start nuclei against all of them to find vulnerabilities quickly",
            "Run gobuster to find hidden pages",
        ],
        "answer": 1,
        "why": [
            "This works, but you will spend most of the time scanning addresses with nothing on them. Narrow first, then go deep.",
            "Correct. A host discovery sweep (nmap -sn) turns 256 possible addresses into the handful that are real, so every later scan is aimed at something that exists.",
            "nuclei needs to know what it is talking to. Pointed at bare IPs with no known services, it mostly wastes time and makes noise.",
            "gobuster only makes sense once you know there is a web server. You do not know that yet.",
        ],
    },
    {
        "id": "port-445",
        "topic": "Reading results",
        "q": "A scan shows 445/tcp open on a host. What does that tell you, and what is the sensible next step?",
        "options": [
            "It is a web server - run nikto against it",
            "It is Windows file sharing (SMB) - enumerate the shares and check the SMB version",
            "It is SSH - try to log in",
            "Nothing useful; port numbers are arbitrary",
        ],
        "answer": 1,
        "why": [
            "445 is not HTTP. nikto would find nothing because it does not speak this protocol.",
            "Correct. 445 is SMB, one of the highest-value findings on a network: shares are often readable, and the protocol leaks the OS version and domain name freely.",
            "SSH is conventionally 22. Also, trying to log in is a credential attack - a different phase, and outside what a scanning tool should do.",
            "Port numbers are conventions rather than rules, but they are followed closely enough to be a strong first guess - and -sV confirms it.",
        ],
    },
    {
        "id": "filtered-meaning",
        "topic": "Reading results",
        "q": "nmap reports a port as 'filtered'. What does that mean?",
        "options": [
            "The port is closed and the host is secure",
            "A service is running but refused your connection",
            "Nothing came back at all, so nmap cannot tell whether anything is listening",
            "The port is open but the service is unknown",
        ],
        "answer": 2,
        "why": [
            "Filtered is not the same as closed. Closed means the host actively replied 'nothing here'. Filtered means silence, which is not evidence of safety.",
            "That would show as closed - an active refusal (a TCP reset) is a reply.",
            "Correct. Something, usually a firewall, swallowed the probe. You have no information about that port, which is different from having negative information.",
            "That would be 'open' with an unrecognised service. Filtered means no reply reached you at all.",
        ],
    },
    {
        "id": "version-matters",
        "topic": "Methodology",
        "q": "Why is 'OpenSSH 4.7p1' more useful to you than 'port 22 is open'?",
        "options": [
            "It is not - both say the same thing",
            "Vulnerabilities belong to specific software versions, so a version is something you can actually look up",
            "Because version strings are always completely reliable",
            "Because it proves the host is running Linux",
        ],
        "answer": 1,
        "why": [
            "'Port 22 is open' tells you a door exists. The version tells you which lock is on it.",
            "Correct. A CVE affects named versions. Without a version you cannot tell whether a known flaw applies, so -sV is the step that makes everything after it possible.",
            "They are usually honest but they are self-reported, and a backported security fix leaves the version number unchanged. Treat a version as strong evidence, not proof.",
            "It is a hint, not proof - and it is not the reason the version matters.",
        ],
    },
    {
        "id": "timing-t5",
        "topic": "Tool choice",
        "q": "Your scan is slow, so you consider switching from -T4 to -T5. What is the catch?",
        "options": [
            "There is no catch; T5 is simply faster",
            "T5 sends packets faster than many networks answer, so it misses open ports - and it is the loudest setting",
            "T5 requires root and T4 does not",
            "T5 only works on Windows targets",
        ],
        "answer": 1,
        "why": [
            "Faster is not free. Speed buys you a worse result here.",
            "Correct. 'Insane' timing gives up on ports that are actually open, so you get a fast answer that is wrong. It is also unmissable to anything monitoring the network.",
            "Timing templates do not change privilege requirements. The scan technique (-sS vs -sT) does.",
            "Timing is unrelated to the target's operating system.",
        ],
    },
    {
        "id": "scope-typo",
        "topic": "Legal and safety",
        "q": "Your lab scope is 10.10.10.0/24. You mistype a target as 10.10.100.5 and scan it. What happened?",
        "options": [
            "Nothing - it was an accident, so it does not count",
            "You scanned a machine outside your authorization, which is unauthorized access regardless of intent",
            "It is fine as long as you found nothing",
            "It is fine because it is a private address",
        ],
        "answer": 1,
        "why": [
            "Intent is not the test. The law asks whether you had authorization for that system, and you did not.",
            "Correct. This is exactly why ReconScan makes you declare scope up front and blocks anything outside it - a typo becomes a refusal instead of an incident.",
            "Whether you found anything does not change whether you were permitted to look.",
            "10.10.100.5 is private, but private does not mean yours. It belongs to someone on that network.",
        ],
    },
    {
        "id": "authorization",
        "topic": "Legal and safety",
        "q": "A friend says you can scan their home server. What do you actually need before you start?",
        "options": [
            "Nothing - verbal permission from the owner is enough in every country",
            "Written permission from someone entitled to give it, naming the systems and the dates",
            "A VPN, so it cannot be traced back to you",
            "Only a note in your own records that you asked",
        ],
        "answer": 1,
        "why": [
            "Verbal permission leaves you with nothing to point at if it is ever questioned, and your friend may not own the network the server sits on.",
            "Correct. Written, specific, dated, and from someone with the authority to grant it. In a class, that is your instructor's lab brief.",
            "Hiding your source is what an attacker does. On an authorized test you have no reason to, and doing so undermines any claim that you were acting in good faith.",
            "Your own note records what you believed, not what you were permitted.",
        ],
    },
    {
        "id": "masscan-vs-nmap",
        "topic": "Tool choice",
        "q": "You have a /16 to survey (65,536 addresses) and limited time. What is the sensible approach?",
        "options": [
            "nmap -p- -sV across the whole range",
            "masscan first to find open ports fast, then nmap -sV on just what it found",
            "nuclei across the range, since it checks everything at once",
            "gobuster against each address in turn",
        ],
        "answer": 1,
        "why": [
            "This is thorough and would take days. nmap is the right tool for depth, not for first-pass breadth.",
            "Correct. masscan answers 'where is anything listening' quickly; nmap then answers 'what is it' on the short list. Breadth first, then depth.",
            "nuclei tests web and service templates against known targets. It is not a discovery tool for bare address ranges.",
            "gobuster guesses paths on a known web server. It has nothing to do with finding hosts.",
        ],
    },
    {
        "id": "false-positive",
        "topic": "Reading results",
        "q": "A scanner reports a critical CVE against a service. What should you do before putting it in your report?",
        "options": [
            "Nothing - the scanner said critical, so it is critical",
            "Check the exact version against the CVE's affected range, and read the evidence the scanner matched on",
            "Exploit it to prove it is real",
            "Raise the severity to be safe",
        ],
        "answer": 1,
        "why": [
            "Scanners match patterns, and patterns mislead. A backported fix leaves the version string unchanged, which produces confident false positives.",
            "Correct. Verifying findings by hand is most of what separates a professional report from a tool dump.",
            "Exploitation is a different phase with different authorization, and it is outside what ReconScan does. Verification does not require it.",
            "Inflating severity makes your report less useful and less trusted. Report what you can support.",
        ],
    },
    {
        "id": "gobuster-403",
        "topic": "Reading results",
        "q": "During content discovery, a path returns HTTP 403. Why is that often more interesting than a 200?",
        "options": [
            "It is not - 403 means the path does not exist",
            "The server confirmed the path is real while refusing to show it, which tells you there is something there worth protecting",
            "403 means the server has crashed",
            "403 means you have been blocked and should stop",
        ],
        "answer": 1,
        "why": [
            "404 means it does not exist. 403 means it exists and you are not allowed in - a meaningful difference.",
            "Correct. A 403 is the server telling you something is there. That is a stronger signal than a public page anyone can read.",
            "A crash would be a 500. A 403 is a deliberate refusal.",
            "Being blocked usually shows as everything failing at once, not one path returning 403. If every request starts failing, then suspect rate limiting.",
        ],
    },
    {
        "id": "udp-openfiltered",
        "topic": "Reading results",
        "q": "A UDP scan reports 161/udp as 'open|filtered'. What does the pipe mean?",
        "options": [
            "The port is both open and firewalled at the same time",
            "No reply came back, and with UDP that is genuinely ambiguous - nmap cannot tell open from dropped",
            "The scan failed and should be re-run",
            "The port alternates between open and closed",
        ],
        "answer": 1,
        "why": [
            "It is not a statement about two simultaneous states - it is a statement about nmap's uncertainty.",
            "Correct. UDP has no handshake, so a service that does not reply looks identical to a firewall dropping the packet. nmap reports that honestly rather than guessing.",
            "The scan worked fine. The ambiguity is inherent to UDP, not a failure.",
            "Nothing is alternating. The scanner simply has insufficient information.",
        ],
    },
    {
        "id": "noise-awareness",
        "topic": "Legal and safety",
        "q": "Why does it matter whether a scan is 'loud'?",
        "options": [
            "It does not - if you are authorized, detection is irrelevant",
            "Because a loud scan can trip defences, get you blocked mid-scan, and on some engagements the client specifically wants to test whether they notice",
            "Because loud scans are illegal and quiet ones are not",
            "Because quiet scans always return better results",
        ],
        "answer": 1,
        "why": [
            "Even when authorized, tripping an alert can trigger an incident response at 2am, waste a team's night, and get your traffic blocked so the rest of your scan returns nothing.",
            "Correct. Noise is an engagement decision. Sometimes you want to be loud and fast; sometimes the point of the test is whether the monitoring catches you. Choose deliberately.",
            "Legality depends on authorization, not on speed.",
            "Quieter is often more accurate, but not always better - a -T1 scan of a /24 can take days you do not have.",
        ],
    },
    {
        "id": "boundary",
        "topic": "Methodology",
        "q": "Your scan finds a service with a known remote code execution flaw. Within the scanning phase, what is the correct next action?",
        "options": [
            "Exploit it immediately to confirm it is real",
            "Verify the version against the CVE, document the evidence, and stop there",
            "Delete the finding since you cannot prove it",
            "Try default passwords on the service",
        ],
        "answer": 1,
        "why": [
            "Exploitation is a separate phase with its own authorization. Doing it because you can is how an assessment becomes an intrusion.",
            "Correct. Scanning takes you to 'here is a likely weakness, verified as far as an outside look allows'. That is a complete and valuable deliverable.",
            "An unconfirmed finding is still worth reporting - clearly labelled as needing verification. Deleting evidence is the opposite of the job.",
            "Password guessing is a credential attack: a different phase, different authorization, and outside what this tool does.",
        ],
    },
    {
        "id": "demo-honesty",
        "topic": "Legal and safety",
        "q": "You explored ReconScan in Demo mode and got a page of realistic findings. Can those go in your report?",
        "options": [
            "Yes - the output looks exactly like a real scan",
            "No - demo output is sample data, and presenting it as results from a real system would be fabricating evidence",
            "Yes, as long as you also ran one real scan somewhere",
            "Only if you change the IP addresses to match your lab",
        ],
        "answer": 1,
        "why": [
            "Looking real is precisely the problem. Demo output is designed to be realistic so you can learn from it, not so it can pass as evidence.",
            "Correct. ReconScan labels demo scans in every report format for exactly this reason. Fabricated evidence is the fastest way to fail an assessment and end a career.",
            "One real scan does not make the other results real.",
            "Editing sample data to look like your lab is fabrication with extra steps.",
        ],
    },
]

TOPICS = sorted({q["topic"] for q in BANK})


# --- questions generated from the user's own scans --------------------------
_GENERATORS = {
    21: ("FTP", "check whether anonymous login is allowed and record the exact server version",
         ["try every password until one works", "ignore it - FTP is always harmless",
          "shut the service down"]),
    23: ("Telnet", "record it as a finding in its own right: administrative access in clear text",
         ["assume it is a typo for SSH", "log in with the default password",
          "treat it as equivalent to SSH"]),
    445: ("SMB", "enumerate the shares and check the SMB version for known flaws",
          ["run nikto against it", "ignore it unless port 80 is also open",
           "try to log in as Administrator"]),
    3306: ("MySQL", "record that a database is reachable over the network and get its version",
           ["connect with the root password 'root'", "ignore it - databases are not in scope",
            "run gobuster against it"]),
    161: ("SNMP", "try the snmp-info script, since devices are routinely left with the default community string",
          ["ignore it - UDP results are never reliable", "brute-force the community string",
           "run nikto against it"]),
    6379: ("Redis", "confirm the version and report the exposure, since Redis has no authentication by default",
           ["write a key to prove you can", "ignore it - Redis is only ever on localhost",
            "run whatweb against it"]),
    5900: ("VNC", "check which authentication types it offers with the vnc-info script",
           ["connect and take a screenshot", "ignore it - VNC needs a password",
            "run gobuster against it"]),
    80: ("HTTP", "fingerprint the stack with whatweb, then run nikto and gobuster",
         ["assume it is a static page and move on", "try SQL injection on every form",
          "run masscan against it again"]),
}


def generated(project_id: str, limit: int = 6) -> list[dict]:
    """Build questions from findings this user actually produced."""
    with db.connect() as conn:
        rows = db.rows_to_list(conn.execute(
            "SELECT f.target, f.type, f.data, s.is_demo FROM findings f "
            "JOIN scans s ON s.id = f.scan_id WHERE s.project_id=? AND f.type='port'",
            (project_id,)))
    seen: set[tuple] = set()
    out: list[dict] = []
    for r in rows:
        d = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
        port = d.get("port")
        if d.get("state") != "open" or port not in _GENERATORS:
            continue
        key = (r["target"], port)
        if key in seen:
            continue
        seen.add(key)
        name, right, wrongs = _GENERATORS[port]
        opts = [right] + list(wrongs)
        order = list(range(len(opts)))
        random.Random(f"{project_id}{key}").shuffle(order)
        shuffled = [opts[i] for i in order]
        answer = order.index(0)
        k = interpret.PORTS.get(port, {})
        why = []
        for i in order:
            if i == 0:
                why.append(f"Correct. {k.get('note', '')} {k.get('next', '')}".strip())
            else:
                why.append(_wrong_reason(opts[i]))
        out.append({
            "id": f"gen-{r['target']}-{port}",
            "topic": "Your scans",
            "q": (f"Your scan of {r['target']} found port {port} open"
                  f"{f' ({name})' if name else ''}"
                  f"{' [from a demo scan]' if r['is_demo'] else ''}. What is the right next step?"),
            "options": shuffled,
            "answer": answer,
            "why": why,
            "generated": True,
        })
        if len(out) >= limit:
            break
    return out


def _wrong_reason(text: str) -> str:
    low = text.lower()
    if any(w in low for w in ("password", "log in", "brute", "connect with")):
        return ("This is a credential attack - a different phase of the engagement, with its own "
                "authorization, and outside what a scanning tool should do.")
    if "ignore" in low:
        return ("Dismissing a finding without looking is how real issues get missed. Every open "
                "port is something willing to talk to you.")
    if "shut" in low or "write a key" in low or "screenshot" in low:
        return ("This changes or uses the target rather than observing it. Scanning is a "
                "read-only activity; anything else needs separate authorization.")
    return ("This tool does not speak that protocol, so it would tell you nothing about this "
            "service. Match the tool to what is actually listening.")


# --- assembling a quiz ------------------------------------------------------
def build(project_id: str | None = None, count: int = 8, topic: str = "") -> list[dict]:
    pool = [q for q in BANK if not topic or q["topic"] == topic]
    gen = generated(project_id) if project_id and topic in ("", "Your scans") else []
    if topic == "Your scans":
        pool = []
    questions = gen + pool
    random.shuffle(questions)
    return [_public(q) for q in questions[:count]]


def _public(q: dict) -> dict:
    """The question without the answer - the client must ask to find out."""
    return {"id": q["id"], "topic": q["topic"], "q": q["q"], "options": q["options"],
            "generated": q.get("generated", False)}


def check(question_id: str, choice: int, project_id: str | None = None) -> dict:
    q = next((x for x in BANK if x["id"] == question_id), None)
    if q is None and project_id:
        q = next((x for x in generated(project_id, limit=50) if x["id"] == question_id), None)
    if q is None:
        raise KeyError(question_id)
    correct = int(choice) == q["answer"]
    with db.connect() as conn:
        conn.execute("INSERT INTO quiz_answers (id, question_id, topic, correct, answered_at)"
                     " VALUES (?,?,?,?,?)",
                     (db.new_id(), q["id"], q["topic"], 1 if correct else 0, db.now()))
    return {"correct": correct, "answer": q["answer"], "why": q["why"],
            "chosen": int(choice)}


def progress() -> dict:
    with db.connect() as conn:
        rows = db.rows_to_list(conn.execute(
            "SELECT topic, correct FROM quiz_answers"))
    by_topic: dict[str, dict] = {}
    for r in rows:
        t = by_topic.setdefault(r["topic"], {"asked": 0, "right": 0})
        t["asked"] += 1
        t["right"] += r["correct"]
    total = len(rows)
    right = sum(r["correct"] for r in rows)
    return {"answered": total, "correct": right,
            "percent": round(right / total * 100) if total else 0,
            "by_topic": by_topic, "topics": TOPICS + ["Your scans"]}


def reset() -> None:
    with db.connect() as conn:
        conn.execute("DELETE FROM quiz_answers")
