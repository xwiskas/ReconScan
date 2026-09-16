"""gobuster - find pages and directories that are not linked anywhere."""
from __future__ import annotations

import re

from .. import validate
from .base import BuildResult, Card, Goal, Option, Tool, Warning_, RAW_FLAGS, finding

COMMON_WORDLISTS = [
    {"value": "/usr/share/wordlists/dirb/common.txt",
     "label": "dirb common.txt (~4,600 words) - recommended",
     "help": "Ships with Kali. Small, fast, and finds the usual suspects. Start here."},
    {"value": "/usr/share/wordlists/dirb/big.txt",
     "label": "dirb big.txt (~20,000 words)",
     "help": "Four times the coverage, four times the requests and the time."},
    {"value": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
     "label": "dirbuster medium (~220,000 words)",
     "help": "Thorough and slow - tens of minutes, and a very large spike in the target's logs."},
    {"value": "custom", "label": "Another path...", "help": "Type the full path to any wordlist file on the Kali host."},
]

TOOL = Tool(
    id="gobuster",
    name="gobuster",
    binary="gobuster",
    category="Content and directory discovery",
    card=Card(
        what=("gobuster takes a list of likely names and asks the web server about each "
              "one in turn: /admin? /backup? /config.php? Anything that does not come "
              "back as 'not found' is something that exists but is not linked from the "
              "site's pages."),
        why=("Unlinked content is where the interesting things live: forgotten admin "
             "panels, backup files, staging copies, API endpoints. A crawler will never "
             "find them because nothing links to them."),
        when=("After whatweb has told you what the site is - the stack determines which "
              "wordlist and which file extensions are worth trying."),
        noise=("Extremely loud. Thousands of 404s in a few seconds is one of the easiest "
               "attack patterns to spot, and rate limiters and WAFs often block it "
               "part-way through."),
        safe_default="dirb's common.txt with 10 threads against one URL.",
        docs="https://github.com/OJ/gobuster",
    ),
    goals=[
        Goal(
            id="dir_discovery", label="Find hidden pages and directories",
            blurb="Guess common paths against a web server and report which ones exist.",
            detail=("This is brute force by guessing names, not by guessing passwords - it "
                    "never tries to log in to anything. A result is a path that answered "
                    "with something other than 'not found'. A 301 or 302 usually means a "
                    "real directory; a 401 or 403 means it exists and you are not allowed "
                    "in, which is often the most interesting result of all."),
            options=[
                Option(id="wordlist_choice", label="Wordlist", type="select",
                       default="/usr/share/wordlists/dirb/common.txt",
                       help="The list of names to try. Bigger lists find more and take much longer.",
                       choices=COMMON_WORDLISTS),
                Option(id="wordlist", label="Wordlist path", type="text", default="",
                       help="Full path to a wordlist file on the machine running the scan.",
                       placeholder="/usr/share/wordlists/dirb/common.txt"),
                Option(id="extensions", label="Also try file extensions", type="text", default="",
                       help=("Comma separated, no dots: php,txt,bak. Each extension multiplies "
                             "the number of requests by one. Match them to the stack - php on a "
                             "PHP site, asp,aspx on IIS."),
                       placeholder="php,txt,bak"),
                Option(id="threads", label="Parallel requests", type="number", default=10,
                       help=("How many requests are in flight at once. 10 is brisk and usually "
                             "fine. 50+ will hammer a small server and is the quickest way to "
                             "get yourself rate-limited or blocked."),
                       min=1, max=100),
                Option(id="status_codes", label="Treat as 'not found'", type="text", default="404",
                       help=("Responses to ignore. Some servers return 200 with a 'page not "
                             "found' body for everything, which floods the results - in that "
                             "case add that code here or filter by size instead."),
                       advanced=True),
                Option(id="follow_redirect", label="Follow redirects", type="bool", default=False,
                       help="Off is usually better: a 301 tells you the directory exists, and following it just adds noise.",
                       advanced=True),
                Option(id="insecure_tls", label="Ignore TLS certificate errors (-k)", type="bool",
                       default=True,
                       help="Lab machines almost always have self-signed certificates. Without this, every HTTPS request fails.",
                       advanced=True),
                RAW_FLAGS,
            ],
            target_types=("ip", "host", "url"),
            typical_duration="30 seconds to 20 minutes, depending on the wordlist",
        ),
    ],
    flag_help={
        "gobuster": "The program itself - a directory and file brute-forcer.",
        "dir": "The mode: guess paths under a URL. (gobuster also has dns and vhost modes.)",
        "-u": "The base URL to guess paths under.",
        "-w": "The wordlist file - one candidate name per line.",
        "-x": "File extensions to append to each word.",
        "-t": "Number of parallel requests.",
        "-b": "Status codes to treat as 'not found' and hide.",
        "-k": "Do not verify TLS certificates - needed for the self-signed certs common in labs.",
        "-q": "Quiet: results only, no banner.",
        "--no-color": "Plain text with no terminal colour codes.",
        "-r": "Follow redirects instead of just reporting them.",
        "--no-progress": "Do not draw a progress bar (it does not render usefully outside a terminal).",
    },
)


HINTS = [
    (r"no such file or directory|cannot find the (file|path)|wordlist file.*not",
     "gobuster could not open the wordlist. The path is read on the machine running the scan, "
     "not on your browser's machine. On Kali, /usr/share/wordlists/dirb/common.txt comes from "
     "'sudo apt install dirb wordlists'."),
    (r"connection refused|no such host|dial tcp",
     "Nothing answered on that URL. Check the host and port, and whether the site is HTTP or "
     "HTTPS - they are different ports."),
    (r"the server returns a status code that matches the provided options|wildcard",
     "This server answers every request with the same status, so every guess looks like a hit. "
     "Add that status code to 'Treat as not found' under Advanced, and try again."),
    (r"unknown flag|unknown shorthand",
     "One of the extra raw flags is not valid for this version of gobuster. Check it against "
     "'gobuster dir --help' on the machine running the scan."),
]


def build(goal_id: str, target: str, opts: dict) -> BuildResult:
    if goal_id != "dir_discovery":
        raise validate.ValidationError(f"Unknown gobuster goal {goal_id!r}.")

    url = target if target.lower().startswith(("http://", "https://")) else f"http://{target}"
    validate.classify(url)

    choice = (opts.get("wordlist_choice") or "").strip()
    wordlist = (opts.get("wordlist") or "").strip()
    if choice and choice != "custom":
        wordlist = choice
    if not wordlist:
        raise validate.ValidationError("Choose a wordlist, or type the path to one.")
    wordlist = validate.validate_wordlist(wordlist)

    threads = validate.validate_int(opts.get("threads", 10), 1, 100, "Parallel requests")
    codes = (opts.get("status_codes") or "404").strip()
    if not re.match(r"^\d{3}(,\d{3})*$", codes):
        raise validate.ValidationError(
            "'Treat as not found' must be three-digit status codes separated by commas, e.g. 404 or 404,403.")

    args = ["dir", "-u", url, "-w", wordlist, "-t", str(threads), "-b", codes,
            "-q", "--no-color", "--no-progress"]

    exts = (opts.get("extensions") or "").strip().replace(".", "")
    if exts:
        if not re.match(r"^[A-Za-z0-9]{1,10}(,[A-Za-z0-9]{1,10})*$", exts):
            raise validate.ValidationError(
                "Extensions must be letters and digits separated by commas, e.g. php,txt,bak.")
        args += ["-x", exts]
    if opts.get("follow_redirect"):
        args += ["-r"]
    if opts.get("insecure_tls", True):
        args += ["-k"]
    args += validate.validate_raw_flags(opts.get("raw_flags", ""))

    words = {"common.txt": 4600, "big.txt": 20000, "directory-list-2.3-medium.txt": 220000}
    est_words = next((n for k, n in words.items() if wordlist.endswith(k)), 10000)
    multiplier = 1 + len([e for e in exts.split(",") if e]) if exts else 1
    requests = est_words * multiplier

    warns = [Warning_(
        "caution", f"This sends roughly {requests:,} requests",
        "Almost all of them will be 404s. That pattern is unmistakable in a web server log "
        "and is exactly what rate limiters and web application firewalls are built to "
        "catch - do not be surprised if the target starts refusing you part-way through. "
        "Only run it in scope.")]
    if threads > 30:
        warns.append(Warning_(
            "danger", f"{threads} parallel requests is a lot",
            "A small lab web server can fall over under this, which turns a scan into an "
            "accidental denial of service. 10-20 gets you the results without the risk."))
    if requests > 150000:
        warns.append(Warning_(
            "caution", "That wordlist will take a long time",
            "Expect tens of minutes. Start with dirb's common.txt and only escalate if it "
            "finds nothing interesting."))

    notes = [f"Wordlist path is read on the machine running the scan (the Kali host), not "
             f"on your browser's machine."]
    if not target.lower().startswith(("http://", "https://")):
        notes.append(f"No scheme given, so http:// was assumed: {url}.")

    return BuildResult(args=args, warnings=warns, notes=notes,
                       est_seconds=int(max(20, requests / (threads * 25))))


# gobuster 3.6 and earlier printed "/admin (Status: 301)"; 3.7+ dropped the
# leading slash and prints "admin (Status: 301)". Accept either and normalise,
# so the same parser works whichever version the host (or the bundled copy) has.
_RESULT_RE = re.compile(
    r"^(?P<path>/?[^\s(]+)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?")


def parse(stdout: str, stderr: str, target: str) -> list[dict]:
    out: list[dict] = []
    for raw in stdout.splitlines():
        m = _RESULT_RE.match(raw.strip())
        if not m:
            continue
        path, status, size, redirect = (
            m.group("path"), m.group("status"), m.group("size"), m.group("redirect"))
        if not path.startswith("/"):
            path = "/" + path
        code = int(status)
        if code in (401, 403):
            sev = "medium"
        elif code == 200:
            sev = "low"
        else:
            sev = "info"
        low = path.lower()
        if any(k in low for k in ("admin", "backup", ".git", "config", ".env", "phpmyadmin",
                                  "wp-admin", "manager", "console", "dump", ".sql", ".bak")):
            sev = "high" if code in (200, 301, 302, 401, 403) else sev
        out.append(finding(target, "web", {
            "kind": "path", "path": path, "status": code,
            "size": int(size) if size else None,
            "redirect": (redirect or "").strip(), "severity": sev,
            "message": f"{path} responded with HTTP {code}",
        }))
    return out
