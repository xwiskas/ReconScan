"""Demo/Learn mode output (PRD F9).

Realistic saved output for every tool and goal, so the whole application - the
parsers, the interpretation layer, the reports - runs end to end without a
single packet leaving the machine. The target name is substituted in so the
demo reads as if it really ran against what you typed.

The output below is modelled on a deliberately vulnerable practice VM
(Metasploitable-style), which is what a class lab target usually looks like.
"""
from __future__ import annotations

import json

from . import validate

DEMO_IP = "10.10.10.42"


def _ip_for(target: str) -> str:
    host = validate.scan_host_part(target)
    try:
        validate.classify(host)
    except validate.ValidationError:
        return DEMO_IP
    t = validate.classify(host)
    if t == "ip":
        return host
    if t in ("cidr", "range"):
        base = host.split("/")[0].split("-")[0]
        parts = base.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["42"])
    return DEMO_IP


NMAP_DISCOVER = """Starting Nmap 7.94 ( https://nmap.org ) at {date} UTC
Initiating Ping Scan at 14:02
Scanning {count} hosts [4 ports/host]
Completed Ping Scan at 14:02, 2.31s elapsed ({count} total hosts)
Initiating Parallel DNS resolution of {count} hosts. at 14:02
Nmap scan report for gateway.lab.local ({net}.1)
Host is up (0.00042s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for {net}.42
Host is up (0.00089s latency).
MAC Address: 08:00:27:A5:3B:11 (Oracle VirtualBox virtual NIC)
Nmap scan report for web01.lab.local ({net}.50)
Host is up (0.00067s latency).
MAC Address: 08:00:27:C1:9E:42 (Oracle VirtualBox virtual NIC)
Nmap scan report for dc01.lab.local ({net}.100)
Host is up (0.00121s latency).
MAC Address: 08:00:27:7F:2D:88 (Oracle VirtualBox virtual NIC)
Read data files from: /usr/bin/../share/nmap
Nmap done: {count} IP addresses (4 hosts up) scanned in 2.54 seconds
"""

NMAP_PORTS = """Starting Nmap 7.94 ( https://nmap.org ) at {date} UTC
Initiating ARP Ping Scan at 14:07
Scanning {ip} [1 port]
Completed ARP Ping Scan at 14:07, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 14:07
Scanning {ip} [1000 ports]
Discovered open port 22/tcp on {ip}
Discovered open port 80/tcp on {ip}
Discovered open port 445/tcp on {ip}
Discovered open port 139/tcp on {ip}
Discovered open port 21/tcp on {ip}
Discovered open port 3306/tcp on {ip}
Discovered open port 23/tcp on {ip}
Discovered open port 8180/tcp on {ip}
SYN Stealth Scan Timing: About 62.30% done; ETC: 14:08 (0:00:14 remaining)
Discovered open port 5900/tcp on {ip}
Discovered open port 111/tcp on {ip}
Completed SYN Stealth Scan at 14:08, 21.44s elapsed (1000 total ports)
Nmap scan report for {ip}
Host is up (0.00075s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
5900/tcp open  vnc
8180/tcp open  unknown
MAC Address: 08:00:27:A5:3B:11 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.83 seconds
           Raw packets sent: 1006 (44.264KB) | Rcvd: 1004 (40.172KB)
"""

NMAP_SERVICES = """Starting Nmap 7.94 ( https://nmap.org ) at {date} UTC
Initiating SYN Stealth Scan at 14:12
Scanning {ip} [1000 ports]
Completed SYN Stealth Scan at 14:12, 19.90s elapsed (1000 total ports)
Initiating Service scan at 14:12
Scanning 10 services on {ip}
Completed Service scan at 14:13, 42.11s elapsed (10 services on 1 host)
Nmap scan report for {ip}
Host is up (0.00068s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5900/tcp open  vnc         VNC (protocol 3.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 08:00:27:A5:3B:11 (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  metasploitable.localdomain, localhost; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.44 seconds
"""

NMAP_OS = """Starting Nmap 7.94 ( https://nmap.org ) at {date} UTC
Initiating SYN Stealth Scan at 14:20
Completed SYN Stealth Scan at 14:20, 12.04s elapsed (1000 total ports)
Initiating OS detection (try #1) against {ip}
Nmap scan report for {ip}
Host is up (0.00071s latency).
Not shown: 990 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
445/tcp  open  microsoft-ds
MAC Address: 08:00:27:A5:3B:11 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.88 seconds
"""

NMAP_VULN = """Starting Nmap 7.94 ( https://nmap.org ) at {date} UTC
NSE: Loaded 149 scripts for scanning.
NSE: Script Pre-scanning.
Initiating SYN Stealth Scan at 14:31
Completed SYN Stealth Scan at 14:31, 18.22s elapsed (1000 total ports)
Initiating Service scan at 14:31
NSE: Starting runlevel 1 (of 3) scan.
Nmap scan report for {ip}
Host is up (0.00070s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_sslv2-drown:
| ftp-vsftpd-backdoor:
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2011-2523  BID:48539
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|_      http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open
|       and hold them open as long as possible.
|     Disclosure date: 2009-09-17
|     References:
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
| http-enum:
|   /phpinfo.php: Possible information file
|   /phpMyAdmin/: phpMyAdmin
|_  /dav/: Potentially interesting folder
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
| smb-vuln-ms17-010:
|   NOT VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: NOT VULNERABLE
|_
| smb-vuln-cve2009-3103:
|   VULNERABLE:
|   SMBv2 exploit
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|_
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
|_mysql-empty-password: Host 'x' is not allowed to connect to this MySQL server

NSE: Script Post-scanning.
Nmap done: 1 IP address (1 host up) scanned in 94.31 seconds
"""

NMAP_UDP = """Starting Nmap 7.94 ( https://nmap.org ) at {date} UTC
Initiating UDP Scan at 14:40
Scanning {ip} [50 ports]
Discovered open port 53/udp on {ip}
Discovered open port 161/udp on {ip}
UDP Scan Timing: About 48.00% done; ETC: 14:41 (0:00:31 remaining)
Discovered open port 137/udp on {ip}
Completed UDP Scan at 14:41, 58.91s elapsed (50 total ports)
Nmap scan report for {ip}
Host is up (0.00082s latency).
Not shown: 44 closed udp ports (port-unreach)
PORT    STATE         SERVICE
53/udp  open          domain
69/udp  open|filtered tftp
111/udp open|filtered rpcbind
137/udp open          netbios-ns
161/udp open          snmp
500/udp open|filtered isakmp
MAC Address: 08:00:27:A5:3B:11 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 59.32 seconds
"""

MASSCAN = """Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at {date} GMT
Initiating SYN Stealth Scan
Scanning {count} hosts [1000 ports/host]
rate:  0.98-kpps, 12.44% done,   0:00:31 remaining, found=3
Discovered open port 22/tcp on {net}.1
Discovered open port 80/tcp on {net}.1
Discovered open port 21/tcp on {net}.42
Discovered open port 22/tcp on {net}.42
Discovered open port 80/tcp on {net}.42
Discovered open port 445/tcp on {net}.42
rate:  1.00-kpps, 68.12% done,   0:00:11 remaining, found=9
Discovered open port 3306/tcp on {net}.42
Discovered open port 80/tcp on {net}.50
Discovered open port 443/tcp on {net}.50
Discovered open port 8080/tcp on {net}.50
Discovered open port 445/tcp on {net}.100
Discovered open port 389/tcp on {net}.100
Discovered open port 3389/tcp on {net}.100
rate:  0.00-kpps, 100.00% done, waiting 3 seconds
"""

WHATWEB = json.dumps([{
    "target": "{url}",
    "http_status": 200,
    "request_config": {"headers": {"User-Agent": "WhatWeb/0.5.5"}},
    "plugins": {
        "Apache": {"version": ["2.2.8"], "string": ["Apache/2.2.8 (Ubuntu) DAV/2"]},
        "HTTPServer": {"os": ["Ubuntu Linux"], "string": ["Apache/2.2.8 (Ubuntu) DAV/2"]},
        "PHP": {"version": ["5.2.4-2ubuntu5.10"]},
        "X-Powered-By": {"string": ["PHP/5.2.4-2ubuntu5.10"]},
        "Title": {"string": ["Metasploitable2 - Linux"]},
        "Country": {"string": ["RESERVED"], "module": ["ZZ"]},
        "IP": {"string": ["{ip}"]},
        "Cookies": {"string": ["PHPSESSID"]},
        "HttpOnly": {"string": ["PHPSESSID"]},
        "Script": {"string": ["text/javascript"]},
        "Index-Of": {},
    },
}], indent=1)

NUCLEI_VULNS = [
    {"template-id": "apache-detect", "host": "{url}", "matched-at": "{url}",
     "info": {"name": "Apache Detection", "severity": "info",
              "description": "Apache web server was detected.", "tags": ["tech", "apache"],
              "classification": {}},
     "extracted-results": ["Apache/2.2.8"]},
    {"template-id": "php-detect", "host": "{url}", "matched-at": "{url}",
     "info": {"name": "PHP Detection", "severity": "info",
              "description": "PHP was detected via the X-Powered-By header.",
              "tags": ["tech", "php"], "classification": {}},
     "extracted-results": ["PHP/5.2.4-2ubuntu5.10"]},
    {"template-id": "phpinfo-files", "host": "{url}", "matched-at": "{url}/phpinfo.php",
     "info": {"name": "phpinfo() Information Disclosure", "severity": "low",
              "description": ("A phpinfo() page is publicly reachable. It exposes the PHP "
                              "configuration, loaded modules, environment variables and absolute "
                              "filesystem paths, all of which help an attacker plan further work."),
              "tags": ["exposure", "config", "php"],
              "reference": ["https://www.php.net/manual/en/function.phpinfo.php"],
              "classification": {}}},
    {"template-id": "apache-dav-enabled", "host": "{url}", "matched-at": "{url}/dav/",
     "info": {"name": "Apache WebDAV Enabled", "severity": "medium",
              "description": ("WebDAV is enabled on this server. Depending on its permissions "
                              "this can allow files to be listed, uploaded or replaced."),
              "tags": ["misconfig", "apache", "webdav"], "classification": {}}},
    {"template-id": "CVE-2011-2523", "host": "{url}", "matched-at": "{ip}:21",
     "info": {"name": "vsFTPd 2.3.4 - Backdoor Command Execution", "severity": "critical",
              "description": ("The vsftpd 2.3.4 source distributed from the official site in "
                              "mid-2011 was modified to include a backdoor which opens a shell "
                              "on port 6200 when a username containing a smiley face is used."),
              "tags": ["cve", "cve2011", "vsftpd", "backdoor", "rce"],
              "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
              "classification": {"cve-id": ["CVE-2011-2523"], "cvss-score": 9.8}}},
    {"template-id": "phpmyadmin-panel", "host": "{url}", "matched-at": "{url}/phpMyAdmin/",
     "info": {"name": "phpMyAdmin Panel Exposed", "severity": "medium",
              "description": ("A phpMyAdmin login panel is publicly reachable. Administrative "
                              "database interfaces should not be exposed to untrusted networks."),
              "tags": ["panel", "phpmyadmin", "exposure"], "classification": {}}},
]

NUCLEI_TECH = [NUCLEI_VULNS[0], NUCLEI_VULNS[1]]

NIKTO = """- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          {ip}
+ Target Hostname:    {ip}
+ Target Port:        {port}
+ Start Time:         {date}
---------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) DAV/2
+ /: Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.10.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /phpinfo.php: Output from the phpinfo() function was found.
+ /phpMyAdmin/: phpMyAdmin directory found.
+ /phpMyAdmin/changelog.php: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ /dav/: WebDAV enabled (SEARCH PROPFIND COPY PROPPATCH LOCK UNLOCK listed as allowed).
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /test/: Directory indexing found.
+ /doc/: Directory indexing found.
+ /doc/: The /doc/ directory is browsable. This may be /usr/doc.
+ 8908 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           {date} (38 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""

GOBUSTER = """/.hta                 (Status: 403) [Size: 288]
/.htaccess            (Status: 403) [Size: 293]
/.htpasswd            (Status: 403) [Size: 293]
/cgi-bin/             (Status: 403) [Size: 291]
/dav                  (Status: 301) [Size: 315] [--> {url}/dav/]
/doc                  (Status: 301) [Size: 315] [--> {url}/doc/]
/icons                (Status: 301) [Size: 317] [--> {url}/icons/]
/index                (Status: 200) [Size: 891]
/index.php            (Status: 200) [Size: 891]
/phpinfo.php          (Status: 200) [Size: 48097]
/phpMyAdmin           (Status: 301) [Size: 322] [--> {url}/phpMyAdmin/]
/server-status        (Status: 403) [Size: 297]
/test                 (Status: 301) [Size: 316] [--> {url}/test/]
/twiki                (Status: 301) [Size: 317] [--> {url}/twiki/]
"""


def _url_for(target: str) -> str:
    if target.lower().startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"http://{target}"


def get(tool_id: str, goal_id: str, target: str, opts: dict, date: str) -> tuple[str, str, int]:
    """Return (stdout, stderr, exit_code) for a demo run."""
    ip = _ip_for(target)
    net = ".".join(ip.split(".")[:3]) if ip.count(".") == 3 else "10.10.10"
    url = _url_for(target)
    try:
        count = validate.host_count(validate.scan_host_part(target))
    except validate.ValidationError:
        count = 1
    ctx = {"ip": ip, "net": net, "url": url, "date": date, "count": count,
           "port": opts.get("port", 80)}

    if tool_id == "nmap":
        tpl = {"discover": NMAP_DISCOVER, "quick_ports": NMAP_PORTS,
               "services": NMAP_SERVICES, "os_detect": NMAP_OS,
               "vuln_nse": NMAP_VULN, "udp": NMAP_UDP}.get(goal_id, NMAP_PORTS)
        return tpl.format(**ctx), "", 0
    if tool_id == "masscan":
        return MASSCAN.format(**ctx), "", 0
    if tool_id == "whatweb":
        return WHATWEB.replace("{url}", url).replace("{ip}", ip), "", 0
    if tool_id == "nuclei":
        recs = NUCLEI_TECH if goal_id == "tech_detect" else NUCLEI_VULNS
        sev_filter = opts.get("severity", "low")
        chain = {"info": 5, "low": 4, "medium": 3, "high": 2}.get(sev_filter, 4)
        rank = {"info": 5, "low": 4, "medium": 3, "high": 2, "critical": 1}
        lines = []
        for r in recs:
            if goal_id != "tech_detect" and rank[r["info"]["severity"]] > chain:
                continue
            lines.append(json.dumps(r).replace("{url}", url).replace("{ip}", ip))
        return "\n".join(lines) + "\n", "", 0
    if tool_id == "nikto":
        return NIKTO.format(**ctx), "", 0
    if tool_id == "gobuster":
        return GOBUSTER.replace("{url}", url), "", 0
    return f"(No demo fixture for {tool_id}/{goal_id}.)\n", "", 0
