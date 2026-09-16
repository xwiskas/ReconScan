"""Runtime configuration for ReconScan.

Everything here can be overridden with environment variables so the same code
runs on your Windows machine (Demo mode) and on Kali (real scans) unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path

# --- Where data lives -------------------------------------------------------
# The SQLite database and any exports live next to the package by default.
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("RECONSCAN_DATA_DIR", BASE_DIR.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "reconscan.sqlite3"

WEB_DIR = BASE_DIR / "web"

# --- bundled scanning tools -------------------------------------------------
# Binaries carried alongside the app (on a USB stick, say) live here, in a
# per-platform folder. ReconScan prefers these over anything on PATH, so a stick
# runs the versions you put on it rather than whatever the host happens to have.
#
#   app/tools/win-amd64/nuclei.exe
#   app/tools/linux-x86_64/nuclei
#
# Only self-contained binaries can live here. Tools needing a packet-capture
# driver (nmap, masscan) or an interpreter (nikto/Perl, whatweb/Ruby) must be
# installed on the host - see fetch_tools.py.
TOOLS_DIR = Path(os.environ.get("RECONSCAN_TOOLS_DIR", BASE_DIR.parent / "tools"))


def platform_key() -> str:
    """Folder name for this OS and architecture, e.g. win-amd64, linux-x86_64."""
    import sysconfig
    return sysconfig.get_platform()


def bundled_tools_dir() -> Path:
    return TOOLS_DIR / platform_key()

# --- Network binding --------------------------------------------------------
# Loopback (localhost) is passwordless for the simplest single-machine setup.
# Binding to any other address (e.g. 0.0.0.0 on Kali) is treated as "LAN mode"
# and REQUIRES login (see reconscan/auth.py and §A7 of the PRD).
HOST = os.environ.get("RECONSCAN_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECONSCAN_PORT", "8000"))

_LOOPBACK = {"127.0.0.1", "localhost", "::1", ""}


def is_loopback(host: str) -> bool:
    return host in _LOOPBACK


def requires_auth() -> bool:
    """LAN binds require authentication; loopback does not."""
    return not is_loopback(HOST)


# --- Demo mode --------------------------------------------------------------
# When True, scans return realistic canned output instead of running real tools.
# Defaults to True on Windows (tools usually absent) and False on Linux/Kali,
# but the UI can flip it per-scan regardless.
DEMO_DEFAULT = os.environ.get(
    "RECONSCAN_DEMO", "1" if os.name == "nt" else "0"
) not in ("0", "false", "False", "")

# Session lifetime for LAN logins.
SESSION_TTL_HOURS = int(os.environ.get("RECONSCAN_SESSION_TTL_HOURS", "12"))

APP_NAME = "ReconScan"
APP_VERSION = "1.0.0"
