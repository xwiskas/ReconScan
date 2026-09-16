"""Entry point: python -m reconscan

  python -m reconscan                 localhost only, no password (default)
  python -m reconscan --lan           bind 0.0.0.0 over HTTPS, login required
  python -m reconscan --port 9000     pick a different port
  python -m reconscan --demo          force Demo mode as the default for new scans
  python -m reconscan --real          force real execution as the default
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import webbrowser
from pathlib import Path


def _lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "your-kali-ip"
    finally:
        s.close()


def _should_open_browser(args) -> bool:
    """Open a browser only where there is a person and a desktop to open it on."""
    if args.no_browser or os.environ.get("RECONSCAN_NO_BROWSER"):
        return False
    if Path("/.dockerenv").exists():
        return False        # in a container the browser is on the other side of the port
    if os.name != "nt" and not (os.environ.get("DISPLAY")
                                or os.environ.get("WAYLAND_DISPLAY")
                                or sys.platform == "darwin"):
        return False        # headless Kali over SSH: there is no desktop to open
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        # Running under sudo for raw-packet scans. Launching a browser as root
        # would run it with full privileges on every page you then visit.
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(prog="reconscan", description="ReconScan server")
    ap.add_argument("--lan", action="store_true",
                    help="Accept connections from other devices (HTTPS + login required).")
    ap.add_argument("--host", default=None, help="Bind address (overrides --lan).")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--demo", action="store_true", help="Default new scans to Demo mode.")
    ap.add_argument("--real", action="store_true", help="Default new scans to real execution.")
    ap.add_argument("--no-browser", action="store_true",
                    help="Do not open a browser window on startup.")
    args = ap.parse_args()

    if args.host:
        os.environ["RECONSCAN_HOST"] = args.host
    elif args.lan:
        os.environ["RECONSCAN_HOST"] = "0.0.0.0"
    if args.port:
        os.environ["RECONSCAN_PORT"] = str(args.port)
    if args.demo:
        os.environ["RECONSCAN_DEMO"] = "1"
    if args.real:
        os.environ["RECONSCAN_DEMO"] = "0"

    from . import auth, certs, config, db  # imported after the env is set

    db.init_db()

    ssl_args: dict = {}
    if config.requires_auth():
        pair = certs.ensure_cert()
        if pair is None:
            print("ERROR: LAN mode needs HTTPS, but no certificate could be generated.\n"
                  "       Install one of:  pip install cryptography   (or)  apt install openssl\n"
                  "       Refusing to serve a login page over plain HTTP on the network.",
                  file=sys.stderr)
            return 2
        ssl_args = {"ssl_certfile": pair[0], "ssl_keyfile": pair[1]}
        scheme, shown = "https", _lan_ip()
    else:
        scheme, shown = "http", "127.0.0.1"

    url = f"{scheme}://{shown}:{config.PORT}"
    print(f"\n  {config.APP_NAME} {config.APP_VERSION}")
    print(f"  {'-' * 52}")
    print(f"  Open:        {url}")
    print(f"  Data:        {config.DATA_DIR}")
    print(f"  Scan mode:   {'DEMO by default (no packets sent)' if config.DEMO_DEFAULT else 'REAL execution by default'}")
    if config.requires_auth():
        print(f"  Access:      LAN - encrypted, login required")
        print(f"  Certificate: self-signed. Your browser will warn once; that is expected.")
        fp = certs.fingerprint()
        if fp:
            print(f"               SHA-256 {fp[:47]}...")
        if not auth.user_exists():
            print(f"  Account:     none yet - the first screen will ask you to create one.")
    else:
        print(f"  Access:      localhost only - no password needed.")
        print(f"               Run with --lan to reach it from another device.")
    print(f"  {'-' * 52}")
    print("  Authorized use only. Scan only systems you have written permission to test.\n")
    if _should_open_browser(args):
        print("  Opening your browser. Close this window to stop ReconScan.\n")
        # uvicorn.run() blocks, so the browser has to be opened from a timer. A
        # second and a half is enough for the server to accept connections; if it
        # is not, the browser retries far more gracefully than a failed connection.
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    else:
        reason = ("running as root - open it in your normal browser rather than a root one"
                  if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0
                  else "no browser opened automatically here")
        print(f"  Open the address above yourself ({reason}).")
        print("  Press Ctrl+C to stop ReconScan.\n")
    sys.stdout.flush()

    import uvicorn
    uvicorn.run("reconscan.api:app", host=config.HOST, port=config.PORT,
                log_level="warning", **ssl_args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
