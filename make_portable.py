"""Build a self-contained ReconScan you can carry on a USB stick.

    python make_portable.py                     build deps for this machine, in place
    python make_portable.py --dest E:/ReconScan  copy the whole app to the stick and build
    python make_portable.py --dest E:/ReconScan --no-deps   copy only, build later

What ends up on the stick:

    ReconScan/
      run.bat          double-click on Windows
      run.sh           ./run.sh on Linux or macOS
      README.md
      app/
        reconscan/     the application
        launch.py      finds the dependencies, then starts it
        _vendor/
          win-amd64-py3.12/     <- built by running this on Windows
          linux-x86_64-py3.12/  <- built by running this on Kali
        data/          your projects, scans and reports (created on first run)

Run this once per platform you want the stick to work on. The folders sit side
by side and the launcher picks the right one, because a few dependencies ship
compiled code and cannot be shared between Windows and Linux.

Two things are NOT on the stick and cannot be: Python itself, and the scanning
tools (nmap, masscan, nuclei, nikto, whatweb, gobuster). Without the tools you
still get the full application in Demo mode; real scans need them installed on
the machine you plug into, which is what Kali is for.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app"

# Copied to the destination. Everything else (data/, __pycache__, the PRD) stays behind.
SHIP = ["run.bat", "run.sh", "README.md"]
SKIP_DIRS = {"__pycache__", "data", ".git", ".pytest_cache"}


def _ignore(_dir: str, names: list[str]) -> set[str]:
    return {n for n in names if n in SKIP_DIRS or n.endswith(".pyc")}


def copy_app(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    target_app = dest / "app"
    if target_app.exists():
        # Replace the code, but never touch the folders that are expensive or
        # impossible to rebuild: your scan data, the vendored Python packages,
        # and any scanning binaries already downloaded for other platforms.
        for child in target_app.iterdir():
            if child.name in ("data", "_vendor", "tools"):
                continue
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    print(f"Copying the application to {target_app}")
    shutil.copytree(APP, target_app, ignore=_ignore, dirs_exist_ok=True)
    for name in SHIP:
        src = ROOT / name
        if src.exists():
            shutil.copy2(src, dest / name)
            print(f"  {name}")
    sh = dest / "run.sh"
    if sh.exists():
        sh.chmod(0o755)


def build_deps(app_dir: Path) -> int:
    launch = app_dir / "launch.py"
    if not launch.exists():
        print(f"ERROR: {launch} is missing.")
        return 1
    return subprocess.run([sys.executable, str(launch), "--build-deps"]).returncode


def folder_size(p: Path) -> str:
    if not p.exists():
        return "not built"
    total = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    if total < 1_000_000:
        return f"{total / 1_000:.0f} KB"
    return f"{total / 1_000_000:.1f} MB"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build a portable ReconScan for a USB stick.")
    ap.add_argument("--dest", help="Where to build it, e.g. E:/ReconScan. "
                                   "Omit to build in place.")
    ap.add_argument("--no-deps", action="store_true",
                    help="Copy the files but do not download dependencies.")
    args = ap.parse_args()

    dest = Path(args.dest).resolve() if args.dest else ROOT
    app_dir = (dest / "app") if args.dest else APP

    if args.dest:
        copy_app(dest)

    if not args.no_deps:
        print()
        if build_deps(app_dir) != 0:
            return 1
    else:
        print("\nSkipped dependencies (--no-deps). Build them later with:")
        print(f'    python "{app_dir / "launch.py"}" --build-deps')

    vendor = app_dir / "_vendor"
    toolsdir = app_dir / "tools"
    print("\n" + "-" * 62)
    print(f"Portable ReconScan is ready at {dest}")
    print(f"  application : {folder_size(app_dir / 'reconscan')}")
    print(f"  dependencies: {folder_size(vendor)}")
    if vendor.is_dir():
        for d in sorted(p.name for p in vendor.iterdir() if p.is_dir()):
            print(f"      {d}")
    print(f"  scan tools  : {folder_size(toolsdir)}")
    if toolsdir.is_dir():
        for d in sorted(p for p in toolsdir.iterdir() if p.is_dir()):
            names = ", ".join(sorted(f.name for f in d.iterdir() if f.is_file()))
            print(f"      {d.name}: {names or '(empty)'}")
    else:
        print("      none yet - run:  python fetch_tools.py --dest "
              f"{dest}")
    print("\nTo start it:")
    print("  Windows        double-click run.bat")
    print("  Linux / macOS  ./run.sh")
    print("\nFor another platform, copy the stick there and run this script again -")
    print("the two dependency folders sit side by side and the launcher picks one.")
    print("\nReminder: Python must exist on the machine you plug into, and real")
    print("scans need nmap and friends installed there. Demo mode always works.")
    print("-" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
