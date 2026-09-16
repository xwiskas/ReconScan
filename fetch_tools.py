"""Download the self-contained scanning tools into the app, so they travel with it.

    python fetch_tools.py                       for this machine
    python fetch_tools.py --platform linux-x86_64   for the Kali stick, from Windows
    python fetch_tools.py --dest E:/ReconScan   straight onto the USB stick
    python fetch_tools.py --list                show what can and cannot be bundled

Only two of ReconScan's six tools can honestly be carried: nuclei and gobuster
are written in Go and link statically, so each is one file that runs anywhere on
its platform with nothing installed.

The other four cannot be, and it is worth knowing why rather than fighting it:

  nmap, masscan   need a packet-capture layer. On Linux that is libpcap (Kali has
                  it); on Windows it is Npcap, a kernel driver that must be
                  *installed* - a driver cannot run from a folder.
  nikto           is a Perl program, and needs a Perl interpreter.
  whatweb         is a Ruby program, and needs a Ruby interpreter.

On Kali all four are one apt command away, which is the intended setup:

    sudo apt install -y nmap masscan nikto whatweb wordlists dirb

Downloads come from each project's official GitHub releases over HTTPS. The
SHA-256 of every file is printed so you can check it against the checksums the
projects publish alongside their releases.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import sysconfig
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Tools that are a single statically linked binary. Keys are ReconScan tool ids.
PORTABLE = {
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        "asset": {                       # platform key -> substring of the asset name
            "win-amd64": "windows_amd64.zip",
            "win-arm64": "windows_arm64.zip",
            "linux-x86_64": "linux_amd64.zip",
            "linux-aarch64": "linux_arm64.zip",
            "macosx-x86_64": "macOS_amd64.zip",
            "macosx-arm64": "macOS_arm64.zip",
        },
        "binary": "nuclei",
        "note": "Run 'nuclei -update-templates' once after this; the binary ships no templates.",
    },
    "gobuster": {
        "repo": "OJ/gobuster",
        "asset": {
            "win-amd64": "Windows_x86_64.zip",
            "win-arm64": "Windows_arm64.zip",
            "linux-x86_64": "Linux_x86_64.tar.gz",
            "linux-aarch64": "Linux_arm64.tar.gz",
            "macosx-x86_64": "Darwin_x86_64.tar.gz",
            "macosx-arm64": "Darwin_arm64.tar.gz",
        },
        "binary": "gobuster",
        "note": "",
    },
}

CANNOT_BUNDLE = {
    "nmap": "needs libpcap (Linux) or the Npcap kernel driver (Windows), plus its data files",
    "masscan": "needs libpcap (Linux) or the Npcap kernel driver (Windows)",
    "nikto": "is a Perl program and needs a Perl interpreter",
    "whatweb": "is a Ruby program and needs a Ruby interpreter",
}

UA = {"User-Agent": "ReconScan-fetch-tools"}


def normalise_platform(key: str) -> str:
    """Accept friendly names as well as the exact sysconfig key."""
    alias = {
        "windows": "win-amd64", "win": "win-amd64", "win64": "win-amd64",
        "linux": "linux-x86_64", "kali": "linux-x86_64", "linux64": "linux-x86_64",
        "mac": "macosx-x86_64", "macos": "macosx-x86_64",
    }
    k = key.lower()
    if k in alias:
        return alias[k]
    if k.startswith("macosx-"):          # sysconfig adds the OS version: macosx-14.0-arm64
        return "macosx-arm64" if k.endswith("arm64") else "macosx-x86_64"
    return key


def latest_release(repo: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def pick_asset(release: dict, needle: str) -> dict | None:
    for a in release.get("assets", []):
        if needle.lower() in a["name"].lower():
            return a
    return None


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def extract_binary(blob: bytes, asset_name: str, binary: str, dest: Path,
                   windows: bool) -> Path:
    want = f"{binary}.exe" if windows else binary
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / want

    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            member = next((n for n in z.namelist()
                           if Path(n).name.lower() in (want.lower(), binary.lower())), None)
            if member is None:
                raise RuntimeError(f"{asset_name} does not contain {want}")
            with z.open(member) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
    elif asset_name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            member = next((m for m in t.getmembers()
                           if Path(m.name).name.lower() in (want.lower(), binary.lower())), None)
            if member is None:
                raise RuntimeError(f"{asset_name} does not contain {want}")
            src = t.extractfile(member)
            if src is None:
                raise RuntimeError(f"could not read {member.name} from {asset_name}")
            with open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
    else:
        raise RuntimeError(f"unsupported archive type: {asset_name}")

    if not windows:
        out.chmod(out.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return out


def show_list() -> int:
    here = normalise_platform(sysconfig.get_platform())
    print(f"\nThis machine looks like: {here}\n")
    print("Can be bundled (single static binary, runs from a folder):")
    for name, spec in PORTABLE.items():
        plats = ", ".join(sorted(spec["asset"]))
        print(f"  {name:10s} {spec['repo']}")
        print(f"             platforms: {plats}")
    print("\nCannot be bundled - install these on the machine that does the scanning:")
    for name, why in CANNOT_BUNDLE.items():
        print(f"  {name:10s} {why}")
    print("\n  On Kali:  sudo apt install -y nmap masscan nikto whatweb wordlists dirb\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Download portable scanning tools into ReconScan.")
    ap.add_argument("--platform", default=None,
                    help="Target platform, e.g. linux-x86_64 or win-amd64. "
                         "Defaults to this machine. Use 'kali' for linux-x86_64.")
    ap.add_argument("--dest", default=None,
                    help="A ReconScan folder to install into, e.g. E:/ReconScan. "
                         "Defaults to this checkout.")
    ap.add_argument("--only", default=None,
                    help="Just one tool: nuclei or gobuster.")
    ap.add_argument("--list", action="store_true",
                    help="Show what can and cannot be bundled, then exit.")
    args = ap.parse_args()

    if args.list:
        return show_list()

    plat = normalise_platform(args.platform or sysconfig.get_platform())
    root = Path(args.dest).resolve() if args.dest else ROOT
    app_dir = root / "app" if (root / "app").is_dir() else root
    dest = app_dir / "tools" / plat
    windows = plat.startswith("win")

    wanted = {args.only: PORTABLE[args.only]} if args.only else PORTABLE
    if args.only and args.only not in PORTABLE:
        print(f"'{args.only}' cannot be bundled. Run --list to see why.")
        return 1

    print(f"Target platform : {plat}")
    print(f"Installing into : {dest}\n")

    failures = 0
    for name, spec in wanted.items():
        needle = spec["asset"].get(plat)
        if not needle:
            print(f"  {name}: no build published for {plat} - skipping")
            failures += 1
            continue
        try:
            print(f"  {name}: looking up the latest release of {spec['repo']}")
            rel = latest_release(spec["repo"])
            asset = pick_asset(rel, needle)
            if asset is None:
                names = ", ".join(a["name"] for a in rel.get("assets", [])[:6])
                print(f"    could not find an asset matching '{needle}'. Saw: {names}")
                failures += 1
                continue
            print(f"    downloading {asset['name']} ({asset['size'] / 1_000_000:.1f} MB)")
            blob = download(asset["browser_download_url"])
            digest = hashlib.sha256(blob).hexdigest()
            out = extract_binary(blob, asset["name"], spec["binary"], dest, windows)
            print(f"    -> {out}")
            print(f"    version {rel.get('tag_name', '?')}  sha256 {digest}")
            if spec["note"]:
                print(f"    note: {spec['note']}")
        except Exception as exc:  # noqa: BLE001 - report and carry on to the next tool
            print(f"    FAILED: {exc}")
            failures += 1
        print()

    print("-" * 66)
    if dest.is_dir():
        have = sorted(p.name for p in dest.iterdir() if p.is_file())
        print(f"Bundled for {plat}: {', '.join(have) if have else '(nothing)'}")
    print("\nReconScan prefers these over anything installed on the host, so the")
    print("stick runs the versions you put on it.")
    print("\nStill needed on the machine that does the scanning:")
    for name, why in CANNOT_BUNDLE.items():
        print(f"  {name:10s} {why}")
    print("\n  On Kali:  sudo apt install -y nmap masscan nikto whatweb wordlists dirb")
    print("-" * 66)
    return 1 if failures == len(wanted) else 0


if __name__ == "__main__":
    raise SystemExit(main())
