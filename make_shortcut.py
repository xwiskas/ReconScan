"""Put a ReconScan icon on your desktop.

    python make_shortcut.py              add it
    python make_shortcut.py --menu       also add it to the Start Menu / app list
    python make_shortcut.py --remove     take it away again

Double-clicking the shortcut starts ReconScan and opens your browser. A small
console window stays open while it runs - that window IS the server, so closing
it stops ReconScan.

On Linux this writes a .desktop entry instead. Note that it launches ReconScan
as your normal user, which is enough for Demo mode and for connect scans, but
not for SYN scans, OS detection, UDP scans or masscan - those need raw packets,
so run `sudo ./run.sh` from a terminal when you need them.

If ReconScan lives on a USB stick, prefer double-clicking run.bat on the stick
itself: a desktop shortcut stores an absolute path, and Windows hands removable
drives a different letter depending on what else is plugged in.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ICON_ICO = ROOT / "app" / "reconscan" / "web" / "reconscan.ico"
ICON_PNG = ROOT / "app" / "reconscan" / "web" / "reconscan.png"
NAME = "ReconScan"
DESCRIPTION = "Guided scanning for authorized penetration testing"


def desktop_dir() -> Path:
    """Where this user's desktop actually is, including OneDrive redirection."""
    if os.name == "nt":
        try:
            import winreg
            key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
                raw, _ = winreg.QueryValueEx(k, "Desktop")
            expanded = Path(os.path.expandvars(raw))
            if expanded.is_dir():
                return expanded
        except Exception:  # noqa: BLE001 - fall through to the obvious place
            pass
    fallback = Path.home() / "Desktop"
    return fallback if fallback.is_dir() else Path.home()


def ensure_icon() -> None:
    if ICON_ICO.exists() and ICON_PNG.exists():
        return
    sys.path.insert(0, str(ROOT / "app"))
    from reconscan.icon import write_all
    write_all(ICON_ICO.parent)
    print(f"Drew the icon into {ICON_ICO.parent}")


# --- Windows ----------------------------------------------------------------
def _powershell(script: str) -> int:
    exe = "powershell.exe"
    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout.strip())
        print(result.stderr.strip(), file=sys.stderr)
    return result.returncode


def windows_shortcut(path: Path, target: Path) -> bool:
    # WScript.Shell is the supported way to write a .lnk and needs nothing installed.
    script = f"""
$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{path}')
$s.TargetPath       = '{target}'
$s.WorkingDirectory = '{target.parent}'
$s.IconLocation     = '{ICON_ICO}'
$s.Description      = '{DESCRIPTION}'
$s.Save()
"""
    return _powershell(script) == 0


def start_menu_dir() -> Path:
    return (Path(os.environ.get("APPDATA", Path.home()))
            / "Microsoft" / "Windows" / "Start Menu" / "Programs")


# --- Linux ------------------------------------------------------------------
DESKTOP_ENTRY = """[Desktop Entry]
Type=Application
Name={name}
Comment={comment}
Exec={exec_path}
Path={workdir}
Icon={icon}
Terminal=true
Categories=Network;Security;
StartupNotify=true
"""


def linux_entry(path: Path, target: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DESKTOP_ENTRY.format(
        name=NAME, comment=DESCRIPTION, exec_path=target,
        workdir=target.parent, icon=ICON_PNG))
    path.chmod(0o755)
    # GNOME needs desktop files it did not install to be marked as trusted.
    if subprocess.run(["which", "gio"], capture_output=True).returncode == 0:
        subprocess.run(["gio", "set", str(path), "metadata::trusted", "true"],
                       capture_output=True)
    return True


# --- main -------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Add a ReconScan shortcut to your desktop.")
    ap.add_argument("--menu", action="store_true",
                    help="Also add it to the Start Menu (Windows) or app list (Linux).")
    ap.add_argument("--remove", action="store_true", help="Remove the shortcuts.")
    ap.add_argument("--target", default=None,
                    help="A different ReconScan folder to point at, e.g. E:/ReconScan.")
    args = ap.parse_args()

    windows = os.name == "nt"
    suffix = ".lnk" if windows else ".desktop"
    places = [desktop_dir() / f"{NAME}{suffix}"]
    if args.menu:
        places.append((start_menu_dir() if windows
                       else Path.home() / ".local" / "share" / "applications")
                      / f"{NAME}{suffix}")

    if args.remove:
        for p in places:
            if p.exists():
                p.unlink()
                print(f"Removed {p}")
            else:
                print(f"Nothing at {p}")
        return 0

    root = Path(args.target).resolve() if args.target else ROOT
    launcher = root / ("run.bat" if windows else "run.sh")
    if not launcher.exists():
        print(f"ERROR: {launcher} does not exist.")
        print("Point --target at a folder containing run.bat / run.sh.")
        return 1
    if not windows:
        launcher.chmod(launcher.stat().st_mode | 0o111)

    ensure_icon()

    made = 0
    for p in places:
        okay = windows_shortcut(p, launcher) if windows else linux_entry(p, launcher)
        if okay:
            print(f"Created {p}")
            made += 1
        else:
            print(f"FAILED to create {p}")

    if not made:
        return 1

    print(f"\nDouble-click '{NAME}' to start it. Your browser opens automatically.")
    print("A console window stays open while it runs - that window is the server,")
    print("so closing it stops ReconScan.\n")
    if args.target:
        print("Because this points at a specific folder, note that a USB stick can get a")
        print("different drive letter on a different machine, which would break the link.")
        print("On the stick itself, double-click run.bat instead.\n")
    if not windows:
        print("This launches as your normal user. SYN scans, OS detection, UDP scans and")
        print("masscan need raw packets, so for those run:  sudo ./run.sh\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
