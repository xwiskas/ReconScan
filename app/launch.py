"""Portable launcher - finds ReconScan's dependencies wherever they are.

Run this instead of `python -m reconscan` when the app lives on a USB stick or
any machine where you have not pip-installed anything. It looks for a vendored
dependency folder built by make_portable.py, falls back to normally installed
packages, and if neither is there it tells you exactly what to run.

    python app/launch.py            # same arguments as `python -m reconscan`
    python app/launch.py --lan
    python app/launch.py --build-deps   # fetch dependencies into _vendor (needs internet)

Vendored packages are platform- and version-specific, because a few of them ship
compiled code (pydantic-core, cryptography, argon2). So each folder is keyed by
platform and Python version, and several can sit side by side on one stick:

    app/_vendor/win-amd64-py3.12/
    app/_vendor/linux-x86_64-py3.12/
"""
from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
from pathlib import Path

HERE = Path(__file__).resolve().parent          # the app/ directory
VENDOR_ROOT = HERE / "_vendor"
REQUIREMENTS = HERE / "requirements.txt"
NEEDED = ("fastapi", "uvicorn")                 # the two without which nothing runs

MIN_PYTHON = (3, 11)


def vendor_key() -> str:
    """A folder name unique to this platform and Python version."""
    return f"{sysconfig.get_platform()}-py{sys.version_info.major}.{sys.version_info.minor}"


def vendor_dir() -> Path:
    return VENDOR_ROOT / vendor_key()


def have_deps() -> bool:
    from importlib.util import find_spec
    try:
        return all(find_spec(m) is not None for m in NEEDED)
    except (ImportError, ValueError):
        return False


def build_deps(dest: Path | None = None) -> int:
    """pip install the requirements into a vendor folder for THIS platform."""
    target = dest or vendor_dir()
    if not REQUIREMENTS.exists():
        print(f"ERROR: {REQUIREMENTS} is missing - cannot work out what to install.")
        return 1
    print(f"Fetching ReconScan's dependencies for {vendor_key()}")
    print(f"  into {target}")
    print("  (this needs an internet connection, and takes a minute)\n")
    target.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade",
           "--target", str(target), "-r", str(REQUIREMENTS)]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("\nERROR: pip could not install the dependencies. The message above says why.")
        return result.returncode
    size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    print(f"\nDone. {target.name} is {size / 1_000_000:.0f} MB.")
    print("ReconScan will now start on this machine without installing anything.")
    return 0


def explain_missing() -> int:
    here = Path(sys.argv[0]).resolve().parent
    launcher = "run.bat" if os.name == "nt" else "./run.sh"
    print(f"""
ReconScan cannot start: its Python dependencies are not available.

  Python in use : {sys.executable}
  Looking for   : {vendor_dir()}
  Also checked  : the packages installed for this Python

Pick one:

  1. Build a portable copy right here (needs internet once, then never again):

         python "{Path(__file__).resolve()}" --build-deps

     After that, {launcher} works on any machine with the same platform and
     Python {sys.version_info.major}.{sys.version_info.minor}, with nothing installed.

  2. Or install them normally for this Python:

         "{sys.executable}" -m pip install -r "{REQUIREMENTS}"

If you are running from a USB stick and it already has a _vendor folder, it was
probably built for a different platform or Python version. Folders present:
""".rstrip())
    if VENDOR_ROOT.is_dir():
        found = sorted(p.name for p in VENDOR_ROOT.iterdir() if p.is_dir())
        for name in found or ["(none)"]:
            mark = "  <- matches this machine" if name == vendor_key() else ""
            print(f"    {name}{mark}")
    else:
        print("    (no _vendor folder at all)")
    print()
    return 1


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        print(f"ReconScan needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer. "
              f"This is Python {sys.version.split()[0]} at {sys.executable}.")
        return 1

    args = sys.argv[1:]
    if "--build-deps" in args:
        return build_deps()

    # A vendored folder for this exact platform wins, so a USB copy is used even
    # on a machine that happens to have its own (possibly different) versions.
    vd = vendor_dir()
    if vd.is_dir():
        sys.path.insert(0, str(vd))
        os.environ["PYTHONPATH"] = os.pathsep.join(
            [str(vd), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep)

    if not have_deps():
        return explain_missing()

    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))

    from reconscan.__main__ import main as run
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
