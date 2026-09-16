#!/usr/bin/env bash
# ReconScan launcher for Linux and macOS.
#
#   ./run.sh              localhost only, no password
#   ./run.sh --lan        reachable from your network (HTTPS + login)
#   sudo ./run.sh         needed for SYN scans, OS detection and UDP scans
#
# If this will not run, it probably needs the executable bit:  chmod +x run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPDIR="$HERE/app"

# sudo resets PATH and HOME, so resolve Python before deciding anything else.
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PY="$(command -v "$candidate")"
    break
  fi
done

if [ -z "$PY" ]; then
  cat <<'EOF'

  ReconScan needs Python 3.11 or newer, and none was found.

  On Kali or Debian:   sudo apt install python3
  On macOS:            brew install python

EOF
  exit 1
fi

exec "$PY" "$APPDIR/launch.py" "$@"
