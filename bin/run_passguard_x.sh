#!/bin/sh
# Small wrapper to run PASSGUARD-X from the checked-out folder
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
python3 cracker.py "$@"
