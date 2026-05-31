#!/usr/bin/env bash
# Small wrapper to run PASSGUARD-X from the checked-out folder
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
python3 cracker.py "$@"
