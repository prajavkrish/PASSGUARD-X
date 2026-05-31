#!/usr/bin/env bash
# PASSGUARD-X installer
# Usage: ./install.sh [github_repo]
# github_repo can be a full git URL or user/repo. If omitted, the script will prompt.
set -euo pipefail

REPO_URL=""
if [ $# -ge 1 ]; then
  REPO_URL="$1"
fi

read -r -p "GitHub repo URL or user/repo (default: paste or press Enter to cancel): " INPUT
if [ -n "$INPUT" ]; then
  REPO_URL="$INPUT"
fi

if [ -z "$REPO_URL" ]; then
  echo "No repository provided. Canceling."
  exit 1
fi

# Normalize user/repo to full URL
if [[ "$REPO_URL" != http*://* && "$REPO_URL" != git@* ]]; then
  if [[ "$REPO_URL" == */* ]]; then
    REPO_URL="https://github.com/${REPO_URL}.git"
  else
    echo "Repository string not understood. Provide full URL or user/repo." >&2
    exit 1
  fi
fi

TARGET_DIR="$HOME/PASSGUARD-X"
if [ -d "$TARGET_DIR" ]; then
  echo "Target $TARGET_DIR already exists." 
  read -r -p "Remove and re-clone? [y/N] " yn
  case "$yn" in
    [Yy]*) rm -rf "$TARGET_DIR" ;;
    *) echo "Aborting."; exit 1 ;;
  esac
fi

echo "Cloning $REPO_URL -> $TARGET_DIR"
git clone "$REPO_URL" "$TARGET_DIR"

# Create launcher script in user's local bin
mkdir -p "$HOME/.local/bin"
LAUNCHER_PATH="$HOME/.local/bin/passguard-x"
cat > "$LAUNCHER_PATH" <<'EOF'
#!/usr/bin/env bash
# Launcher for PASSGUARD-X
SCRIPT_DIR="$HOME/PASSGUARD-X"
cd "$SCRIPT_DIR" || exit 1
python3 cracker.py --gui
EOF
chmod +x "$LAUNCHER_PATH"

# Create desktop entry
mkdir -p "$HOME/.local/share/applications"
DESKTOP_PATH="$HOME/.local/share/applications/passguard-x.desktop"
cat > "$DESKTOP_PATH" <<EOF
[Desktop Entry]
Type=Application
Name=PASSGUARD-X
Comment=Password recovery GUI (PASSGUARD-X)
Exec=$HOME/.local/bin/passguard-x
Icon=security
Terminal=false
Categories=Utility;Security;
EOF

# Attempt to detect and advise on Tkinter availability
echo "\nChecking for Tkinter availability in the current Python..."
python3 -c 'import importlib,sys
try:
  importlib.import_module("tkinter")
  print("Tkinter OK")
except Exception as e:
  print("TK_MISSING", e)
' || true

echo "\nInstallation complete. You can launch PASSGUARD-X by running:"
echo "  passguard-x"
echo "or by using your desktop environment's application launcher ('PASSGUARD-X')."

echo "If Tkinter is missing the installer can't add system packages automatically."
echo "On Debian/Ubuntu: sudo apt install python3-tk"
echo "On Arch/Manjaro: sudo pacman -S tk"

echo "If you prefer the web UI fallback, run: python3 cracker.py (it will open the browser)."
