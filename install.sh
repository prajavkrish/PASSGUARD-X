#!/usr/bin/env bash
# PASSGUARD-X installer
# Usage: ./install.sh [github_repo]
# github_repo can be a full git URL or user/repo. If omitted, installs this folder.
set -euo pipefail

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL=""
if [ $# -ge 1 ]; then
  REPO_URL="$1"
fi

if [ -z "$REPO_URL" ] && [ -t 0 ]; then
  read -r -p "GitHub repo URL or user/repo (press Enter to install this folder): " INPUT
  if [ -n "$INPUT" ]; then
    REPO_URL="$INPUT"
  fi
fi

INSTALL_DIR="$CURRENT_DIR"

if [ -n "$REPO_URL" ]; then
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
  INSTALL_DIR="$TARGET_DIR"
else
  echo "Installing launcher for current folder: $INSTALL_DIR"
fi

# Create launcher script in user's local bin
mkdir -p "$HOME/.local/bin"
LAUNCHER_PATH="$HOME/.local/bin/passguard-x"
cat > "$LAUNCHER_PATH" <<EOF
#!/bin/sh
# Launcher for PASSGUARD-X
SCRIPT_DIR="$INSTALL_DIR"
cd "\$SCRIPT_DIR" || exit 1
python3 cracker.py "\$@"
EOF
chmod +x "$LAUNCHER_PATH"

# Install app icon for desktop launchers
ICON_SOURCE="$INSTALL_DIR/assets/passguard-x.svg"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
ICON_PATH="$ICON_DIR/passguard-x.svg"
if [ -f "$ICON_SOURCE" ]; then
  mkdir -p "$ICON_DIR"
  cp "$ICON_SOURCE" "$ICON_PATH"
fi

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
for SHELL_RC in "$HOME/.zshrc" "$HOME/.bashrc"; do
  if [ -f "$SHELL_RC" ] && ! grep -Fq '.local/bin' "$SHELL_RC"; then
    {
      printf "\n# Add user-local commands such as passguard-x\n"
      printf '%s\n' "$PATH_LINE"
    } >> "$SHELL_RC"
    echo "Added ~/.local/bin to $SHELL_RC"
  fi
done

# Create desktop entry
mkdir -p "$HOME/.local/share/applications"
DESKTOP_PATH="$HOME/.local/share/applications/passguard-x.desktop"
cat > "$DESKTOP_PATH" <<EOF
[Desktop Entry]
Type=Application
Name=PASSGUARD-X
Comment=Password recovery GUI (PASSGUARD-X)
Exec=$HOME/.local/bin/passguard-x app
Icon=passguard-x
Terminal=false
Categories=System;Security;
StartupNotify=true
EOF

# Attempt to detect and advise on Tkinter availability
printf "\nChecking for Tkinter availability in the current Python...\n"
python3 -c 'import importlib,sys
try:
  importlib.import_module("tkinter")
  print("Tkinter OK")
except Exception as e:
  print("TK_MISSING", e)
' || true

printf "\nInstallation complete. You can launch PASSGUARD-X by running:\n"
echo "  passguard-x"
echo "  passguard-x --help"
echo "or by using your desktop environment's application launcher ('PASSGUARD-X')."
echo ""
echo "If your current terminal says 'command not found', run:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "or restart the terminal."

echo "If Tkinter is missing the installer can't add system packages automatically."
echo "On Debian/Ubuntu: sudo apt install python3-tk"
echo "On Arch/Manjaro: sudo pacman -S tk"

echo "If Tkinter is unavailable, PASSGUARD-X automatically opens the red themed web app."
