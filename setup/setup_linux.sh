#!/usr/bin/env bash
# ============================================================
#  MagiSentry — Linux / WSL installer
# ============================================================
#  1. Verifies pip is available.
#  2. Installs MagiSentry in editable mode from the local source
#     tree (the package is not yet on PyPI).
#  3. Symlinks `magisentry` into ~/.local/bin and prepends that
#     directory to PATH via the user's shell rc.
#  4. Prints next-step hints (source the rc; optional VT_API_KEY).
# ============================================================
set -e

# --- 0. Language choice (BEFORE any pip install) -------------
# Wizard reads MAGISENTRY_LANG and skips its own language prompt
# when this is already set to en or sk.
echo ""
echo "Choose language / Zvoľte jazyk: [1] English  [2] Slovenčina"
read -r lang_choice
if [ "$lang_choice" = "2" ]; then
    export MAGISENTRY_LANG=sk
else
    export MAGISENTRY_LANG=en
fi
echo "Selected language: $MAGISENTRY_LANG"
echo ""

# --- 0b. Detect existing install -----------------------------
if command -v magisentry >/dev/null 2>&1; then
    echo ""
    if [ "$MAGISENTRY_LANG" = "sk" ]; then
        echo "MagiSentry je už nainštalovaný."
        echo "[1] Preinštalovať / Aktualizovať  [2] Odinštalovať  [3] Zrušiť"
    else
        echo "MagiSentry is already installed."
        echo "[1] Reinstall / Update  [2] Uninstall  [3] Cancel"
    fi
    read -r action
    case "$action" in
        2) magisentry uninstall; exit 0 ;;
        3) exit 0 ;;
        *) ;;  # 1 or anything else -> reinstall, fall through
    esac
    echo ""
fi

# --- detect shell rc -----------------------------------------
SHELL_RC=""
if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "$(command -v zsh)" ]; then
  SHELL_RC="$HOME/.zshrc"
else
  SHELL_RC="$HOME/.bashrc"
fi

# --- find this repo root -------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$PROJECT_ROOT/setup.py" ]; then
  echo "[ERROR] setup.py not found at $PROJECT_ROOT/setup.py"
  echo "        Run this script from inside a clone of the MagiSentry repo."
  exit 1
fi

# --- pick a python -------------------------------------------
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "[ERROR] python is not on PATH. Install Python 3.8+ and re-run."
  exit 1
fi

echo "Installing MagiSentry in editable mode from $PROJECT_ROOT ..."
"$PY" -m pip install --user --upgrade pip
"$PY" -m pip install --user -e "$PROJECT_ROOT"

# --- register magisentry on PATH -----------------------------
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
MAGI_BIN="$(command -v magisentry || true)"
if [ -n "$MAGI_BIN" ] && [ ! -e "$INSTALL_DIR/magisentry" ]; then
  ln -sf "$MAGI_BIN" "$INSTALL_DIR/magisentry" 2>/dev/null || true
fi

# Idempotent: only append if no MagiSentry entry already exists, so
# repeated runs of the installer don't grow $SHELL_RC indefinitely.
if ! grep -q "magisentry" "$SHELL_RC" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"  # magisentry' >> "$SHELL_RC"
fi

# --- build initial integrity manifest ------------------------
# `--yes` skips the interactive [y/N]; only the setup script may
# use this flag, never an AI agent at runtime.
echo ""
echo "Building initial integrity manifest..."
magisentry integrity update --yes || echo "[WARN] integrity manifest build returned non-zero status"

echo ""
echo "MagiSentry installed."
echo "  Run:        source $SHELL_RC"
echo "  Optional:   echo 'export VT_API_KEY=\"your_key_here\"' >> $SHELL_RC"
echo ""
echo "Next: launch the setup wizard"
echo "  magisentry config --wizard"
