#!/usr/bin/env bash
# ============================================================
#  MagiSentry — macOS installer (uv tool, v1.0.3+)
# ============================================================
#  Action menu mirrors setup_windows.bat:
#    [1] Fresh install
#    [2] Reinstall / Update
#    [3] Uninstall
#  See setup_linux.sh for the rationale; this script is identical
#  except for the shell-rc detection (zsh-first on macOS).
# ============================================================
# NOTE: deliberately no `set -e` — see setup_linux.sh comment.

# --- 0. Language choice (BEFORE any installation work) -------
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

# --- 0b. Auto-detect + Action menu --------------------------------
# Ak nie je nainštalovaná → priamo na inštaláciu.
# Ak je → iba Odinštalovať alebo Zrušiť.
# Reinstal nie je v menu (bezpečnostný dôvod: uv tool install
# vždy re-resolvuje celú izoláciu — potenciálny vektor útoku).
MAGI_INSTALLED=0
if [ -f "$HOME/.local/share/uv/tools/magisentry/bin/magisentry" ]; then
    MAGI_INSTALLED=1
fi

ACTION=1
if [ "$MAGI_INSTALLED" = "1" ]; then
    if [ "$MAGISENTRY_LANG" = "sk" ]; then
        echo "MagiSentry je už nainštalovaná."
        echo ""
        echo "[1] Odinstalovat"
        echo "[2] Zrusit"
    else
        echo "MagiSentry is already installed."
        echo ""
        echo "[1] Uninstall"
        echo "[2] Cancel"
    fi
    echo ""
    read -r ACTION
    echo ""
    if [ "$ACTION" = "2" ]; then
        if [ "$MAGISENTRY_LANG" = "sk" ]; then
            echo "Zrušené. Nastavenia zmeníte cez: magisentry config --wizard"
        else
            echo "Cancelled. Change settings via: magisentry config --wizard"
        fi
        exit 0
    fi
    # When installed, [1] means Uninstall. Remap to action 3.
    ACTION=3
else
    if [ "$MAGISENTRY_LANG" = "sk" ]; then
        echo "MagiSentry nie je nainštalovaná. Spúšťam inštaláciu..."
    else
        echo "MagiSentry not installed. Starting fresh installation..."
    fi
    echo ""
fi

# --- 0c. Uninstall path --------------------------------------
if [ "$ACTION" = "3" ]; then
    if [ "$MAGISENTRY_LANG" = "sk" ]; then
        echo "Odinstalujem MagiSentry..."
    else
        echo "Uninstalling MagiSentry..."
    fi
    # Refresh PATH so magisentry-install-hooks resolves to the uv
    # deployment we're about to remove.
    export PATH="$HOME/.local/share/uv/tools/magisentry/bin:$HOME/.local/bin:$PATH"
    # Clean up AI-tool hook entries BEFORE removing the binary.
    if [ "$MAGISENTRY_LANG" = "sk" ]; then
        echo "Odstraňujem AI-tool hooky..."
    else
        echo "Removing AI-tool hooks..."
    fi
    magisentry-install-hooks --uninstall --all 2>/dev/null || true
    uv tool uninstall magisentry 2>/dev/null || true
    python3 -m pip uninstall magisentry -y 2>/dev/null || true
    if [ -d "$HOME/.magisentry" ]; then
        rm -rf "$HOME/.magisentry"
        if [ "$MAGISENTRY_LANG" = "sk" ]; then
            echo "Konfiguracny priecinok vymazany."
        else
            echo "Config directory removed."
        fi
    fi
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [ -f "$rc" ]; then
            grep -v "magisentry" "$rc" > "${rc}.tmp" \
                && mv "${rc}.tmp" "$rc" || true
        fi
    done
    if [ "$MAGISENTRY_LANG" = "sk" ]; then
        echo "MagiSentry odinstalovana."
    else
        echo "MagiSentry uninstalled."
    fi
    exit 0
fi

# zsh is default on macOS since Catalina; honour an existing .bashrc.
SHELL_RC="$HOME/.zshrc"
if [ -f "$HOME/.bashrc" ] && [ ! -f "$HOME/.zshrc" ]; then
  SHELL_RC="$HOME/.bashrc"
fi

# --- 1. Ensure uv is present ---------------------------------
if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found. Installing via the official installer..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # See setup_linux.sh — installer updates the rc but not the
    # current process. Prepend both candidate dirs so `uv` resolves
    # immediately in this very session.
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

if ! command -v uv >/dev/null 2>&1; then
    echo "[ERROR] uv still not on PATH after install. Open a NEW terminal and re-run."
    exit 1
fi
echo "uv detected: $(uv --version)"

# --- 2a. Pre-install cleanup --------------------------------------
echo "Preparing clean isolation..."
uv tool uninstall magisentry 2>/dev/null || true
if [ -d "$HOME/.magisentry" ]; then
    rm -rf "$HOME/.magisentry"
fi
MAGI_BIN="$(command -v magisentry || true)"
if [ -n "$MAGI_BIN" ] && ! echo "$MAGI_BIN" | grep -q "/uv/"; then
    echo "Found existing pip installation. Migrating..."
    python3 -m pip uninstall magisentry -y >/dev/null 2>&1 || true
else
    echo "Fresh installation detected."
fi

# --- 3. Locate project root ----------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$PROJECT_ROOT/setup.py" ]; then
  echo "[ERROR] setup.py not found at $PROJECT_ROOT/setup.py"
  echo "        Run this script from inside a clone of the MagiSentry repo."
  exit 1
fi

# --- 4. Install via uv tool (editable from local clone) ------
echo ""
echo "Installing MagiSentry via uv tool (editable from local clone)..."
echo "  source: $PROJECT_ROOT"
uv tool install --force --editable "$PROJECT_ROOT" || {
    echo "[ERROR] uv tool install failed. See output above."
    exit 1
}

# --- 5. Register PATH ----------------------------------------
if ! grep -q "magisentry" "$SHELL_RC" 2>/dev/null; then
  {
    echo ''
    echo '# MagiSentry'
    echo 'export PATH="$HOME/.local/bin:$HOME/.magisentry/bin:$PATH"'
  } >> "$SHELL_RC"
fi
export PATH="$HOME/.local/bin:$HOME/.magisentry/bin:$PATH"

# --- 6. Setup wizard -----------------------------------------
echo ""
echo "Launching the setup wizard..."
magisentry config --wizard --mode=fresh || \
    echo "[WARN] Wizard exited with non-zero. Re-run: magisentry config --wizard"

# --- 7. Hook installation ------------------------------------
echo ""
echo "Installing AI-tool hooks (interactive)..."
magisentry-install-hooks --interactive || \
    echo "[WARN] Hook installer exited with non-zero."

# --- 8. Build initial integrity manifest ---------------------
echo ""
echo "Building initial integrity manifest..."
magisentry integrity update --yes || \
    echo "[WARN] Integrity manifest build returned non-zero."

echo ""
if [ "$MAGISENTRY_LANG" = "sk" ]; then
    echo "=== Hotovo. Otvor NOVY terminal a vyskusaj: magisentry pip install requests ==="
else
    echo "=== Done. Open a NEW terminal, then try: magisentry pip install requests ==="
fi
echo "  Run:        source $SHELL_RC"
echo "  Optional:   echo 'export VT_API_KEY=\"your_key_here\"' >> $SHELL_RC"
