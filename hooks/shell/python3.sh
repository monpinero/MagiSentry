#!/usr/bin/env bash
# MagiSentry shim for python3. Intercepts 'python3 -m pip install'.
# Passes all other python3 calls directly to the real binary.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_PYTHON=""
IFS=':' read -ra DIRS <<< "$PATH"
for dir in "${DIRS[@]}"; do
    resolved="$(cd "$dir" 2>/dev/null && pwd)"
    if [ "$resolved" = "$SCRIPT_DIR" ]; then continue; fi
    if [ -x "$dir/python3" ]; then
        REAL_PYTHON="$dir/python3"
        break
    fi
done
if [ -z "$REAL_PYTHON" ]; then
    echo "magisentry: real python3 not found on PATH" >&2; exit 127
fi
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
    exec "$REAL_PYTHON" -m magisentry.shim pip "${@:3}"
fi
exec "$REAL_PYTHON" "$@"
