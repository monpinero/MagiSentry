#!/usr/bin/env bash
# MagiSentry wrapper for Codex CLI (OpenAI). Add an alias:
#   alias codex='/path/to/this/wrapper.sh'
# Relies on the universal pip/npm shims being first on PATH.
set -e
export CODEX_CONFIRM_EXEC=1
if ! command -v codex >/dev/null 2>&1; then
  echo "MagiSentry: codex CLI not found on PATH." >&2
  exit 127
fi
exec codex "$@"
