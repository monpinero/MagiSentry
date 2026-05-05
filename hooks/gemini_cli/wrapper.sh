#!/usr/bin/env bash
# MagiSentry wrapper for Gemini CLI (Google). Add an alias:
#   alias gemini='/path/to/this/wrapper.sh'
set -e
if ! command -v gemini >/dev/null 2>&1; then
  echo "MagiSentry: gemini CLI not found on PATH." >&2
  exit 127
fi
exec gemini "$@"
