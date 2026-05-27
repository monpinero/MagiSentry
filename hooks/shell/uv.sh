#!/usr/bin/env bash
# MagiSentry shim for uv on Linux/macOS. Place its parent directory FIRST in PATH.
# Intercepts `uv add`, `uv pip install`, `uv tool install`; passes through
# every other `uv` subcommand (sync, run, build, lock, venv, ...).
exec python3 -m magisentry.shim uv "$@"
