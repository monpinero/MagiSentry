#!/usr/bin/env bash
# MagiSentry shim for pnpm on Linux/macOS. Place its parent directory FIRST in PATH.
exec python3 -m magisentry.shim pnpm "$@"
