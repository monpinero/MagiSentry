#!/usr/bin/env bash
# MagiSentry shim for npm on Linux/macOS. Place its parent directory FIRST in PATH.
exec python3 -m magisentry.shim npm "$@"
