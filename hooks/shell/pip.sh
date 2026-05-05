#!/usr/bin/env bash
# MagiSentry shim for pip on Linux/macOS. Place its parent directory FIRST in PATH.
exec python3 -m magisentry.shim pip "$@"
