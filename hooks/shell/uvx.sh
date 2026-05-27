#!/usr/bin/env bash
# MagiSentry shim for uvx on Linux/macOS. Place its parent directory FIRST in PATH.
# Intercepts `uvx install`; passes through every other invocation.
exec python3 -m magisentry.shim uvx "$@"
