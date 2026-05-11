#!/usr/bin/env bash
# MagiSentry shim for pip3 on Linux/macOS.
exec python3 -m magisentry.shim pip "$@"
