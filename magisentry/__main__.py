"""Enables `python -m magisentry <args>` as an alias for the
`magisentry` console script. Useful when the `magisentry.exe`
shim isn't on PATH yet (fresh install) and the user still needs
to run e.g. `python -m magisentry uninstall`.
"""
import sys

from magisentry.scanner import main

if __name__ == "__main__":
    # Forward the scanner's exit code: 0 = OK, 1 = technical failure,
    # 2 = threat detected. Without `sys.exit(main())` Python returns 0
    # for any clean function return, which silently hides EXIT_THREAT
    # from CI pipelines and hooks that drive behaviour off exit codes.
    sys.exit(main())
