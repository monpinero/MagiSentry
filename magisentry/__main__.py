"""Enables `python -m magisentry <args>` as an alias for the
`magisentry` console script. Useful when the `magisentry.exe`
shim isn't on PATH yet (fresh install) and the user still needs
to run e.g. `python -m magisentry uninstall`.
"""
from magisentry.scanner import main

if __name__ == "__main__":
    main()
