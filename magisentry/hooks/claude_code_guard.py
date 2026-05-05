"""Claude Code PreToolUse hook entry-point.

Claude Code feeds a JSON payload on stdin describing the proposed tool call:
    {
      "tool_name": "Bash",
      "tool_input": {"command": "pip install requests", ...},
      ...
    }

We extract the command, parse it for pip/npm/yarn install patterns, and
re-invoke the magisentry scanner. Exit codes:
    0 -> allow the original Bash call
    2 -> deny  (Claude Code surfaces the message to the user)
"""
import json
import sys

from ._shared import (
    parse_install_command, parse_special_command,
    run_for_packages, passthrough, block_with_message,
)


def main() -> int:
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except (json.JSONDecodeError, OSError):
        return passthrough()

    if payload.get("tool_name") != "Bash":
        return passthrough()
    command = (payload.get("tool_input") or {}).get("command") or ""
    parsed = parse_install_command(command) or parse_special_command(command)
    if parsed is None:
        return passthrough()

    ecosystem, packages = parsed
    rc = run_for_packages(ecosystem, packages)
    if rc == 2:
        return block_with_message(
            f"MagiSentry blocked this install ({ecosystem}: {', '.join(packages)}). "
            "See the scanner output above for details."
        )
    if rc == 1:
        return block_with_message(
            "MagiSentry scanner failed in fail-secure mode — install blocked."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
