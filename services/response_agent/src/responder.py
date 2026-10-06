"""CyberSentry Response Agent Service (M1 Scaffold).

NOTE: In accordance with ADR-0003 (Mandatory Human Approval for Destructive Response Actions),
there is NO automated containment or response execution logic implemented in Milestone 1.
All containment actions in M1 are non-executing stubs and strictly require explicit analyst
approvals before execution in future milestones.
"""

from __future__ import annotations

import json
import signal
import sys
import time

_running = True


def _handle_signal(signum: int, frame) -> None:
    global _running
    _running = False


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    banner = {
        "service": "response_agent",
        "milestone": "M1",
        "status": "scaffold only — implemented in M2+",
    }
    sys.stdout.write(json.dumps(banner) + "\n")
    sys.stdout.flush()

    while _running:
        time.sleep(1)


if __name__ == "__main__":
    main()
