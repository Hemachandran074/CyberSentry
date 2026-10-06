"""CyberSentry Correlation Agent Service (M1 Scaffold).

Consumes detections from sec.detections, clusters events across sliding temporal
windows by shared entity (host, user, or IP), computes composite risk, and creates incidents.
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
        "service": "correlation_agent",
        "milestone": "M1",
        "status": "scaffold only — implemented in M2+",
    }
    sys.stdout.write(json.dumps(banner) + "\n")
    sys.stdout.flush()

    while _running:
        time.sleep(1)


if __name__ == "__main__":
    main()
