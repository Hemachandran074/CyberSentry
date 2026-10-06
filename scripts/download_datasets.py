#!/usr/bin/env python
"""Stage the MITRE ATT&CK catalogue and adversary telemetry sample guidance."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import urlretrieve

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
ATTACK = RAW / "attack"
TELEMETRY = RAW / "telemetry"

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

EXTERNAL_RESOURCES = [
    (
        "EVTX-ATTACK-SAMPLES",
        "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        "Clone and place .evtx event logs under data/raw/telemetry/evtx/",
    ),
    (
        "Security Datasets (Mordor)",
        "https://securitydatasets.com/",
        "Download atomic or compound JSON datasets into data/raw/telemetry/mordor/",
    ),
    (
        "CIC-IDS2017",
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        "Request access and place CSV telemetry under data/raw/telemetry/cicids/",
    ),
]


def fetch_attack_catalogue() -> None:
    """Download enterprise-attack.json STIX dataset if not already cached."""
    ATTACK.mkdir(parents=True, exist_ok=True)
    target = ATTACK / "enterprise-attack.json"

    if target.exists():
        print("[cache] enterprise-attack.json is already present.")
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            techniques = [
                obj
                for obj in data.get("objects", [])
                if obj.get("type") == "attack-pattern" and not obj.get("revoked")
            ]
            print(f"        {len(techniques)} active techniques indexed in local file.")
        except Exception:
            pass
        return

    print("[download] Fetching enterprise-attack.json (~40 MB from MITRE CTI)...")
    urlretrieve(ATTACK_STIX_URL, target)

    data = json.loads(target.read_text(encoding="utf-8"))
    techniques = [
        obj
        for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern" and not obj.get("revoked")
    ]
    print(f"           Successfully downloaded: {len(techniques)} active techniques available.")


def main() -> int:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    try:
        fetch_attack_catalogue()
    except Exception as exc:
        print(f"[warning] MITRE ATT&CK download encountered an error: {exc}")
        print("          seed_db.py will continue using the bundled core technique subset.")

    print("\nTelemetry corpora requiring manual download:")
    for name, url, instructions in EXTERNAL_RESOURCES:
        print(f"  - {name}: {url}")
        print(f"      Instruction: {instructions}")

    print("\nSecurity notice: Telemetry contains internal hostnames, user accounts, and IPs.")
    print("                 The data/raw/telemetry/ path is strictly excluded from Git tracking.")
    print("Next step: Run 'dvc add data/raw && dvc push' to update data version control.")
    return 0


if __name__ == "__main__":
    sys.exit(main())