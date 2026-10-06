#!/usr/bin/env python
"""Load MITRE ATT&CK reference data from STIX enterprise-attack.json into PostgreSQL."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
STIX_PATH = ROOT / "data" / "raw" / "attack" / "enterprise-attack.json"

DSN = (
    f"host={os.getenv('DB_HOST', 'localhost')} port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'cybersentry')} user={os.getenv('DB_USER', 'sentry')} "
    f"password={os.getenv('DB_PASS', 'sentry_dev_2026')}"
)

# Standard phase to tactic_id lookup
PHASE_TO_TACTIC_ID = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}


def load_from_stix(conn) -> tuple[int, int]:
    raw_text = STIX_PATH.read_text(encoding="utf-8")
    data = json.loads(raw_text)
    objects = data.get("objects", [])

    tactics_to_insert = []
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            slug = obj.get("x_mitre_shortname")
            name = obj.get("name")
            ext_refs = obj.get("external_references", [])
            ext_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if ext_id and slug and name:
                tactics_to_insert.append((ext_id, slug, name))

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO attack_tactics (tactic_id, tactic_slug, tactic_name)
            VALUES (%s, %s, %s)
            ON CONFLICT (tactic_id) DO UPDATE SET
                tactic_slug = EXCLUDED.tactic_slug,
                tactic_name = EXCLUDED.tactic_name
            """,
            tactics_to_insert,
        )

    # Collect techniques
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        ext_refs = obj.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not tech_id:
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")
        phases = obj.get("kill_chain_phases", [])
        primary_phase = phases[0]["phase_name"] if phases else None
        tactic_id = PHASE_TO_TACTIC_ID.get(primary_phase)

        parent_id = tech_id.split(".")[0] if "." in tech_id else None
        is_sub = "." in tech_id

        techniques.append({
            "id": tech_id,
            "name": name,
            "tactic_id": tactic_id,
            "parent_id": parent_id,
            "is_sub": is_sub,
            "description": desc[:500] if desc else None,
        })

    # Sort so parents (is_sub == False) are inserted before sub-techniques (is_sub == True)
    techniques.sort(key=lambda t: t["is_sub"])

    with conn.cursor() as cur:
        for tech in techniques:
            cur.execute(
                """
                INSERT INTO attack_techniques (technique_id, technique_name, tactic_id, parent_technique, description)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (technique_id) DO UPDATE SET
                    technique_name = EXCLUDED.technique_name,
                    tactic_id = EXCLUDED.tactic_id,
                    parent_technique = EXCLUDED.parent_technique,
                    description = EXCLUDED.description
                """,
                (tech["id"], tech["name"], tech["tactic_id"], tech["parent_id"], tech["description"]),
            )
    conn.commit()
    return len(tactics_to_insert), len(techniques)


def main() -> int:
    if not STIX_PATH.exists():
        print(f"[info] STIX enterprise-attack.json not found at {STIX_PATH}.")
        print("       Seed script will continue using the bundled ATT&CK reference subset.")
        return 0

    print(f"[load] Parsing STIX ATT&CK file from {STIX_PATH}...")
    try:
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            tactics_count, techniques_count = load_from_stix(conn)
            print(f"[success] Upserted {tactics_count} tactics and {techniques_count} techniques from STIX.")
    except Exception as exc:
        print(f"[warn] Failed to load STIX into DB: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
