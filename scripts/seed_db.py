#!/usr/bin/env python
"""Seed CyberSentry ATT&CK reference taxonomy, detection rules, assets, and demo detections.

Deterministic execution seeded with 20260911. Safe to re-run (idempotent).
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_YAML = ROOT / "config" / "detection_rules.yml"

DSN = (
    f"host={os.getenv('DB_HOST', 'localhost')} port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'cybersentry')} user={os.getenv('DB_USER', 'sentry')} "
    f"password={os.getenv('DB_PASS', 'sentry_dev_2026')}"
)

# 11 required core tactics
TACTICS = [
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0040", "impact", "Impact"),
]

# Bundled technique catalogue covering all 24 rules plus parent techniques
# Format: (technique_id, technique_name, tactic_id, parent_technique)
BUNDLED_TECHNIQUES = [
    # Parents / Root Techniques
    ("T1003", "OS Credential Dumping", "TA0006", None),
    ("T1021", "Remote Services", "TA0008", None),
    ("T1041", "Exfiltration Over C2 Channel", "TA0010", None),
    ("T1046", "Network Service Discovery", "TA0007", None),
    ("T1048", "Exfiltration Over Alternative Protocol", "TA0010", None),
    ("T1053", "Scheduled Task/Job", "TA0003", None),
    ("T1055", "Process Injection", "TA0005", None),
    ("T1059", "Command and Scripting Interpreter", "TA0002", None),
    ("T1070", "Indicator Removal", "TA0005", None),
    ("T1071", "Application Layer Protocol", "TA0011", None),
    ("T1078", "Valid Accounts", "TA0001", None),
    ("T1087", "Account Discovery", "TA0007", None),
    ("T1098", "Account Manipulation", "TA0003", None),
    ("T1105", "Ingress Tool Transfer", "TA0011", None),
    ("T1110", "Brute Force", "TA0006", None),
    ("T1136", "Create Account", "TA0003", None),
    ("T1218", "System Binary Proxy Execution", "TA0005", None),
    ("T1490", "Inhibit System Recovery", "TA0040", None),
    ("T1547", "Boot or Logon Autostart Execution", "TA0003", None),
    ("T1548", "Abuse Elevation Control Mechanism", "TA0004", None),
    ("T1558", "Steal or Forge Kerberos Tickets", "TA0006", None),
    ("T1562", "Impair Defenses", "TA0005", None),
    ("T1566", "Phishing", "TA0001", None),
    # Sub-techniques (referencing parents)
    ("T1003.001", "LSASS Memory", "TA0006", "T1003"),
    ("T1021.001", "Remote Desktop Protocol", "TA0008", "T1021"),
    ("T1021.002", "SMB/Windows Admin Shares", "TA0008", "T1021"),
    ("T1053.005", "Scheduled Task", "TA0003", "T1053"),
    ("T1059.001", "PowerShell", "TA0002", "T1059"),
    ("T1070.001", "Clear Windows Event Logs", "TA0005", "T1070"),
    ("T1071.004", "DNS", "TA0011", "T1071"),
    ("T1087.002", "Domain Account", "TA0007", "T1087"),
    ("T1136.001", "Local Account", "TA0003", "T1136"),
    ("T1218.011", "Rundll32", "TA0005", "T1218"),
    ("T1547.001", "Registry Run Keys / Startup Folder", "TA0003", "T1547"),
    ("T1548.002", "Bypass User Account Control", "TA0004", "T1548"),
    ("T1558.003", "Kerberoasting", "TA0006", "T1558"),
    ("T1562.001", "Disable or Modify Tools", "TA0005", "T1562"),
    ("T1566.001", "Spearphishing Attachment", "TA0001", "T1566"),
]

PLAYBOOKS = [
    (
        "PB_CRED_DUMP",
        "Credential dumping containment playbook",
        "T1003.001",
        json.dumps(["isolate_host", "collect_forensics", "disable_account", "notify_owner"]),
        True,
    ),
    (
        "PB_BRUTE_FORCE",
        "Brute force IP containment playbook",
        "T1110",
        json.dumps(["block_ip", "notify_owner"]),
        False,
    ),
    (
        "PB_C2_DNS",
        "DNS command-and-control containment playbook",
        "T1071.004",
        json.dumps(["block_ip", "isolate_host", "collect_forensics"]),
        True,
    ),
]

SEVERITY_SCORE = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}


def load_rules_from_yaml() -> list[dict]:
    if not RULES_YAML.exists():
        raise FileNotFoundError(f"Missing rules file: {RULES_YAML}")
    content = yaml.safe_load(RULES_YAML.read_text(encoding="utf-8"))
    return content.get("rules", [])


def seed_reference_data(cur) -> tuple[int, int, int, int]:
    # 1. Tactics
    cur.executemany(
        """
        INSERT INTO attack_tactics (tactic_id, tactic_slug, tactic_name)
        VALUES (%s, %s, %s)
        ON CONFLICT (tactic_id) DO NOTHING
        """,
        TACTICS,
    )

    # 2. Techniques (parents before children)
    for tid, name, tactic, parent in sorted(BUNDLED_TECHNIQUES, key=lambda t: (t[3] is not None)):
        cur.execute(
            """
            INSERT INTO attack_techniques (technique_id, technique_name, tactic_id, parent_technique)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (technique_id) DO NOTHING
            """,
            (tid, name, tactic, parent),
        )

    # Check known techniques
    cur.execute("SELECT technique_id FROM attack_techniques")
    known_techs = {r["technique_id"] for r in cur.fetchall()}

    # 3. Detection Rules loaded from YAML
    rules_data = load_rules_from_yaml()
    rule_tuples = []
    for r in rules_data:
        code = r["code"]
        ver = r["version"]
        title = r["title"]
        tech = r["attack_technique"]
        sev = r["base_severity"]
        params = json.dumps(r.get("params", {}))

        if tech not in known_techs:
            raise ValueError(f"Rule {code} references unknown MITRE technique {tech}!")

        rule_tuples.append((code, ver, title, tech, sev, params))

    cur.executemany(
        """
        INSERT INTO detection_rules (rule_code, version, title, technique_id, base_severity, params, author)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb, 'sec-eng')
        ON CONFLICT (rule_code, version) DO NOTHING
        """,
        rule_tuples,
    )

    # 4. Playbooks
    cur.executemany(
        """
        INSERT INTO playbooks (playbook_id, title, trigger_technique, steps, requires_approval)
        VALUES (%s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (playbook_id) DO NOTHING
        """,
        PLAYBOOKS,
    )

    return len(TACTICS), len(BUNDLED_TECHNIQUES), len(rule_tuples), len(PLAYBOOKS)


def seed_estate(cur, n_assets: int = 60, n_identities: int = 40) -> tuple[list[str], list[str]]:
    assets = []
    identities = []

    # Assets allocation:
    # 2 Domain Controllers (crown_jewel)
    # 12 Servers (high)
    # 10 Cloud Instances (internet-facing, medium/high)
    # 36 Workstations (low/medium)
    for i in range(n_assets):
        if i < 2:
            atype = "domain_controller"
            crit = "crown_jewel"
            is_net = False
        elif i < 14:
            atype = "server"
            crit = "high"
            is_net = False
        elif i < 24:
            atype = "cloud_instance"
            crit = "high" if i % 2 == 0 else "medium"
            is_net = True
        else:
            atype = "workstation"
            crit = "medium" if i % 3 == 0 else "low"
            is_net = False

        host_id = f"HOST-{i:04d}"
        hostname = f"corp-{atype[:4]}-{i:03d}"
        os_family = "windows" if atype in ("domain_controller", "workstation") else "linux"
        ip_addr = str(ipaddress.IPv4Address(0x0A000000 + i))
        bu = ["finance", "engineering", "sales", "it", "security"][i % 5]
        email = f"lead.{bu}@corp.example"

        cur.execute(
            """
            INSERT INTO assets (host_id, hostname, asset_type, os_family, ip_address,
                                business_unit, owner_email, criticality, is_internet_facing, last_seen_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (host_id) DO UPDATE SET hostname = EXCLUDED.hostname
            RETURNING asset_id
            """,
            (host_id, hostname, atype, os_family, ip_addr, bu, email, crit, is_net),
        )
        assets.append(cur.fetchone()["asset_id"])

    # Identities allocation:
    # 40 users, every 8th is privileged admin
    for i in range(n_identities):
        is_priv = (i % 8 == 0)
        itype = "admin" if is_priv else "user"
        uname = f"corp\\user{i:03d}"
        dname = f"User {i:03d}" + (" (Admin)" if is_priv else "")
        dept = ["finance", "engineering", "sales", "it", "security"][i % 5]

        cur.execute(
            """
            INSERT INTO identities (user_name, display_name, identity_type, is_privileged, department, is_active)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            ON CONFLICT (user_name) DO UPDATE SET display_name = EXCLUDED.display_name
            RETURNING identity_id
            """,
            (uname, dname, itype, is_priv, dept),
        )
        identities.append(cur.fetchone()["identity_id"])

    return assets, identities


def seed_demo_detections(cur, assets: list[str], identities: list[str], n: int = 300) -> int:
    rng = random.Random(20260911)
    rules_data = load_rules_from_yaml()
    now = datetime.now(timezone.utc)
    inserted = 0

    for i in range(n):
        rule = rng.choice(rules_data)
        rule_code = rule["code"]
        rule_ver = rule["version"]
        base_sev = rule["base_severity"]
        score = SEVERITY_SCORE.get(base_sev, 50)

        asset_id = rng.choice(assets)
        identity_id = rng.choice(identities)
        offset_minutes = rng.randint(0, 7 * 24 * 60)
        detected_at = now - timedelta(minutes=offset_minutes)

        bucket = int(detected_at.timestamp() // (15 * 60))
        dedup_key = f"{rule_code}|{asset_id}|{bucket}|{i % 97}"

        day_str = detected_at.strftime("%Y.%m.%d")
        evidence_idx = f"sentry-events-{day_str}"
        doc_id = f"doc-{i:06d}"
        detail = json.dumps({"seeded": True, "title": rule["title"], "params": rule.get("params", {})})

        cur.execute(
            """
            INSERT INTO detections (rule_code, rule_version, detected_at, asset_id, identity_id,
                                    source_ip, severity, risk_score, dedup_key, evidence_index,
                                    evidence_doc_id, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (dedup_key) DO NOTHING
            """,
            (
                rule_code,
                rule_ver,
                detected_at,
                asset_id,
                identity_id,
                str(ipaddress.IPv4Address(rng.getrandbits(32))),
                base_sev,
                score,
                dedup_key,
                evidence_idx,
                doc_id,
                detail,
            ),
        )
        inserted += 1

    return inserted


def main() -> int:
    print(f"[seed] Connecting to PostgreSQL at {DSN}...")
    with psycopg.connect(DSN, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM detection_rules")
            existing = cur.fetchone()["c"]
            if existing >= 24:
                print("already seeded — run `make reset` first to reseed")
                return 0

            n_tactics, n_techs, n_rules, n_playbooks = seed_reference_data(cur)
            assets, identities = seed_estate(cur, n_assets=60, n_identities=40)
            n_detections = seed_demo_detections(cur, assets, identities, n=300)

            cur.execute(
                """
                INSERT INTO audit_log (actor, action, resource_type, resource_id, detail)
                VALUES ('seed_script', 'SEED', 'database', 'cybersentry', '{"milestone": "M1"}'::jsonb)
                """
            )
        conn.commit()

    print(
        f"Seeded: {n_tactics} tactics, {n_techs} techniques, {n_rules} rules, "
        f"{n_playbooks} playbooks, {len(assets)} assets, {len(identities)} identities, "
        f"~{n_detections} detections."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())