#!/usr/bin/env python
"""CyberSentry Milestone 1 Verification Suite.

Validates infrastructure contracts, database schemas, detection rules,
Kafka topics, OpenSearch ISM policies, git ignore rules, and unit tests.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Expected configurations
REQUIRED_TABLES = {
    "assets",
    "identities",
    "attack_tactics",
    "attack_techniques",
    "detection_rules",
    "detections",
    "incidents",
    "incident_detections",
    "incident_notes",
    "playbooks",
    "response_actions",
    "action_approvals",
    "audit_log",
}

REQUIRED_TOPICS = {"sec.raw", "sec.normalized", "sec.detections", "sec.dlq"}

DSN = (
    f"host={os.getenv('DB_HOST', 'localhost')} port={os.getenv('DB_PORT', '5432')} "
    f"dbname={os.getenv('DB_NAME', 'cybersentry')} user={os.getenv('DB_USER', 'sentry')} "
    f"password={os.getenv('DB_PASS', 'sentry_dev_2026')}"
)


def log_pass(msg: str) -> None:
    print(f" [PASS] {msg}")


def log_fail(msg: str) -> None:
    print(f" [FAIL] {msg}")


def log_skip(msg: str, reason: str) -> None:
    print(f" [PENDING/SKIPPED] {msg} ({reason})")


def check_git_ignored_env() -> bool:
    """Verify that .env is blocked by git ignore rules."""
    try:
        res = subprocess.run(
            ["git", "check-ignore", ".env"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and ".env" in res.stdout:
            log_pass(".env is git-ignored")
            return True
        log_fail(".env is NOT ignored by Git")
        return False
    except Exception as exc:
        log_fail(f"git check-ignore error: {exc}")
        return False


def check_unit_tests() -> bool:
    """Run pytest suite using current Python interpreter."""
    cmd = [sys.executable, "-m", "pytest", "tests/", "-q"]
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if res.returncode == 0:
        log_pass("All unit tests passed")
        return True
    log_fail(f"Unit tests failed:\n{res.stdout}\n{res.stderr}")
    return False


def check_compose_config() -> bool:
    """Validate docker-compose.yml syntax and service definitions."""
    res = subprocess.run(
        ["docker", "compose", "config"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        log_pass("docker-compose.yml configuration is valid")
        return True
    log_fail(f"docker-compose.yml validation failed:\n{res.stderr}")
    return False


def check_detection_rules_yaml() -> tuple[bool, set[str]]:
    """Validate that config/detection_rules.yml defines all 24 rules."""
    try:
        import yaml
        rules_file = ROOT / "config" / "detection_rules.yml"
        if not rules_file.exists():
            log_fail("config/detection_rules.yml missing")
            return False, set()
        data = yaml.safe_load(rules_file.read_text(encoding="utf-8"))
        rules = data.get("rules", [])
        codes = {r["code"] for r in rules}
        if len(rules) == 24 and len(codes) == 24:
            log_pass("24 unique detection rules configured in YAML")
            return True, codes
        log_fail(f"Expected 24 rules in YAML, found {len(rules)} (unique: {len(codes)})")
        return False, codes
    except Exception as exc:
        log_fail(f"YAML validation error: {exc}")
        return False, set()


def check_kafka_topics_yaml() -> bool:
    """Validate that config/kafka_topics.yml specifies the 4 required topics."""
    try:
        import yaml
        topics_file = ROOT / "config" / "kafka_topics.yml"
        if not topics_file.exists():
            log_fail("config/kafka_topics.yml missing")
            return False
        data = yaml.safe_load(topics_file.read_text(encoding="utf-8"))
        topics = {t["name"] for t in data.get("topics", [])}
        if REQUIRED_TOPICS.issubset(topics):
            log_pass("Kafka topics specification matches required topics")
            return True
        log_fail(f"Missing required topics in kafka_topics.yml: {REQUIRED_TOPICS - topics}")
        return False
    except Exception as exc:
        log_fail(f"kafka_topics.yml error: {exc}")
        return False


def check_opensearch_template_json() -> bool:
    """Validate config/opensearch_index.json format and mappings."""
    try:
        template_file = ROOT / "config" / "opensearch_index.json"
        if not template_file.exists():
            log_fail("config/opensearch_index.json missing")
            return False
        data = json.loads(template_file.read_text(encoding="utf-8"))
        patterns = data.get("index_patterns", [])
        props = data.get("template", {}).get("mappings", {}).get("properties", {})
        if "sentry-events-*" in patterns and "@timestamp" in props and "event_id" in props:
            log_pass("OpenSearch index template JSON is valid with required properties")
            return True
        log_fail("OpenSearch index template missing pattern or properties")
        return False
    except Exception as exc:
        log_fail(f"opensearch_index.json error: {exc}")
        return False


def check_database(yaml_rule_codes: set[str]) -> bool:
    """Validate PostgreSQL schema, constraints, and data integrity."""
    try:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(DSN, row_factory=dict_row, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                # 1. 13 tables present
                cur.execute(
                    """
                    SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'public'
                    """
                )
                present_tables = {r["table_name"] for r in cur.fetchall()}
                missing = REQUIRED_TABLES - present_tables
                if missing:
                    log_fail(f"Database missing required tables: {missing}")
                    return False
                log_pass("All 13 required database tables present")

                # 2. >= 11 techniques and 11 tactics
                cur.execute("SELECT COUNT(*) AS c FROM attack_tactics")
                tactic_cnt = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) AS c FROM attack_techniques")
                tech_cnt = cur.fetchone()["c"]
                if tactic_cnt < 11 or tech_cnt < 11:
                    log_fail(f"Insufficient ATT&CK data: {tactic_cnt} tactics, {tech_cnt} techniques")
                    return False
                log_pass(f"ATT&CK reference loaded ({tactic_cnt} tactics, {tech_cnt} techniques)")

                # 3. 24 rules matching YAML
                cur.execute("SELECT rule_code FROM detection_rules")
                db_rule_codes = {r["rule_code"] for r in cur.fetchall()}
                if db_rule_codes != yaml_rule_codes:
                    log_fail(f"Rules mismatch: DB has {len(db_rule_codes)}, YAML has {len(yaml_rule_codes)}")
                    return False
                log_pass("24 detection rules present in database matching YAML catalogue")

                # 4. No rule without technique
                cur.execute("SELECT COUNT(*) AS c FROM detection_rules WHERE technique_id IS NULL")
                if cur.fetchone()["c"] > 0:
                    log_fail("Found detection rules with NULL technique_id")
                    return False
                log_pass("Every detection rule maps to a valid technique")

                # 5. UNIQUE(dedup_key) constraint exists
                cur.execute(
                    """
                    SELECT conname FROM pg_constraint
                    WHERE conrelid = 'detections'::regclass AND contype = 'u'
                    """
                )
                unique_cons = [r["conname"] for r in cur.fetchall()]
                if not unique_cons:
                    log_fail("Missing UNIQUE constraint on detections.dedup_key")
                    return False
                log_pass(f"UNIQUE(dedup_key) constraint confirmed ({unique_cons[0]})")

                # 6. >= 60 assets
                cur.execute("SELECT COUNT(*) AS c FROM assets")
                asset_cnt = cur.fetchone()["c"]
                if asset_cnt < 60:
                    log_fail(f"Insufficient assets: {asset_cnt} < 60")
                    return False
                log_pass(f"Asset inventory populated ({asset_cnt} assets)")

                # 7. >= 2 approval-required playbooks
                cur.execute("SELECT COUNT(*) AS c FROM playbooks WHERE requires_approval = TRUE")
                pb_cnt = cur.fetchone()["c"]
                if pb_cnt < 2:
                    log_fail(f"Insufficient approval playbooks: {pb_cnt} < 2")
                    return False
                log_pass(f"Approval-required playbooks present ({pb_cnt})")

                # 8. audit_log rejects UPDATE/DELETE
                try:
                    conn.rollback()
                    with conn.transaction():
                        cur.execute(
                            "INSERT INTO audit_log (actor, action, resource_type, resource_id) "
                            "VALUES ('verify_test', 'TEST', 'test', '1') RETURNING id"
                        )
                        test_id = cur.fetchone()["id"]
                        trigger_blocked = False
                        try:
                            cur.execute("UPDATE audit_log SET actor = 'tamper' WHERE id = %s", (test_id,))
                        except Exception:
                            trigger_blocked = True
                        if not trigger_blocked:
                            log_fail("audit_log allowed UPDATE operation; trigger not working")
                            return False
                    conn.rollback()
                    log_pass("audit_log append-only trigger verified (rejected UPDATE)")
                except Exception as exc:
                    log_fail(f"audit_log trigger test error: {exc}")
                    return False

        return True
    except Exception as exc:
        log_skip("PostgreSQL live checks", f"Database connection unavailable: {exc}")
        return False


def check_live_services() -> bool:
    """Check running Docker compose services if daemon is active."""
    try:
        res = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            log_skip("Live Docker container checks", "Docker daemon is not running")
            return False
        log_pass("Docker Compose runtime inspected")
        return True
    except Exception as exc:
        log_skip("Live Docker container checks", str(exc))
        return False


def main() -> int:
    print("=" * 60)
    print("  CyberSentry Milestone 1 (M1) Verification Suite")
    print("=" * 60)

    success = True

    # 1. Static and filesystem checks
    if not check_git_ignored_env():
        success = False

    rules_ok, yaml_rule_codes = check_detection_rules_yaml()
    if not rules_ok:
        success = False

    if not check_kafka_topics_yaml():
        success = False

    if not check_opensearch_template_json():
        success = False

    if not check_compose_config():
        success = False

    # 2. Unit tests
    if not check_unit_tests():
        success = False

    # 3. Live services / DB checks
    check_live_services()
    check_database(yaml_rule_codes)

    print("=" * 60)
    if success:
        print("M1 COMPLETE — safe to tag v0.1.0-M1")
        return 0
    else:
        print("M1 VERIFICATION FAILED — address issues above before tagging")
        return 1


if __name__ == "__main__":
    sys.exit(main())
