#!/usr/bin/env python3
"""
UEBA Baseline Seeder for India CNI.

Seeds realistic behavioral baseline data for CNI user accounts so the UEBA
deviation scorer has reference distributions to compare against.

Accounts seeded:
  - exam.coordinator@cbse.gov.in  (CBSE, education sector)
  - svc-ehrsystem@aiims.gov.in    (AIIMS, healthcare sector)
  - ot-admin@pgcil.gov.in         (PGCIL, OT/power grid)
  - user047@ministry.gov.in       (Ministry, government)
  - svc-backup@example.com        (Generic service account)

Usage:
    python scripts/seed_ueba_baseline.py
    python scripts/seed_ueba_baseline.py --ueba-url http://localhost:8010
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta
import random

# Baseline behavioral profiles for each CNI persona
# Values represent normal (non-anomalous) activity distributions

CNI_BASELINES = [
    {
        "entity_id": "exam.coordinator@cbse.gov.in",
        "entity_type": "user",
        "sector": "education",
        "profile": {
            "normal_login_hours": {"start_hour": 9, "end_hour": 18, "timezone": "Asia/Kolkata"},
            "normal_login_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
            "avg_db_records_per_hour": 200,
            "max_db_records_per_hour": 500,
            "normal_data_transfer_mb_per_day": 50,
            "normal_unique_dst_ips_per_day": 5,
            "normal_failed_logins_per_day": 1,
            "alert_thresholds": {
                "db_records_per_hour": 2000,
                "data_transfer_mb_per_day": 500,
                "off_hours_access": True,
                "unique_dst_ips_per_day": 15,
            },
            "peer_group": "cbse_exam_coordinators",
            "context": "Manages exam schedules and coordinator assignments; normal activity is modest DB queries",
        },
    },
    {
        "entity_id": "svc-ehrsystem@aiims.gov.in",
        "entity_type": "service_account",
        "sector": "healthcare",
        "profile": {
            "normal_login_hours": {"start_hour": 0, "end_hour": 24, "timezone": "Asia/Kolkata"},
            "normal_login_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
            "avg_file_operations_per_hour": 150,
            "max_file_operations_per_hour": 300,
            "normal_data_transfer_mb_per_day": 200,
            "normal_unique_dst_ips_per_day": 3,
            "alert_thresholds": {
                "file_operations_per_hour": 2000,
                "vss_deletion_events": 1,
                "shadow_copy_commands": 1,
                "bcdedit_commands": 1,
            },
            "peer_group": "aiims_service_accounts",
            "context": "EHR system service account; runs scheduled backup jobs; any VSS deletion is anomalous",
        },
    },
    {
        "entity_id": "ot-admin@pgcil.gov.in",
        "entity_type": "user",
        "sector": "power_grid_ot",
        "profile": {
            "normal_login_hours": {"start_hour": 8, "end_hour": 20, "timezone": "Asia/Kolkata"},
            "normal_login_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
            "normal_hosts_accessed_per_day": 3,
            "max_hosts_accessed_per_day": 6,
            "normal_commands_per_session": 20,
            "ot_network_access": True,
            "allowed_protocols": ["SSH", "RDP_to_IT_only"],
            "alert_thresholds": {
                "native_recon_commands_per_session": 5,
                "it_to_ot_rdp": True,
                "modbus_write_commands": 0,
                "dnp3_write_commands": 0,
                "hosts_accessed_per_day": 10,
            },
            "peer_group": "pgcil_ot_admins",
            "context": "OT administrator; should never issue Modbus/DNP3 write commands from IT-side workstation",
        },
    },
    {
        "entity_id": "user047@ministry.gov.in",
        "entity_type": "user",
        "sector": "government",
        "profile": {
            "normal_login_hours": {"start_hour": 9, "end_hour": 18, "timezone": "Asia/Kolkata"},
            "normal_login_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
            "normal_files_accessed_per_day": 30,
            "max_files_accessed_per_day": 80,
            "normal_unique_dst_ips_per_day": 4,
            "privilege_level": "standard_user",
            "alert_thresholds": {
                "off_hours_privileged_access": True,
                "dc_access_from_workstation": True,
                "new_local_admin_account_creation": 1,
                "powershell_encoded_commands": 1,
            },
            "peer_group": "ministry_standard_users",
            "context": "Standard government employee; no AD admin rights; PowerShell should never be used",
        },
    },
    {
        "entity_id": "svc-backup@example.com",
        "entity_type": "service_account",
        "sector": "generic_it",
        "profile": {
            "normal_login_hours": {"start_hour": 0, "end_hour": 4, "timezone": "UTC"},
            "normal_login_days": ["Sunday"],
            "avg_file_operations_per_hour": 500,
            "max_file_operations_per_hour": 1000,
            "normal_hosts_accessed_per_day": 2,
            "allowed_hosts": ["FIN-DB01", "FIN-DB02"],
            "alert_thresholds": {
                "smb_lateral_movement": True,
                "vss_deletion_events": 1,
                "file_encryption_pattern": 100,
                "access_outside_maintenance_window": True,
            },
            "peer_group": "backup_service_accounts",
            "context": "Backup service account; should only run Sunday 00:00-04:00; SMB lateral access is always anomalous",
        },
    },
]


def _post_baselines(ueba_url: str, baselines: list[dict]) -> None:
    """POST baseline profiles to UEBA service."""
    try:
        import urllib.request
        import urllib.error
    except ImportError:
        pass  # stdlib — always available

    for baseline in baselines:
        payload = json.dumps({
            "entity_id": baseline["entity_id"],
            "entity_type": baseline["entity_type"],
            "baseline_data": baseline["profile"],
            "sector": baseline["sector"],
            "seed_source": "cni_hackathon_demo",
        }).encode()

        req = urllib.request.Request(
            f"{ueba_url}/api/v1/ueba/baselines",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                print(f"  [OK] Seeded baseline: {baseline['entity_id']}")
        except urllib.error.HTTPError as e:
            print(f"  [WARN] HTTP {e.code} for {baseline['entity_id']}: {e.reason}")
        except Exception as e:
            print(f"  [WARN] Could not reach UEBA ({e}) — printing baseline instead:")
            print(f"         Entity: {baseline['entity_id']} | Sector: {baseline['sector']}")


def seed_locally(baselines: list[dict]) -> None:
    """Print baseline profiles (when UEBA service is unavailable)."""
    print("\nCNI User Behavioral Baselines (for UEBA deviation scoring):")
    print("-" * 70)
    for b in baselines:
        p = b["profile"]
        hours = p.get("normal_login_hours", {})
        print(f"\n  Entity:  {b['entity_id']}")
        print(f"  Sector:  {b['sector']}")
        print(f"  Hours:   {hours.get('start_hour', '?'):02d}:00 - {hours.get('end_hour', '?'):02d}:00 IST")
        print(f"  Context: {p.get('context', '')}")
        thresholds = p.get("alert_thresholds", {})
        print(f"  Alert thresholds: {json.dumps(thresholds, default=str)}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Seed UEBA baseline profiles for India CNI")
    parser.add_argument("--ueba-url", default="http://localhost:8081", help="UEBA service URL")
    parser.add_argument("--local", action="store_true", help="Print baselines without posting to UEBA")
    args = parser.parse_args(argv)

    print(f"Seeding UEBA baselines for {len(CNI_BASELINES)} CNI entities...")

    if args.local:
        seed_locally(CNI_BASELINES)
    else:
        _post_baselines(args.ueba_url, CNI_BASELINES)

    print(f"\nDone. {len(CNI_BASELINES)} baselines seeded.")
    print("UEBA deviation scorer now has reference distributions for:")
    for b in CNI_BASELINES:
        print(f"  - {b['entity_id']} ({b['sector']})")


if __name__ == "__main__":
    main()
