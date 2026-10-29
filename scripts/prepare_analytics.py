"""Turn two checked local snapshots into a private Terraform input file.

This makes no AWS calls. Run it from the repository root after building the data.
"""

import argparse
import json
from pathlib import Path
import re

from cloud_detection.dataset import verify_snapshot


def prepare(live, synthetic, account_id, region):
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise ValueError("Use a 12-digit account ID")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d+", region):
        raise ValueError("Use a valid AWS region")
    datasets, uploads = {}, {}
    for name, source in (("security_events", live), ("synthetic_events", synthetic)):
        source = Path(source).resolve()
        manifest = verify_snapshot(source)
        if manifest["failed_documents"] or manifest["quarantined_records"] or not manifest["accepted_records"]:
            raise ValueError("Use nonempty snapshots without rejects for this first Athena demo")
        partitions = set()
        for artifact in manifest["artifacts"]:
            match = re.fullmatch(r"parquet/event_date=(\d{4}-\d{2}-\d{2})/region=([a-z0-9-]+)/([a-zA-Z0-9_.-]+\.parquet)", artifact["path"])
            if not match:
                if artifact["path"].endswith(".parquet"):
                    raise ValueError("Unexpected Parquet partition path")
                continue
            day, event_region, _ = match.groups()
            partitions.add((day, event_region))
            uploads[f"{name}/{artifact['path']}"] = {
                "dataset": name, "relative_path": artifact["path"],
                "source_path": (source / artifact["path"]).as_posix(), "sha256": artifact["sha256"],
            }
        if not partitions:
            raise ValueError("No Parquet partitions found")
        datasets[name] = {
            "snapshot_id": manifest["input_fingerprint"],
            "partitions": [{"event_date": day, "region": event_region} for day, event_region in sorted(partitions)],
        }
    return {
        "expected_account_id": account_id, "aws_region": region,
        "project_name": "cloud-detection", "allow_data_deletion": False,
        "datasets": datasets, "snapshot_files": uploads,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-snapshot", required=True, type=Path)
    parser.add_argument("--synthetic-snapshot", required=True, type=Path)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path("infra/analytics/terraform.tfvars.json"))
    args = parser.parse_args()
    try:
        config = prepare(args.live_snapshot, args.synthetic_snapshot, args.account_id, args.region)
    except ValueError as exc:
        parser.error(str(exc))
    if args.output.exists():
        parser.error("Output already exists. Choose a new filename or review the current file first.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(config['datasets'])} tables and {len(config['snapshot_files'])} uploads. No AWS changes made.")


if __name__ == "__main__":
    main()
