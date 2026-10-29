"""Run a few manual checks after deploying our two sample tables.

We check row counts and run the no-MFA SQL. Only counts and scan sizes go into
the report; account IDs, event rows, and credentials are not included.
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from cloud_detection.dataset import verify_snapshot


def aws(profile, region, *arguments):
    command = ["aws", *arguments, "--profile", profile, "--region", region, "--no-cli-pager", "--output", "json"]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout) if result.stdout.strip() else {}


def query(call, sql, parameters, database, workgroup):
    submitted = call(
        "athena", "start-query-execution", "--query-string", sql,
        "--query-execution-context", json.dumps({"Database": database, "Catalog": "AwsDataCatalog"}),
        "--work-group", workgroup, "--execution-parameters", *parameters,
    )
    query_id = submitted["QueryExecutionId"]
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        execution = call("athena", "get-query-execution", "--query-execution-id", query_id)["QueryExecution"]
        state = execution["Status"]["State"]
        if state == "SUCCEEDED":
            result = call("athena", "get-query-results", "--query-execution-id", query_id)
            value = int(result["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"])
            return {"query_id": query_id, "count": value, "bytes_scanned": execution["Statistics"].get("DataScannedInBytes", 0)}
        if state in ("FAILED", "CANCELLED"):
            raise RuntimeError(f"Athena {state}: {execution['Status'].get('StateChangeReason', 'no reason returned')}")
        time.sleep(1)
    call("athena", "stop-query-execution", "--query-execution-id", query_id)
    raise RuntimeError("Stopped a query after waiting 60 seconds")


def check(config, snapshots, call, detection_sql):
    account = config["expected_account_id"]
    project = config["project_name"]
    region = config["aws_region"]
    database, workgroup = project.replace("-", "_"), f"{project}-queries"
    if call("sts", "get-caller-identity")["Account"] != account:
        raise ValueError("The active AWS account does not match the project")
    settings = call("athena", "get-work-group", "--work-group", workgroup)["WorkGroup"]["Configuration"]
    result_config = settings["ResultConfiguration"]
    bucket = f"{project}-{account}-{region}-analytics"
    if not (
        settings["EnforceWorkGroupConfiguration"] and settings["BytesScannedCutoffPerQuery"] == 10485760
        and result_config["EncryptionConfiguration"]["EncryptionOption"] == "SSE_S3"
        and result_config["ExpectedBucketOwner"] == account
        and result_config["OutputLocation"] == f"s3://{bucket}/athena-results/"
    ):
        raise ValueError("Workgroup settings differ from our expected cost and storage settings")

    report = {"checks": {}, "workgroup_scan_limit_bytes": 10485760, "query_result_encryption": "SSE_S3"}
    for table in ("security_events", "synthetic_events"):
        manifest = verify_snapshot(snapshots[table])
        dataset = config["datasets"][table]
        if manifest["input_fingerprint"] != dataset["snapshot_id"]:
            raise ValueError("The selected local snapshot differs from the Terraform input")
        metadata = call("glue", "get-table", "--database-name", database, "--name", table)["Table"]
        expected_location = f"s3://{bucket}/datasets/{table}/{dataset['snapshot_id']}/parquet/"
        if metadata["StorageDescriptor"]["Location"] != expected_location:
            raise ValueError("A table points to an unexpected dataset")
        partitions = dataset["partitions"]
        event_regions = sorted({item["region"] for item in partitions})
        if len(event_regions) > 2:
            raise ValueError("This small demo checks at most two regions per table")
        row_count, findings, executions = 0, 0, []
        for event_region in event_regions:
            days = sorted(item["event_date"] for item in partitions if item["region"] == event_region)
            parameters = [f"'{days[0]}'", f"'{days[-1]}'", f"'{event_region}'"]
            count_sql = f"SELECT COUNT(*) FROM {table} WHERE event_date BETWEEN ? AND ? AND region = ?"
            row_result = query(call, count_sql, parameters, database, workgroup)
            # Wrapping the existing SELECT lets us count findings without exporting identities.
            selected_sql = detection_sql.replace("FROM security_events", f"FROM {table}").rstrip().rstrip(";")
            detection = query(call, f"SELECT COUNT(*) FROM (\n{selected_sql}\n) findings", parameters, database, workgroup)
            row_count += row_result["count"]
            findings += detection["count"]
            executions.extend([row_result, detection])
        if row_count != manifest["accepted_records"]:
            raise ValueError(f"Row count differs for {table}")
        if table == "synthetic_events" and findings != 1:
            raise ValueError("The synthetic sample should produce exactly one no-MFA finding")
        report["checks"][table] = {
            "sample_kind": "synthetic" if table == "synthetic_events" else "live",
            "expected_rows": manifest["accepted_records"], "athena_rows": row_count,
            "console_login_without_mfa_findings": findings, "queries": executions,
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("infra/analytics/terraform.tfvars.json"))
    parser.add_argument("--live-snapshot", required=True, type=Path)
    parser.add_argument("--synthetic-snapshot", required=True, type=Path)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    call = lambda *arguments: aws(args.profile, config["aws_region"], *arguments)
    sql = (Path(__file__).resolve().parents[1] / "sql/detections/console_login_without_mfa.sql").read_text()
    try:
        report = check(config, {"security_events": args.live_snapshot, "synthetic_events": args.synthetic_snapshot}, call, sql)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
