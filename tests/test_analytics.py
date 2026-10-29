import copy
import json
from pathlib import Path
import tempfile
import unittest

import pyarrow as pa

from cloud_detection.dataset import build_dataset, EVENT_SCHEMA
from scripts.prepare_analytics import prepare
from scripts.check_athena import check


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = Path(__file__).resolve().parents[1]
        records = json.loads((self.project / "examples/cloudtrail.json").read_text())["Records"]
        for name in ("live", "synthetic"):
            source = self.root / f"{name}.json"
            content = copy.deepcopy(records)
            if name == "live":
                for record in content:
                    record["eventName"] = "GetBucketVersioning"
                    record["eventSource"] = "s3.amazonaws.com"
            source.write_text(json.dumps({"Records": content}))
            build_dataset([source], self.root / name)
        self.snapshots = {"security_events": self.root / "live", "synthetic_events": self.root / "synthetic"}
        self.config = prepare(self.root / "live", self.root / "synthetic", "111122223333", "us-east-1")
        self.sql = (self.project / "sql/detections/console_login_without_mfa.sql").read_text()
        self.started = []
        self.query_counts = {}
        self.account = "111122223333"
        self.scan_limit = 10485760

    def call(self, service, action, *arguments):
        if (service, action) == ("sts", "get-caller-identity"):
            return {"Account": self.account}
        if (service, action) == ("athena", "get-work-group"):
            return {"WorkGroup": {"Configuration": {
                "EnforceWorkGroupConfiguration": True, "BytesScannedCutoffPerQuery": self.scan_limit,
                "ResultConfiguration": {"ExpectedBucketOwner": "111122223333", "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}, "OutputLocation": "s3://cloud-detection-111122223333-us-east-1-analytics/athena-results/"}
            }}}
        if (service, action) == ("glue", "get-table"):
            table = arguments[arguments.index("--name") + 1]
            snapshot_id = self.config["datasets"][table]["snapshot_id"]
            return {"Table": {"StorageDescriptor": {"Location": f"s3://cloud-detection-111122223333-us-east-1-analytics/datasets/{table}/{snapshot_id}/parquet/"}}}
        if (service, action) == ("athena", "start-query-execution"):
            sql = arguments[arguments.index("--query-string") + 1]
            self.started.append(sql)
            query_id = f"query-{len(self.started)}"
            self.query_counts[query_id] = (1 if "FROM synthetic_events" in sql else 0) if ") findings" in sql else 3
            return {"QueryExecutionId": query_id}
        if (service, action) == ("athena", "get-query-execution"):
            return {"QueryExecution": {"Status": {"State": "SUCCEEDED"}, "Statistics": {"DataScannedInBytes": 100}}}
        if (service, action) == ("athena", "get-query-results"):
            query_id = arguments[arguments.index("--query-execution-id") + 1]
            return {"ResultSet": {"Rows": [{"Data": [{"VarCharValue": "count"}]}, {"Data": [{"VarCharValue": str(self.query_counts[query_id])}]}]}}
        raise AssertionError(f"Unexpected AWS call: {service} {action}")

    def test_preparation_only_selects_parquet_and_keeps_tables_separate(self):
        self.assertEqual(len(self.config["snapshot_files"]), 2)
        self.assertEqual(set(self.config["datasets"]), {"security_events", "synthetic_events"})
        for item in self.config["snapshot_files"].values():
            self.assertTrue(item["relative_path"].endswith(".parquet"))
            self.assertNotIn("quarantine", item["relative_path"])
        self.assertFalse(self.config["allow_data_deletion"])

    def test_glue_column_names_and_types_match_parquet(self):
        type_map = {pa.string(): "string", pa.bool_(): "boolean", pa.timestamp("ms"): "timestamp"}
        expected = [{"name": field.name, "type": type_map[field.type]} for field in EVENT_SCHEMA]
        self.assertEqual(json.loads((self.project / "infra/analytics/columns.json").read_text()), expected)

    def test_query_checks_compare_rows_and_findings_without_exporting_identities(self):
        report = check(self.config, self.snapshots, self.call, self.sql)
        self.assertEqual(len(self.started), 4)
        self.assertEqual(report["checks"]["security_events"]["athena_rows"], 3)
        self.assertEqual(report["checks"]["security_events"]["console_login_without_mfa_findings"], 0)
        self.assertEqual(report["checks"]["synthetic_events"]["console_login_without_mfa_findings"], 1)
        self.assertNotIn("111122223333", json.dumps(report))

    def test_wrong_account_stops_before_queries(self):
        self.account = "999900001111"
        with self.assertRaisesRegex(ValueError, "account"):
            check(self.config, self.snapshots, self.call, self.sql)
        self.assertEqual(self.started, [])

    def test_changed_workgroup_limit_stops_before_queries(self):
        self.scan_limit = 1073741824
        with self.assertRaisesRegex(ValueError, "Workgroup settings"):
            check(self.config, self.snapshots, self.call, self.sql)
        self.assertEqual(self.started, [])

    def test_corrupt_local_snapshot_stops_preparation(self):
        next((self.root / "live").rglob("*.parquet")).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            prepare(self.root / "live", self.root / "synthetic", "111122223333", "us-east-1")


if __name__ == "__main__":
    unittest.main()
