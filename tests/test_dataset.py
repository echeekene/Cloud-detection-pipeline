import copy
from contextlib import redirect_stdout
from datetime import datetime
import gzip
import json
import io
from pathlib import Path
import tempfile
import unittest

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from cloud_detection.__main__ import main
from cloud_detection.dataset import build_dataset
from cloud_detection.pipeline import detect, normalize


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        self.input.mkdir()
        self.output = self.root / "snapshot"
        example = Path(__file__).resolve().parents[1] / "examples" / "cloudtrail.json"
        self.records = json.loads(example.read_text(encoding="utf-8"))["Records"]

    def write(self, name, records):
        data = json.dumps({"Records": records}).encode()
        path = self.input / name
        path.write_bytes(gzip.compress(data) if name.endswith(".gz") else data)
        return path

    def run_dataset(self, **kwargs):
        return build_dataset([self.input], self.output, **kwargs)

    def rows(self):
        return [row for path in self.output.rglob("*.parquet") for row in pq.ParquetFile(path).read().to_pylist()]

    def test_gzip_parquet_round_trip_and_null_semantics(self):
        records = copy.deepcopy(self.records)
        records[1].pop("additionalEventData")
        self.write("events.json.gz", records)
        manifest = self.run_dataset()
        self.assertEqual((manifest["records_seen"], manifest["accepted_records"], manifest["partitions"]), (3, 3, 1))
        self.assertTrue((self.output / "_SUCCESS").is_file())
        rows = {row["event_id"]: row for row in self.rows()}
        self.assertIsNone(rows["synthetic-with-mfa"]["mfa_used"])
        self.assertIs(rows["synthetic-no-mfa"]["mfa_used"], False)
        parquet = next(self.output.rglob("*.parquet"))
        self.assertEqual(pq.ParquetFile(parquet).schema_arrow.field("event_time").type, pa.timestamp("ms"))
        self.assertEqual(pq.ParquetFile(parquet).metadata.row_group(0).column(0).compression, "SNAPPY")

    def test_utc_partitioning_and_fractional_precision(self):
        record = copy.deepcopy(self.records[0])
        record["eventTime"] = "2026-10-28T23:30:00.123456-05:00"
        self.write("events.json", [record])
        self.run_dataset()
        parquet = next(self.output.rglob("*.parquet"))
        self.assertEqual(parquet.parent.parent.name, "event_date=2026-10-29")
        row = self.rows()[0]
        self.assertEqual(row["event_time"], datetime(2026, 10, 29, 4, 30, 0, 123000))
        self.assertEqual(row["event_time_iso"], "2026-10-29T04:30:00.123456Z")

    def test_duplicate_records_across_plain_and_gzip_files(self):
        self.write("first.json", self.records)
        self.write("second.json.gz", self.records)
        manifest = self.run_dataset()
        self.assertEqual((manifest["accepted_records"], manifest["duplicate_records"], len(self.rows())), (3, 3, 3))

    def test_same_identity_with_conflicting_content_quarantines_every_copy(self):
        original = copy.deepcopy(self.records[0])
        changed = copy.deepcopy(original)
        changed["additionalEventData"]["MFAUsed"] = "Yes"
        self.write("first.json", [original, original])
        self.write("second.json", [changed, self.records[1]])
        manifest = self.run_dataset()
        self.assertEqual((manifest["accepted_records"], manifest["duplicate_records"], manifest["conflicting_records"], manifest["quarantined_records"]), (1, 0, 3, 3))
        self.assertEqual(self.rows()[0]["event_id"], "synthetic-with-mfa")
        quarantine = (self.output / "quarantine" / "records.jsonl").read_text()
        self.assertEqual(len(quarantine.splitlines()), 3)

    def test_same_event_id_in_different_accounts_stays_distinct(self):
        first, second = copy.deepcopy(self.records[0]), copy.deepcopy(self.records[0])
        first["recipientAccountId"] = "111122223333"
        second["recipientAccountId"] = "444455556666"
        self.write("events.json", [first, second])
        self.assertEqual(self.run_dataset()["accepted_records"], 2)

    def test_bad_records_do_not_discard_valid_neighbors(self):
        malformed = copy.deepcopy(self.records[0])
        malformed["userIdentity"] = []
        unsafe = copy.deepcopy(self.records[0])
        unsafe["awsRegion"] = "../../escape"
        self.write("events.json", [None, malformed, unsafe, self.records[1]])
        manifest = self.run_dataset()
        self.assertEqual((manifest["accepted_records"], manifest["quarantined_records"]), (1, 3))
        self.assertEqual(manifest["records_seen"], manifest["accepted_records"] + manifest["duplicate_records"] + manifest["quarantined_records"])

    def test_invalid_documents_are_counted_separately(self):
        (self.input / "bad.json").write_text("not json")
        (self.input / "bad.json.gz").write_bytes(b"not gzip")
        (self.input / "wrong.json").write_text('{"Records":null}')
        self.write("good.json", self.records)
        manifest = self.run_dataset()
        self.assertEqual((manifest["failed_documents"], manifest["records_seen"], manifest["accepted_records"]), (3, 3, 3))

    def test_decompression_limit_quarantines_document(self):
        (self.input / "oversized.json.gz").write_bytes(gzip.compress(b" " * 5000))
        manifest = self.run_dataset(document_limit=1000)
        self.assertEqual((manifest["failed_documents"], manifest["accepted_records"]), (1, 0))
        self.assertIn("decompressed_document_exceeds_limit", (self.output / "quarantine" / "records.jsonl").read_text())

    def test_total_limit_failure_does_not_publish_partial_snapshot(self):
        self.write("events.json", self.records)
        with self.assertRaisesRegex(ValueError, "total decompressed"):
            self.run_dataset(total_limit=10)
        self.assertFalse(self.output.exists())

    def test_exact_replay_reuses_snapshot_and_checks_file_integrity(self):
        self.write("events.json", self.records)
        first = self.run_dataset()
        replay = self.run_dataset()
        self.assertFalse(first["reused"])
        self.assertTrue(replay["reused"])
        self.assertEqual(first["input_fingerprint"], replay["input_fingerprint"])
        next(self.output.rglob("*.parquet")).write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.run_dataset()

    def test_changed_input_cannot_overwrite_existing_snapshot(self):
        self.write("events.json", self.records)
        self.run_dataset()
        self.write("events.json", self.records[:1])
        with self.assertRaisesRegex(ValueError, "different inputs"):
            self.run_dataset()
        self.assertEqual(len(self.rows()), 3)

    def test_incomplete_output_cannot_be_reused(self):
        self.write("events.json", self.records)
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.run_dataset()

    def test_replay_rejects_tampered_manifest(self):
        self.write("events.json", self.records)
        self.run_dataset()
        path = self.output / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["accepted_records"] = 999
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "manifest failed"):
            self.run_dataset()

    def test_replay_rejects_unlisted_parquet_files(self):
        self.write("events.json", self.records)
        self.run_dataset()
        path = next(self.output.rglob("*.parquet"))
        path.with_name("extra.parquet").write_bytes(path.read_bytes())
        with self.assertRaisesRegex(ValueError, "unexpected Parquet"):
            self.run_dataset()

    def test_unsupported_precision_and_utc_overflow_are_quarantined(self):
        for value in ("2026-10-28T12:00:00.1234567Z", "0001-01-01T00:00:00+01:00"):
            record = copy.deepcopy(self.records[0])
            record["eventTime"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize(record)

    def test_output_inside_input_is_rejected(self):
        self.write("events.json", self.records)
        with self.assertRaisesRegex(ValueError, "outside input"):
            build_dataset([self.input], self.input / "dataset")

    def test_console_outcome_and_api_error_semantics(self):
        record = copy.deepcopy(self.records[0])
        record["responseElements"] = None
        self.assertEqual(normalize(record)["outcome"], "unknown")
        record["eventSource"] = "s3.amazonaws.com"
        record["eventName"] = "GetBucketVersioning"
        self.assertEqual(normalize(record)["outcome"], "success")
        self.assertIsNone(normalize(record)["mfa_used"])
        record["errorCode"] = "AccessDenied"
        self.assertEqual(normalize(record)["outcome"], "failure")

    def test_sql_reads_actual_parquet_and_matches_python_detection(self):
        records = copy.deepcopy(self.records)
        unknown = copy.deepcopy(records[0])
        unknown["eventID"] = "synthetic-unknown-mfa"
        unknown.pop("additionalEventData")
        records.append(unknown)
        self.write("events.json.gz", records)
        self.run_dataset()
        glob = (self.output / "parquet" / "**" / "*.parquet").as_posix().replace("'", "''")
        with duckdb.connect() as connection:
            connection.execute(f"CREATE VIEW security_events AS SELECT * FROM read_parquet('{glob}', hive_partitioning=true, hive_types={{'event_date':VARCHAR,'region':VARCHAR}})")
            sql_path = Path(__file__).resolve().parents[1] / "sql" / "detections" / "console_login_without_mfa.sql"
            cursor = connection.execute(sql_path.read_text(), ["2026-10-28", "2026-10-28", "us-east-1"])
            rows = cursor.fetchall()
            event_id_index = [item[0] for item in cursor.description].index("event_id")
            sql_ids = sorted(row[event_id_index] for row in rows)
            python_ids = sorted(item["event_id"] for item in detect([normalize(record) for record in records]))
            self.assertEqual(sql_ids, python_ids)
            self.assertEqual(sql_ids, ["synthetic-no-mfa"])
            self.assertEqual(connection.execute(sql_path.read_text(), ["2026-10-29", "2026-10-29", "us-east-1"]).fetchall(), [])

    def test_cli_returns_nonzero_for_completed_snapshot_with_rejects(self):
        self.write("events.json", [None, self.records[0]])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["etl", "--input", str(self.input), "--output", str(self.output)]), 2)
        self.assertTrue((self.output / "_SUCCESS").is_file())


if __name__ == "__main__":
    unittest.main()
