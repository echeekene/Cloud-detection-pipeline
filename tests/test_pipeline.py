import copy
import json
from pathlib import Path
import unittest

from cloud_detection.pipeline import detect, normalize


class PipelineTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "cloudtrail.json"
        self.records = json.loads(path.read_text(encoding="utf-8"))["Records"]

    def test_sample_only_flags_successful_login_without_mfa(self):
        findings = detect([normalize(record) for record in self.records])
        self.assertEqual([finding["event_id"] for finding in findings], ["synthetic-no-mfa"])

    def test_unknown_mfa_is_not_evidence_of_no_mfa(self):
        record = copy.deepcopy(self.records[0])
        record.pop("additionalEventData")
        event = normalize(record)
        self.assertIsNone(event["mfa_used"])
        self.assertEqual(detect([event]), [])

    def test_unrelated_api_does_not_match(self):
        record = copy.deepcopy(self.records[0])
        record["eventSource"] = "s3.amazonaws.com"
        record["eventName"] = "GetObject"
        self.assertEqual(detect([normalize(record)]), [])

    def test_error_code_overrides_success_response(self):
        record = copy.deepcopy(self.records[0])
        record["errorCode"] = "AccessDenied"
        self.assertEqual(detect([normalize(record)]), [])

    def test_timestamp_is_converted_to_utc(self):
        record = copy.deepcopy(self.records[0])
        record["eventTime"] = "2026-10-28T07:00:00-05:00"
        self.assertEqual(normalize(record)["event_time"], "2026-10-28T12:00:00Z")

    def test_invalid_or_unzoned_timestamp_rejected(self):
        for value in ("invalid", "2026-10-28T12:00:00", None):
            with self.subTest(value=value):
                record = copy.deepcopy(self.records[0])
                record["eventTime"] = value
                with self.assertRaises(ValueError):
                    normalize(record)

    def test_missing_event_id_rejected(self):
        record = copy.deepcopy(self.records[0])
        record.pop("eventID")
        with self.assertRaises(ValueError):
            normalize(record)


if __name__ == "__main__":
    unittest.main()
