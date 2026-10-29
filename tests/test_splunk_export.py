import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from cloud_detection.dataset import build_dataset
from cloud_detection.splunk_export import export_snapshot


class SplunkExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = Path(__file__).resolve().parents[1]
        self.snapshot = self.root / "snapshot"
        build_dataset([self.project / "examples/cloudtrail.json"], self.snapshot)
        self.output = self.root / "events.ndjson"

    def test_export_keeps_mfa_boolean_and_sample_labels(self):
        result = export_snapshot(self.snapshot, self.output, "synthetic")
        events = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertEqual(result["events_exported"], 3)
        self.assertTrue(all(event["sample_kind"] == "synthetic" and event["project"] == "cloud_detection" for event in events))
        indexed = {event["event_id"]: event for event in events}
        self.assertIs(indexed["synthetic-no-mfa"]["mfa_used"], False)
        self.assertIs(indexed["synthetic-with-mfa"]["mfa_used"], True)
        self.assertEqual(indexed["synthetic-no-mfa"]["event_time"], "2026-10-28T12:00:00Z")
        self.assertTrue(all(event["region"] == "us-east-1" for event in events))

    def test_missing_mfa_stays_null(self):
        source = json.loads((self.project / "examples/cloudtrail.json").read_text())
        source["Records"][0].pop("additionalEventData")
        path = self.root / "unknown.json"
        path.write_text(json.dumps(source))
        build_dataset([path], self.root / "unknown")
        export_snapshot(self.root / "unknown", self.output, "synthetic")
        event = next(json.loads(line) for line in self.output.read_text().splitlines() if json.loads(line)["event_id"] == "synthetic-no-mfa")
        self.assertIsNone(event["mfa_used"])

    def test_existing_export_is_not_overwritten(self):
        self.output.write_text("keep this")
        with self.assertRaisesRegex(ValueError, "already exists"):
            export_snapshot(self.snapshot, self.output, "synthetic")
        self.assertEqual(self.output.read_text(), "keep this")

    def test_unknown_sample_kind_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "live or synthetic"):
            export_snapshot(self.snapshot, self.output, "unknown")
        self.assertFalse(self.output.exists())

    def test_export_cannot_modify_snapshot_contents(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            export_snapshot(self.snapshot, self.snapshot / "events.ndjson", "synthetic")

    def test_dashboard_is_valid_xml_and_labels_synthetic_findings(self):
        dashboard = ET.parse(self.project / "splunk/dashboards/cloud_detection_lab.xml").getroot()
        self.assertEqual(dashboard.tag, "dashboard")
        self.assertEqual(dashboard.find("search/earliest").text, "0")
        self.assertIn("Synthetic logins without MFA", [title.text for title in dashboard.findall(".//title")])


if __name__ == "__main__":
    unittest.main()
