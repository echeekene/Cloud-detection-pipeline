from pathlib import Path
import unittest

from cloud_detection.detections import RULES

ROOT = Path(__file__).resolve().parents[1]


class RunbookTests(unittest.TestCase):
    def test_every_rule_has_a_runbook_with_triage_steps(self):
        for rule_id, rule in RULES.items():
            with self.subTest(rule=rule_id):
                text = (ROOT / rule["runbook"]).read_text()
                self.assertIn("## Triage", text)
                self.assertIn(rule["mitre_attack"]["id"], text)
