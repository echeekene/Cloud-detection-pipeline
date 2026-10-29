import unittest

import duckdb

from cloud_detection.detections import RULES, catalog, match


def event(**overrides):
    base = {"event_id": "e", "event_source": "iam.amazonaws.com", "event_name": "ListUsers", "outcome": "success",
            "principal_type": "IAMUser", "mfa_used": None}
    base.update(overrides)
    return base


# Each rule gets events that must match and near misses that must not.
CASES = {
    "console_login_without_mfa": (
        [event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", mfa_used=False)],
        [event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", mfa_used=True),
         event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", mfa_used=None),
         event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", mfa_used=False, outcome="failure")],
    ),
    "root_account_console_login": (
        [event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", principal_type="Root", mfa_used=True)],
        [event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", principal_type="IAMUser"),
         event(event_source="signin.amazonaws.com", event_name="ConsoleLogin", principal_type="Root", outcome="failure"),
         event(event_name="ListUsers", principal_type="Root")],
    ),
    "iam_managed_policy_attached": (
        [event(event_name="AttachUserPolicy")],
        [event(event_name="DetachUserPolicy"), event(event_name="AttachUserPolicy", outcome="failure")],
    ),
    "iam_access_key_created": (
        [event(event_name="CreateAccessKey")],
        [event(event_name="DeleteAccessKey"), event(event_name="CreateAccessKey", outcome="failure"),
         event(event_source="sts.amazonaws.com", event_name="CreateAccessKey")],
    ),
    "cloudtrail_logging_disabled": (
        [event(event_source="cloudtrail.amazonaws.com", event_name="StopLogging"),
         event(event_source="cloudtrail.amazonaws.com", event_name="DeleteTrail")],
        [event(event_source="cloudtrail.amazonaws.com", event_name="StartLogging"),
         event(event_source="cloudtrail.amazonaws.com", event_name="StopLogging", outcome="failure")],
    ),
    "s3_public_access_block_removed": (
        [event(event_source="s3.amazonaws.com", event_name="DeleteBucketPublicAccessBlock"),
         event(event_source="s3.amazonaws.com", event_name="DeleteAccountPublicAccessBlock")],
        [event(event_source="s3.amazonaws.com", event_name="PutBucketPublicAccessBlock"),
         event(event_source="s3.amazonaws.com", event_name="DeleteBucketPublicAccessBlock", outcome="failure")],
    ),
}


class DetectionRuleTests(unittest.TestCase):
    def test_every_rule_has_cases_and_complete_metadata(self):
        self.assertEqual(set(CASES), set(RULES))
        for item in catalog():
            self.assertTrue(item["mitre_attack"]["id"].startswith("T"))
            self.assertIn(item["severity"], {"low", "medium", "high"})
            self.assertTrue(item["runbook"].startswith("docs/runbooks/"))
            self.assertNotIn("condition", item)

    def test_python_predicates(self):
        for rule_id, (hits, misses) in CASES.items():
            for e in hits:
                with self.subTest(rule=rule_id, event=e):
                    self.assertIn(rule_id, match(e))
            for e in misses:
                with self.subTest(rule=rule_id, event=e):
                    self.assertNotIn(rule_id, match(e))

    def test_sql_conditions_agree_with_python(self):
        conn = duckdb.connect()
        conn.execute("CREATE TABLE events(event_id VARCHAR, event_source VARCHAR, event_name VARCHAR, outcome VARCHAR, principal_type VARCHAR, mfa_used BOOLEAN)")
        rows = []
        for rule_id, (hits, misses) in CASES.items():
            for index, e in enumerate(hits + misses):
                rows.append((f"{rule_id}-{index}", e["event_source"], e["event_name"], e["outcome"], e["principal_type"], e["mfa_used"]))
        conn.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)", rows)
        by_id = {row[0]: dict(zip(("event_id", "event_source", "event_name", "outcome", "principal_type", "mfa_used"), row)) for row in rows}
        for rule_id, rule in RULES.items():
            with self.subTest(rule=rule_id):
                sql_hits = {row[0] for row in conn.execute(f"SELECT event_id FROM events WHERE {rule['condition']}").fetchall()}
                python_hits = {event_id for event_id, e in by_id.items() if rule["match"](e)}
                self.assertEqual(sql_hits, python_hits)
        conn.close()


if __name__ == "__main__":
    unittest.main()
