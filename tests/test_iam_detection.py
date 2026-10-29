import copy
from pathlib import Path
import unittest

import duckdb

from cloud_detection.pipeline import detect, normalize


class IAMDetectionTests(unittest.TestCase):
    def setUp(self):
        self.record = {
            "eventID": "synthetic-policy-attachment", "eventTime": "2026-01-01T12:00:00Z",
            "eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy", "awsRegion": "us-east-1",
            "userIdentity": {"type": "IAMUser", "accountId": "111122223333", "arn": "arn:aws:iam::111122223333:user/operator"},
            "requestParameters": {"userName": "test-user", "policyArn": "arn:aws:iam::111122223333:policy/test-policy"},
            "responseElements": None,
        }

    def test_null_response_on_successful_iam_write_is_detected(self):
        finding = detect([normalize(self.record)])[0]
        self.assertEqual(finding["rule_id"], "iam-managed-policy-attached")
        self.assertEqual(finding["event_id"], self.record["eventID"])
        self.assertEqual(finding["principal"], self.record["userIdentity"]["arn"])

    def test_denied_reversal_and_unrelated_service_do_not_match(self):
        for patch in ({"errorCode": "AccessDenied"}, {"eventName": "DetachUserPolicy"}, {"eventSource": "sts.amazonaws.com"}):
            with self.subTest(patch=patch):
                record = copy.deepcopy(self.record)
                record.update(patch)
                self.assertEqual(detect([normalize(record)]), [])

    def test_sql_agrees_and_respects_partition_range(self):
        conn = duckdb.connect()
        conn.execute("CREATE TABLE security_events(event_id VARCHAR, event_time TIMESTAMP, account_id VARCHAR, principal VARCHAR, source_ip VARCHAR, region VARCHAR, event_date VARCHAR, event_source VARCHAR, event_name VARCHAR, outcome VARCHAR)")
        conn.execute("INSERT INTO security_events VALUES ('attach', '2026-01-01 12:00:00', '111122223333', 'operator', '192.0.2.1', 'us-east-1', '2026-01-01', 'iam.amazonaws.com', 'AttachUserPolicy', 'success'), ('denied', '2026-01-01 12:00:00', '111122223333', 'operator', '192.0.2.1', 'us-east-1', '2026-01-01', 'iam.amazonaws.com', 'AttachUserPolicy', 'failure')")
        sql = (Path(__file__).resolve().parents[1] / "sql/detections/iam_managed_policy_attached.sql").read_text()
        self.assertEqual([row[0] for row in conn.execute(sql, ['2026-01-01', '2026-01-01', 'us-east-1']).fetchall()], ['attach'])
        self.assertEqual(conn.execute(sql, ['2026-01-02', '2026-01-02', 'us-east-1']).fetchall(), [])
        conn.close()
