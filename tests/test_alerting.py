from datetime import datetime, timezone
import json
import unittest

from cloud_detection.alerting import MAX_ALERTS, build_query, format_alarm, format_message, is_sns_event, is_startup_notice, post_slack, run
from cloud_detection.detections import RULES

NOW = datetime(2026, 10, 30, 0, 30, tzinfo=timezone.utc)
CONFIG = {"workgroup": "cloud-detection-queries", "table": "dedupe", "timeout_seconds": 5,
          "regions": ["us-east-1"], "lookback_minutes": 90}


class FakeAthena:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def start_query_execution(self, **kwargs):
        self.queries.append(kwargs)
        return {"QueryExecutionId": "q"}

    def get_query_execution(self, QueryExecutionId):
        return {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}}

    def get_query_results(self, QueryExecutionId, MaxResults):
        header = ["detection_id", "event_id", "event_time_iso", "event_source", "event_name", "principal", "source_ip", "region"]
        body = [{"Data": [{"VarCharValue": row.get(c)} for c in header]} for row in self.rows]
        return {"ResultSet": {"Rows": [{"Data": [{"VarCharValue": c} for c in header]}] + body}}


class ConditionalCheckFailedException(Exception):
    pass


class FakeDynamo:
    def __init__(self):
        self.items = {}

    def get_item(self, TableName, Key, ConsistentRead):
        key = Key["finding_key"]["S"]
        return {"Item": self.items[key]} if key in self.items else {}

    def put_item(self, TableName, Item, ConditionExpression):
        key = Item["finding_key"]["S"]
        if key in self.items:
            raise ConditionalCheckFailedException()
        self.items[key] = Item


def finding(event_id, rule="iam_access_key_created"):
    return {"detection_id": rule, "event_id": event_id, "event_time_iso": "2026-10-30T00:10:00Z",
            "event_source": "iam.amazonaws.com", "event_name": "CreateAccessKey",
            "principal": "arn:aws:iam::111122223333:user/test", "source_ip": "203.0.113.5", "region": "us-east-1"}


class AlertingTests(unittest.TestCase):
    def test_query_spans_midnight_and_uses_parameters_only(self):
        sql, parameters = build_query("us-east-1", NOW, 90)
        self.assertEqual(sql.count("?"), len(parameters))
        self.assertEqual(parameters[:4], ["'2026-10-29'", "'2026-10-30'", "'us-east-1'", "'2026-10-29T23:00:00Z'"])
        self.assertNotIn("us-east-1", sql)
        self.assertEqual(sql.count("UNION ALL"), len(RULES) - 1)
        with self.assertRaises(ValueError):
            build_query("us-east-1' OR 1=1 --", NOW, 90)

    def test_each_finding_alerts_once_across_overlapping_runs(self):
        athena, dynamo, sent = FakeAthena([finding("e1"), finding("e2")]), FakeDynamo(), []
        first = run(athena, dynamo, sent.append, CONFIG, NOW)
        second = run(athena, dynamo, sent.append, CONFIG, NOW)
        self.assertEqual((first["alerts_sent"], second["alerts_sent"], second["already_sent"]), (2, 0, 2))
        self.assertEqual(len(sent), 2)
        expires = int(dynamo.items["iam_access_key_created#e1"]["expires_at"]["N"])
        self.assertEqual(expires - int(NOW.timestamp()), 7 * 86400)

    def test_failed_delivery_is_not_recorded_so_it_retries(self):
        dynamo = FakeDynamo()

        def broken(message):
            raise RuntimeError("Slack down")
        with self.assertRaises(RuntimeError):
            run(FakeAthena([finding("e1")]), dynamo, broken, CONFIG, NOW)
        self.assertEqual(dynamo.items, {})

    def test_burst_is_capped_with_a_notice(self):
        sent = []
        result = run(FakeAthena([finding(f"e{i}") for i in range(MAX_ALERTS + 5)]), FakeDynamo(), sent.append, CONFIG, NOW)
        self.assertEqual(result["alerts_sent"], MAX_ALERTS)
        self.assertEqual(len(sent), MAX_ALERTS + 1)
        self.assertIn("More than", sent[-1]["text"])

    def test_message_carries_severity_mitre_and_runbook(self):
        text = format_message(finding("e1"))["blocks"][0]["text"]["text"]
        self.assertIn("T1098.001", text)
        self.assertIn("docs/runbooks/iam_access_key_created.md", text)
        self.assertIn("203.0.113.5", text)

    def test_only_slack_webhooks_are_accepted(self):
        calls = []

        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def opener(request, timeout):
            calls.append((request.full_url, json.loads(request.data), timeout))
            return Response()
        post_slack("https://hooks.slack.com/services/T1/B2/abc", {"text": "hi"}, opener=opener)
        self.assertEqual(calls[0][1], {"text": "hi"})
        with self.assertRaises(ValueError):
            post_slack("https://example.com/collect", {"text": "hi"}, opener=opener)
        doubled = "https://hooks.slack.com/services/T1/B2/abc" * 2
        for bad in (doubled, "https://hooks.slack.com/services/T1/B2/abc\n", "https://hooks.slack.com/services/T1/B2"):
            with self.subTest(url=bad[:60]), self.assertRaises(ValueError):
                post_slack(bad, {"text": "hi"}, opener=opener)
        self.assertEqual(len(calls), 1)


class AlarmTests(unittest.TestCase):
    def sns(self, state, old="ALARM"):
        message = {"OldStateValue": old, "AlarmName": "cloud-detection-processor-errors", "NewStateValue": state, "AlarmDescription": "Log processor Lambda errors",
                   "NewStateReason": "Threshold Crossed: 1 datapoint [2.0] was greater than the threshold (0.0).", "StateChangeTime": "2026-10-31T00:00:00Z"}
        return {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": json.dumps(message)}}]}

    def test_alarm_and_recovery_messages(self):
        alarm = format_alarm(self.sns("ALARM")["Records"][0])
        ok = format_alarm(self.sns("OK")["Records"][0])
        self.assertIn("problem detected", alarm["blocks"][0]["text"]["text"])
        self.assertIn("cloud-detection-processor-errors", alarm["text"])
        self.assertIn("recovered", ok["blocks"][0]["text"]["text"])

    def test_first_evaluation_is_not_reported_as_a_recovery(self):
        self.assertTrue(is_startup_notice(self.sns("OK", old="INSUFFICIENT_DATA")["Records"][0]))
        self.assertFalse(is_startup_notice(self.sns("OK", old="ALARM")["Records"][0]))
        self.assertFalse(is_startup_notice(self.sns("ALARM", old="INSUFFICIENT_DATA")["Records"][0]))

    def test_only_sns_records_are_treated_as_alarms(self):
        self.assertTrue(is_sns_event(self.sns("ALARM")))
        self.assertFalse(is_sns_event({"scorecard": True}))
        self.assertFalse(is_sns_event({"Records": [{"eventSource": "aws:s3"}]}))
        self.assertFalse(is_sns_event({}))


if __name__ == "__main__":
    unittest.main()
