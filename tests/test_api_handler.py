from datetime import date
import json
import unittest

from cloud_detection.api_handler import (DETECTIONS, MAX_LIMIT, RequestError, build_events_query,
                                         build_findings_query, route, run_query)

TODAY = date(2026, 10, 29)
BASE = {"start": "2026-10-20", "end": "2026-10-28", "region": "us-east-1"}
CONFIG = {"workgroup": "cloud-detection-queries", "timeout_seconds": 5}


class FakeAthena:
    def __init__(self, states=("SUCCEEDED",), rows=None):
        self.states = list(states)
        self.rows = rows if rows is not None else []
        self.started, self.stopped = [], []

    def start_query_execution(self, **kwargs):
        self.started.append(kwargs)
        return {"QueryExecutionId": "q-1"}

    def get_query_execution(self, QueryExecutionId):
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"QueryExecution": {"Status": {"State": state, "StateChangeReason": "internal detail"}}}

    def stop_query_execution(self, QueryExecutionId):
        self.stopped.append(QueryExecutionId)

    def get_query_results(self, QueryExecutionId, MaxResults):
        header = {"Data": [{"VarCharValue": "event_id"}, {"VarCharValue": "mfa_used"}]}
        body = [{"Data": [{"VarCharValue": f"e{i}"}, {"VarCharValue": "false"}]} for i in range(self.rows_count)]
        return {"ResultSet": {"Rows": ([header] + body)[:MaxResults]}}

    @property
    def rows_count(self):
        return len(self.rows) if isinstance(self.rows, list) else self.rows


def event(path, params=None):
    return {"routeKey": f"GET {path}", "queryStringParameters": params}


class QueryBuildingTests(unittest.TestCase):
    def test_findings_query_uses_parameters_not_user_text(self):
        sql, parameters, window, limit = build_findings_query({**BASE, "dataset": "live"}, TODAY)
        self.assertIn("FROM security_events", sql)
        self.assertNotIn("2026-10-20", sql)
        self.assertNotIn("us-east-1", sql)
        self.assertEqual(sql.count("?"), len(parameters))
        self.assertEqual(parameters[:3], ["'2026-10-20'", "'2026-10-28'", "'us-east-1'"])
        self.assertEqual(len(parameters), 3 * len(DETECTIONS))
        self.assertEqual(limit, 50)

    def test_single_detection_and_default_dataset(self):
        sql, parameters, window, _ = build_findings_query({**BASE, "detection": "iam_managed_policy_attached"}, TODAY)
        self.assertEqual(window["dataset"], "automated")
        self.assertIn("FROM automated_events", sql)
        self.assertIn("AttachUserPolicy", sql)
        self.assertNotIn("ConsoleLogin", sql)
        self.assertEqual(len(parameters), 3)

    def test_event_filters_are_parameterized(self):
        params = {**BASE, "principal": "arn:aws:iam::111122223333:user/test-user", "source_ip": "203.0.113.10",
                  "event_name": "AttachUserPolicy", "outcome": "success", "limit": "10"}
        sql, parameters, _, limit = build_events_query(params, TODAY)
        self.assertNotIn("test-user", sql)
        self.assertNotIn("203.0.113.10", sql)
        self.assertEqual(sql.count("?"), len(parameters))
        self.assertIn("'arn:aws:iam::111122223333:user/test-user'", parameters)
        self.assertEqual(limit, 10)

    def test_injection_attempts_are_rejected(self):
        attempts = [
            {"principal": "x' OR '1'='1"}, {"principal": "a;DROP TABLE security_events"},
            {"event_name": "ConsoleLogin' --"}, {"source_ip": "1.2.3.4' OR 1=1"},
            {"region": "us-east-1' OR 'a'='a"}, {"dataset": "security_events; --"},
            {"outcome": "success' OR 'x'='x"}, {"start": "2026-10-20' --"},
        ]
        for attempt in attempts:
            with self.subTest(attempt=attempt), self.assertRaises(RequestError) as caught:
                build_events_query({**BASE, **attempt}, TODAY)
            self.assertEqual(caught.exception.status, 400)

    def test_window_and_limit_bounds(self):
        bad = [
            {"start": "2026-10-28", "end": "2026-10-20"}, {"start": "2026-09-01", "end": "2026-10-28"},
            {"start": "2019-12-31", "end": "2020-01-01"}, {"end": "2026-11-05"}, {"start": "2026-02-30"},
            {"region": None}, {"limit": "0"}, {"limit": str(MAX_LIMIT + 1)}, {"limit": "abc"},
            {"detection": "unknown_rule"}, {"unexpected": "1"},
        ]
        for change in bad:
            params = {k: v for k, v in {**BASE, **change}.items() if v is not None}
            with self.subTest(change=change), self.assertRaises(RequestError):
                build_findings_query(params, TODAY)

    def test_ipv6_is_normalized(self):
        _, parameters, _, _ = build_events_query({**BASE, "source_ip": "2001:DB8::0:1"}, TODAY)
        self.assertIn("'2001:db8::1'", parameters)


class ExecutionTests(unittest.TestCase):
    def test_success_converts_rows_and_reports_truncation(self):
        athena = FakeAthena(rows=5)
        items, truncated, execution_id = run_query(athena, "SELECT 1", [], 3, CONFIG, sleep=lambda _: None)
        self.assertEqual(len(items), 3)
        self.assertTrue(truncated)
        self.assertIs(items[0]["mfa_used"], False)
        self.assertEqual(athena.started[0]["WorkGroup"], "cloud-detection-queries")
        self.assertEqual(athena.started[0]["QueryExecutionContext"], {"Database": "cloud_detection"})

    def test_timeout_stops_the_query(self):
        athena = FakeAthena(states=("RUNNING",))
        now = [0.0]

        def sleep(seconds):
            now[0] += seconds
        with self.assertRaises(RequestError) as caught:
            run_query(athena, "SELECT 1", [], 5, CONFIG, clock=lambda: now[0], sleep=sleep)
        self.assertEqual(caught.exception.status, 504)
        self.assertEqual(athena.stopped, ["q-1"])

    def test_failed_query_hides_internal_reason(self):
        athena = FakeAthena(states=("FAILED",))
        with self.assertRaises(RequestError) as caught:
            run_query(athena, "SELECT 1", [], 5, CONFIG, sleep=lambda _: None)
        self.assertEqual(caught.exception.status, 502)
        self.assertNotIn("internal", caught.exception.message)


class RoutingTests(unittest.TestCase):
    def test_detections_catalog_has_mitre_mapping(self):
        response = route(event("/detections"), FakeAthena(), CONFIG, TODAY)
        body = json.loads(response["body"])
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual({d["id"] for d in body["detections"]}, set(DETECTIONS))
        self.assertTrue(all(d["mitre_attack"]["id"].startswith("T") for d in body["detections"]))
        self.assertNotIn("condition", body["detections"][0])
        self.assertEqual(response["headers"]["cache-control"], "no-store")

    def test_findings_route_returns_window_and_items(self):
        response = route(event("/findings", dict(BASE)), FakeAthena(rows=2), CONFIG, TODAY)
        body = json.loads(response["body"])
        self.assertEqual((body["count"], body["truncated"], body["region"]), (2, False, "us-east-1"))

    def test_unknown_route(self):
        with self.assertRaises(RequestError) as caught:
            route({"routeKey": "POST /findings"}, FakeAthena(), CONFIG, TODAY)
        self.assertEqual(caught.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
