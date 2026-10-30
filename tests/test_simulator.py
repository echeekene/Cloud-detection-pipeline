from datetime import datetime, timezone
import unittest
from unittest import mock

from cloud_detection import alerting
from cloud_detection.alerting import format_message, is_simulation, mark_detected, run, scorecard
from cloud_detection.detections import RULES
from cloud_detection.simulator import SCENARIOS, simulate

CONFIG = {"table": "sims", "canary_user": "cloud-detection-canary", "canary_policy_arn": "arn:aws:iam::111122223333:policy/cloud-detection-canary-deny-all",
          "canary_bucket": "canary-bucket", "trail": "cloud-detection-audit"}
SIM_ROLE = "cloud-detection-attack-simulator"


class Recorder:
    """Fake boto3 client that records calls and can fail on a named one."""

    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append(name)
            if name == self.fail_on:
                raise RuntimeError("simulated AWS failure")
            if name == "create_access_key":
                return {"AccessKey": {"AccessKeyId": "AKIAEXAMPLE"}}
            return {}
        return call


class FakeTable:
    """In-memory DynamoDB with one store per table name; `items` is the simulations table."""

    def __init__(self):
        self.tables = {}

    @property
    def items(self):
        return self.tables.setdefault("sims", {})

    def _table(self, name):
        return self.tables.setdefault(name, {})

    def put_item(self, TableName, Item, **kwargs):
        self._table(TableName)[Item.get("sim_id", Item.get("finding_key"))["S"]] = dict(Item)

    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None):
        item = self._table(TableName)[Key["sim_id"]["S"]]
        for part in UpdateExpression.removeprefix("SET ").split(", "):
            field, value = part.split(" = ")
            field = (ExpressionAttributeNames or {}).get(field, field)
            item[field] = ExpressionAttributeValues[value]

    def scan(self, TableName, FilterExpression, ExpressionAttributeValues, **kwargs):
        items = list(self._table(TableName).values())
        if "rule_id" in FilterExpression:
            items = [i for i in items if i["rule_id"] == ExpressionAttributeValues[":r"] and "detected_at" not in i]
        if "started_at >=" in FilterExpression:
            items = [i for i in items if int(i["started_at"]["N"]) >= int(ExpressionAttributeValues[":s"]["N"])]
        return {"Items": items}

    def get_item(self, TableName, Key, ConsistentRead):
        key = Key["finding_key"]["S"]
        return {"Item": self._table(TableName)[key]} if key in self._table(TableName) else {}


def clients(fail_on=None):
    recorder = Recorder(fail_on)
    return {"iam": recorder, "s3": recorder, "cloudtrail": recorder}, recorder


class SimulatorTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("cloud_detection.simulator.time.sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_scenario_targets_a_real_rule_and_restores(self):
        restores = {"access_key": "delete_access_key", "attach_policy": "detach_user_policy",
                    "public_access_block": "put_public_access_block", "trail_stop": "start_logging"}
        self.assertEqual(set(restores), set(SCENARIOS))
        for name, (rule_id, _) in SCENARIOS.items():
            with self.subTest(scenario=name):
                self.assertIn(rule_id, RULES)
                table, (c, recorder) = FakeTable(), clients()
                result = simulate(name, c, table, CONFIG, clock=lambda: 1_800_000_000)
                self.assertEqual(result["status"], "completed")
                self.assertEqual(recorder.calls[-1], restores[name])
                record = table.items[result["sim_id"]]
                self.assertEqual((record["status"]["S"], record["rule_id"]["S"]), ("completed", rule_id))
                self.assertEqual(int(record["expires_at"]["N"]) - 1_800_000_000, 30 * 86400)

    def test_restore_runs_even_when_the_pause_step_fails(self):
        table = FakeTable()
        c, recorder = clients()
        with mock.patch("cloud_detection.simulator.time.sleep", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                simulate("trail_stop", c, table, CONFIG)
        self.assertEqual(recorder.calls, ["stop_logging", "start_logging"])
        self.assertEqual(next(iter(table.items.values()))["status"]["S"], "failed")

    def test_failed_action_is_recorded_and_raised(self):
        table, (c, _) = FakeTable(), clients(fail_on="create_access_key")
        with self.assertRaises(RuntimeError):
            simulate("access_key", c, table, CONFIG)
        record = next(iter(table.items.values()))
        self.assertEqual((record["status"]["S"], record["error_type"]["S"]), ("failed", "RuntimeError"))

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            simulate("delete_everything", clients()[0], FakeTable(), CONFIG)


def sim(sim_id, rule, started, detected=None, status="completed"):
    item = {"sim_id": {"S": sim_id}, "scenario": {"S": rule}, "rule_id": {"S": rule},
            "started_at": {"N": str(started)}, "status": {"S": status}}
    if detected:
        item["detected_at"] = {"N": str(detected)}
    return item


class ScoringTests(unittest.TestCase):
    NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)

    def test_simulations_are_recognized_and_labeled(self):
        finding = {"detection_id": "iam_access_key_created", "principal": f"arn:aws:sts::111122223333:assumed-role/{SIM_ROLE}/run",
                   "event_time_iso": "2026-10-31T11:00:00Z", "event_id": "e1"}
        self.assertTrue(is_simulation(finding, SIM_ROLE))
        self.assertFalse(is_simulation({**finding, "principal": "arn:aws:iam::111122223333:user/attacker"}, SIM_ROLE))
        self.assertFalse(is_simulation(finding, ""))
        self.assertTrue(format_message(finding, simulation=True)["text"].startswith("[SIMULATION]"))

    def test_detection_links_to_the_nearest_matching_simulation(self):
        table = FakeTable()
        event_at = int(datetime(2026, 10, 31, 11, 0, tzinfo=timezone.utc).timestamp())
        for item in (sim("far", "iam_access_key_created", event_at - 7200), sim("near", "iam_access_key_created", event_at - 30),
                     sim("other", "cloudtrail_logging_disabled", event_at - 30)):
            table.put_item("sims", item)
        finding = {"detection_id": "iam_access_key_created", "event_time_iso": "2026-10-31T11:00:00Z", "event_id": "e1"}
        self.assertEqual(mark_detected(table, "sims", finding, self.NOW), "near")
        self.assertIn("detected_at", table.items["near"])
        self.assertNotIn("detected_at", table.items["far"])

    def test_scorecard_counts_caught_missed_pending_and_failed(self):
        table, now = FakeTable(), int(self.NOW.timestamp())
        for item in (sim("a", "access_key", now - 5000, detected=now - 5000 + 600), sim("b", "trail_stop", now - 4000, detected=now - 4000 + 1200),
                     sim("c", "attach_policy", now - 7200), sim("d", "access_key", now - 600), sim("e", "access_key", now - 3000, status="failed"),
                     sim("old", "access_key", now - 3 * 86400)):
            table.put_item("sims", item)
        message, summary = scorecard(table, "sims", self.NOW)
        self.assertEqual(summary, {"detected": 2, "missed": 1, "pending": 1, "failed": 1, "median_minutes": 20})
        self.assertIn("2 of 3", message["text"])
        self.assertIn("attach_policy", message["text"])

    def test_alert_run_marks_simulations_detected(self):
        table = FakeTable()
        table.put_item("sims", sim("s1", "iam_access_key_created", int(datetime(2026, 10, 31, 11, 0, tzinfo=timezone.utc).timestamp())))

        class Athena:
            def start_query_execution(self, **kw): return {"QueryExecutionId": "q"}
            def get_query_execution(self, **kw): return {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}}
            def get_query_results(self, **kw):
                header = ["detection_id", "event_id", "event_time_iso", "principal"]
                row = ["iam_access_key_created", "e1", "2026-10-31T11:00:05Z", f"arn:aws:sts::111122223333:assumed-role/{SIM_ROLE}/x"]
                return {"ResultSet": {"Rows": [{"Data": [{"VarCharValue": v} for v in header]}, {"Data": [{"VarCharValue": v} for v in row]}]}}
        sent = []
        config = {"workgroup": "w", "table": "dedupe", "timeout_seconds": 5, "regions": ["us-east-1"], "lookback_minutes": 90,
                  "simulator_role": SIM_ROLE, "simulations_table": "sims"}
        run(Athena(), table, sent.append, config, self.NOW)
        self.assertTrue(sent[0]["text"].startswith("[SIMULATION]"))
        self.assertIn("detected_at", table.items["s1"])


if __name__ == "__main__":
    unittest.main()
