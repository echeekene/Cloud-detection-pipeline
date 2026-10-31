import unittest

from scripts.plan_fingerprint import changes, fingerprint


def plan(*items):
    return {"resource_changes": [{"address": a, "change": {"actions": actions}} for a, actions in items]}


class PlanFingerprintTests(unittest.TestCase):
    def test_unchanged_and_read_only_resources_are_ignored(self):
        self.assertEqual(changes(plan(("aws_sns_topic.health", ["no-op"]), ("data.aws_apigatewayv2_apis.findings", ["read"]))), [])
        self.assertEqual(fingerprint(plan()), fingerprint(plan(("aws_sns_topic.health", ["no-op"]))))

    def test_order_does_not_matter_but_actions_do(self):
        a = plan(("aws_lambda_function.api", ["update"]), ("aws_iam_role.api", ["create"]))
        b = plan(("aws_iam_role.api", ["create"]), ("aws_lambda_function.api", ["update"]))
        self.assertEqual(fingerprint(a), fingerprint(b))
        replaced = plan(("aws_lambda_function.api", ["delete", "create"]), ("aws_iam_role.api", ["create"]))
        self.assertNotEqual(fingerprint(a), fingerprint(replaced))


if __name__ == "__main__":
    unittest.main()
