"""Summarize a Terraform plan (from `terraform show -json`) as a stable fingerprint.

CI plans once for review and again inside the approved deploy job. The deploy job applies only
if both plans would change the same resources in the same way, so what gets applied is what
was approved.
"""

import hashlib
import json
import sys


def changes(plan):
    """Sorted (address, actions) pairs for every resource the plan would change."""
    found = []
    for change in plan.get("resource_changes", []):
        actions = change.get("change", {}).get("actions", [])
        if actions and actions != ["no-op"] and actions != ["read"]:
            found.append((change["address"], "+".join(actions)))
    return sorted(found)


def fingerprint(plan):
    return hashlib.sha256(json.dumps(changes(plan)).encode()).hexdigest()


def main():
    plan = json.load(sys.stdin)
    for address, action in changes(plan):
        print(f"{action}\t{address}", file=sys.stderr)
    print(fingerprint(plan))


if __name__ == "__main__":
    main()
