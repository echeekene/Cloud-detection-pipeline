"""Single source of truth for detection rules used by the API and the scheduled runner.

Each rule has a SQL condition over the normalized event columns and an equivalent Python
predicate. Tests run both against the same fixtures so the two can never drift apart.
Conditions are constants written here; no request or event value is ever inserted into them.
"""

RULES = {
    "console_login_without_mfa": {
        "name": "Console login without MFA",
        "description": "Successful AWS console login where CloudTrail explicitly records that MFA was not used.",
        "mitre_attack": {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
        "severity": "medium",
        "condition": "event_source = 'signin.amazonaws.com' AND event_name = 'ConsoleLogin' AND outcome = 'success' AND mfa_used = FALSE",
        "match": lambda e: e["event_source"] == "signin.amazonaws.com" and e["event_name"] == "ConsoleLogin"
        and e["outcome"] == "success" and e["mfa_used"] is False,
        "runbook": "docs/runbooks/console_login_without_mfa.md",
    },
    "root_account_console_login": {
        "name": "Root account console login",
        "description": "Successful console sign-in by the account root user, which should be rare and planned.",
        "mitre_attack": {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
        "severity": "high",
        "condition": "event_source = 'signin.amazonaws.com' AND event_name = 'ConsoleLogin' AND outcome = 'success' AND principal_type = 'Root'",
        "match": lambda e: e["event_source"] == "signin.amazonaws.com" and e["event_name"] == "ConsoleLogin"
        and e["outcome"] == "success" and e["principal_type"] == "Root",
        "runbook": "docs/runbooks/root_account_console_login.md",
    },
    "iam_managed_policy_attached": {
        "name": "Managed policy attached to IAM user",
        "description": "Successful AttachUserPolicy call. Requires investigation; the rule does not judge whether the permissions are excessive.",
        "mitre_attack": {"id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles"},
        "severity": "medium",
        "condition": "event_source = 'iam.amazonaws.com' AND event_name = 'AttachUserPolicy' AND outcome = 'success'",
        "match": lambda e: e["event_source"] == "iam.amazonaws.com" and e["event_name"] == "AttachUserPolicy"
        and e["outcome"] == "success",
        "runbook": "docs/runbooks/iam_managed_policy_attached.md",
    },
    "iam_access_key_created": {
        "name": "IAM access key created",
        "description": "A new long-lived access key was created for an IAM user.",
        "mitre_attack": {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"},
        "severity": "medium",
        "condition": "event_source = 'iam.amazonaws.com' AND event_name = 'CreateAccessKey' AND outcome = 'success'",
        "match": lambda e: e["event_source"] == "iam.amazonaws.com" and e["event_name"] == "CreateAccessKey"
        and e["outcome"] == "success",
        "runbook": "docs/runbooks/iam_access_key_created.md",
    },
    "cloudtrail_logging_disabled": {
        "name": "CloudTrail logging stopped or trail deleted",
        "description": "A trail was stopped or deleted, which can hide later activity.",
        "mitre_attack": {"id": "T1562.008", "name": "Impair Defenses: Disable or Modify Cloud Logs"},
        "severity": "high",
        "condition": "event_source = 'cloudtrail.amazonaws.com' AND event_name IN ('StopLogging', 'DeleteTrail') AND outcome = 'success'",
        "match": lambda e: e["event_source"] == "cloudtrail.amazonaws.com" and e["event_name"] in ("StopLogging", "DeleteTrail")
        and e["outcome"] == "success",
        "runbook": "docs/runbooks/cloudtrail_logging_disabled.md",
    },
    "s3_public_access_block_removed": {
        "name": "S3 public access block removed",
        "description": "A bucket or account public access block was deleted, a common step before exposing data publicly.",
        "mitre_attack": {"id": "T1530", "name": "Data from Cloud Storage"},
        "severity": "high",
        "condition": "event_source = 's3.amazonaws.com' AND event_name IN ('DeleteBucketPublicAccessBlock', 'DeleteAccountPublicAccessBlock') AND outcome = 'success'",
        "match": lambda e: e["event_source"] == "s3.amazonaws.com"
        and e["event_name"] in ("DeleteBucketPublicAccessBlock", "DeleteAccountPublicAccessBlock") and e["outcome"] == "success",
        "runbook": "docs/runbooks/s3_public_access_block_removed.md",
    },
}

PUBLIC_FIELDS = ("name", "description", "mitre_attack", "severity", "runbook")


def catalog():
    """Rule metadata safe to return from the API."""
    return [{"id": rule_id, **{key: rule[key] for key in PUBLIC_FIELDS}} for rule_id, rule in RULES.items()]


def match(event):
    """Return the IDs of every rule a normalized event matches."""
    return [rule_id for rule_id, rule in RULES.items() if rule["match"](event)]
