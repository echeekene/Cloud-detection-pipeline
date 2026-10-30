"""Scheduled detection runner: query recent automated events, alert Slack once per finding.

EventBridge invokes ``handler`` every 15 minutes. Each run looks back further than the
schedule interval because CloudTrail delivers files up to about 15 minutes late; a
DynamoDB record per (rule, event) makes the overlap harmless. Delivery is at least once:
a finding is recorded only after Slack accepts it, so a crash in between can repeat one
alert but never drop it.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import re
import urllib.request

from .athena import QueryError, literal, run_query
from .detections import RULES

TABLE = "automated_events"
COLUMNS = "event_id, event_time_iso, event_source, event_name, account_id, principal, source_ip, outcome, region"
MAX_ALERTS = 20
DEDUPE_DAYS = 7
REPO_URL = "https://github.com/echeekene/Cloud-detection-pipeline/blob/main/"
REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-\d+")
SEVERITY_MARK = {"high": ":red_circle:", "medium": ":large_orange_circle:", "low": ":white_circle:"}


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_query(region, now, lookback_minutes):
    """One UNION ALL query across every rule for one region. Values are execution parameters."""
    if not REGION.fullmatch(region):
        raise ValueError("invalid region")
    since = now - timedelta(minutes=lookback_minutes)
    dates = sorted({since.date().isoformat(), now.date().isoformat()})
    parts, parameters = [], []
    for rule_id, rule in RULES.items():
        parts.append(f"SELECT '{rule_id}' AS detection_id, {COLUMNS} FROM {TABLE} "
                     f"WHERE event_date BETWEEN ? AND ? AND region = ? AND event_time_iso >= ? AND {rule['condition']}")
        parameters += [literal(dates[0]), literal(dates[-1]), literal(region), literal(iso(since))]
    return " UNION ALL ".join(parts) + " ORDER BY event_time_iso", parameters


def format_message(finding):
    rule = RULES[finding["detection_id"]]
    mitre = rule["mitre_attack"]
    mark = SEVERITY_MARK.get(rule["severity"], "")
    lines = [
        f"{mark} *{rule['name']}* ({rule['severity']})",
        f"*Event:* `{finding.get('event_name')}` from `{finding.get('event_source')}` at {finding.get('event_time_iso')}",
        f"*Principal:* `{finding.get('principal') or 'unknown'}`",
        f"*Source IP:* `{finding.get('source_ip') or 'unknown'}`  *Region:* `{finding.get('region')}`",
        f"*MITRE ATT&CK:* <https://attack.mitre.org/techniques/{mitre['id'].replace('.', '/')}/|{mitre['id']} {mitre['name']}>",
        f"*Runbook:* <{REPO_URL}{rule['runbook']}|triage steps>  *Event ID:* `{finding.get('event_id')}`",
    ]
    return {"text": f"{rule['name']}: {finding.get('event_name')} by {finding.get('principal') or 'unknown'}",
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]}


def post_slack(url, message, opener=urllib.request.urlopen):
    if not url.startswith("https://hooks.slack.com/"):
        raise ValueError("webhook must be a Slack incoming webhook URL")
    request = urllib.request.Request(url, data=json.dumps(message).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
    with opener(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"Slack returned HTTP {response.status}")


def already_sent(dynamodb, table, key):
    return "Item" in dynamodb.get_item(TableName=table, Key={"finding_key": {"S": key}}, ConsistentRead=True)


def record_sent(dynamodb, table, key, now):
    expires = int((now + timedelta(days=DEDUPE_DAYS)).timestamp())
    try:
        dynamodb.put_item(TableName=table, Item={"finding_key": {"S": key}, "expires_at": {"N": str(expires)}},
                          ConditionExpression="attribute_not_exists(finding_key)")
    except Exception as error:  # a concurrent run already recorded it
        if type(error).__name__ != "ConditionalCheckFailedException":
            raise


def run(athena, dynamodb, send, config, now):
    findings = []
    for region in config["regions"]:
        sql, parameters = build_query(region, now, config["lookback_minutes"])
        rows, truncated, _ = run_query(athena, sql, parameters, 200, config)
        if truncated:
            print(json.dumps({"warning": "result truncated", "region": region}))
        findings += rows
    sent = skipped = 0
    for finding in findings:
        key = f"{finding['detection_id']}#{finding['event_id']}"
        if already_sent(dynamodb, config["table"], key):
            skipped += 1
            continue
        if sent == MAX_ALERTS:
            send({"text": f":warning: More than {MAX_ALERTS} new findings this run; remaining ones will be sent next run."})
            break
        send(format_message(finding))
        record_sent(dynamodb, config["table"], key, now)
        sent += 1
    summary = {"findings": len(findings), "alerts_sent": sent, "already_sent": skipped}
    print(json.dumps(summary))
    return summary


_webhook = None


def _get_webhook(ssm, name):
    global _webhook
    if _webhook is None:
        _webhook = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    return _webhook


def handler(event, context):
    import boto3
    config = {"workgroup": os.environ["ATHENA_WORKGROUP"], "table": os.environ["DEDUPE_TABLE"],
              "timeout_seconds": float(os.environ.get("QUERY_TIMEOUT_SECONDS", "60")),
              "regions": [r for r in os.environ.get("REGIONS", "us-east-1").split(",") if r],
              "lookback_minutes": int(os.environ.get("LOOKBACK_MINUTES", "90"))}
    if isinstance(event, dict) and isinstance(event.get("lookback_minutes"), int):
        config["lookback_minutes"] = max(15, min(event["lookback_minutes"], 7 * 24 * 60))
    url = _get_webhook(boto3.client("ssm"), os.environ["WEBHOOK_PARAMETER"])

    def send(message):
        post_slack(url, message)

    if isinstance(event, dict) and event.get("test") is True:
        send({"text": ":white_check_mark: Cloud Detection Alerts test message. The alert pipeline can reach Slack."})
        return {"test_message_sent": True}
    try:
        return run(boto3.client("athena"), boto3.client("dynamodb"), send, config, datetime.now(timezone.utc))
    except QueryError as error:
        raise RuntimeError(f"detection query failed: {error.message}") from None
