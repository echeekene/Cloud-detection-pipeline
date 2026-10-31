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
MATCH_WINDOW_SECONDS = 600


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


def is_simulation(finding, simulator_role):
    return bool(simulator_role) and f":assumed-role/{simulator_role}/" in (finding.get("principal") or "")


def format_message(finding, simulation=False):
    rule = RULES[finding["detection_id"]]
    mitre = rule["mitre_attack"]
    mark = SEVERITY_MARK.get(rule["severity"], "")
    lines = [
        ("[SIMULATION] " if simulation else "") + f"{mark} *{rule['name']}* ({rule['severity']})",
        f"*Event:* `{finding.get('event_name')}` from `{finding.get('event_source')}` at {finding.get('event_time_iso')}",
        f"*Principal:* `{finding.get('principal') or 'unknown'}`",
        f"*Source IP:* `{finding.get('source_ip') or 'unknown'}`  *Region:* `{finding.get('region')}`",
        f"*MITRE ATT&CK:* <https://attack.mitre.org/techniques/{mitre['id'].replace('.', '/')}/|{mitre['id']} {mitre['name']}>",
        f"*Runbook:* <{REPO_URL}{rule['runbook']}|triage steps>  *Event ID:* `{finding.get('event_id')}`",
    ]
    prefix = "[SIMULATION] " if simulation else ""
    return {"text": f"{prefix}{rule['name']}: {finding.get('event_name')} by {finding.get('principal') or 'unknown'}",
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


def _epoch(text):
    return int(datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())


def _scan(dynamodb, table, **kwargs):
    items, start = [], None
    while True:
        page = dynamodb.scan(TableName=table, **kwargs, **({"ExclusiveStartKey": start} if start else {}))
        items += page.get("Items", [])
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


def mark_detected(dynamodb, table, finding, now):
    """Link a simulation finding to the earliest undetected simulation of the same rule nearby in time."""
    event_at = _epoch(finding["event_time_iso"])
    candidates = [item for item in _scan(dynamodb, table, FilterExpression="rule_id = :r AND attribute_not_exists(detected_at)",
                                         ExpressionAttributeValues={":r": {"S": finding["detection_id"]}})
                  if abs(int(item["started_at"]["N"]) - event_at) <= MATCH_WINDOW_SECONDS]
    if not candidates:
        print(json.dumps({"warning": "simulation finding without a matching record", "event_id": finding.get("event_id")}))
        return None
    match = min(candidates, key=lambda item: int(item["started_at"]["N"]))
    dynamodb.update_item(TableName=table, Key={"sim_id": match["sim_id"]},
                         UpdateExpression="SET detected_at = :d, detected_event_id = :e",
                         ExpressionAttributeValues={":d": {"N": str(int(now.timestamp()))}, ":e": {"S": finding["event_id"]}})
    return match["sim_id"]["S"]


def scorecard(dynamodb, table, now, hours=24, grace_minutes=60):
    """Summarize simulations from the last day: detected, missed, still pending, and time to detect."""
    since = int(now.timestamp()) - hours * 3600
    pending_after = int(now.timestamp()) - grace_minutes * 60
    items = _scan(dynamodb, table, FilterExpression="started_at >= :s", ExpressionAttributeValues={":s": {"N": str(since)}})
    detected, missed, pending, failed, delays = [], [], [], [], []
    for item in items:
        scenario = item["scenario"]["S"]
        if item.get("status", {}).get("S") != "completed":
            failed.append(scenario)
        elif "detected_at" in item:
            detected.append(scenario)
            delays.append(int(item["detected_at"]["N"]) - int(item["started_at"]["N"]))
        elif int(item["started_at"]["N"]) > pending_after:
            pending.append(scenario)
        else:
            missed.append(scenario)
    scored = len(detected) + len(missed)
    delays.sort()
    median = delays[len(delays) // 2] // 60 if delays else None
    lines = [f":bar_chart: *Detection scorecard, last {hours} hours*",
             f"*Caught:* {len(detected)} of {scored} simulated attacks" + (f" ({100 * len(detected) // scored}%)" if scored else ""),
             f"*Median time to detect:* {median} min" if median is not None else "*Median time to detect:* no detections yet"]
    if missed:
        lines.append("*Missed:* " + ", ".join(sorted(missed)))
    if pending:
        lines.append(f"*Still within the {grace_minutes} minute window:* {len(pending)}")
    if failed:
        lines.append("*Simulations that failed to run:* " + ", ".join(sorted(failed)))
    summary = {"detected": len(detected), "missed": len(missed), "pending": len(pending), "failed": len(failed),
               "median_minutes": median}
    return {"text": "\n".join(lines)}, summary


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
        simulation = is_simulation(finding, config.get("simulator_role"))
        send(format_message(finding, simulation))
        record_sent(dynamodb, config["table"], key, now)
        if simulation and config.get("simulations_table"):
            mark_detected(dynamodb, config["simulations_table"], finding, now)
        sent += 1
    summary = {"findings": len(findings), "alerts_sent": sent, "already_sent": skipped}
    print(json.dumps(summary))
    return summary


ALARM_MARK = {"ALARM": ":rotating_light:", "OK": ":white_check_mark:", "INSUFFICIENT_DATA": ":grey_question:"}


def format_alarm(record):
    """Turn a CloudWatch alarm notification delivered through SNS into a Slack message."""
    alarm = json.loads(record["Sns"]["Message"])
    state = alarm.get("NewStateValue", "UNKNOWN")
    name = alarm.get("AlarmName", "unknown alarm")
    title = "Pipeline health: " + ("problem detected" if state == "ALARM" else "recovered" if state == "OK" else state.lower())
    lines = [f"{ALARM_MARK.get(state, '')} *{title}*",
             f"*Alarm:* `{name}`",
             f"*What it watches:* {alarm.get('AlarmDescription') or 'no description'}",
             f"*Reason:* {(alarm.get('NewStateReason') or '')[:300]}",
             f"*Since:* {alarm.get('StateChangeTime', 'unknown')}"]
    return {"text": f"{state}: {name}", "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]}


def is_sns_event(event):
    records = event.get("Records") if isinstance(event, dict) else None
    return isinstance(records, list) and bool(records) and all(r.get("EventSource") == "aws:sns" for r in records)


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
              "lookback_minutes": int(os.environ.get("LOOKBACK_MINUTES", "90")),
              "simulator_role": os.environ.get("SIMULATOR_ROLE", ""),
              "simulations_table": os.environ.get("SIMULATIONS_TABLE", "")}
    if isinstance(event, dict) and isinstance(event.get("lookback_minutes"), int):
        config["lookback_minutes"] = max(15, min(event["lookback_minutes"], 7 * 24 * 60))
    url = _get_webhook(boto3.client("ssm"), os.environ["WEBHOOK_PARAMETER"])

    def send(message):
        post_slack(url, message)

    if is_sns_event(event):
        for record in event["Records"]:
            send(format_alarm(record))
        return {"alarm_notifications_sent": len(event["Records"])}
    if isinstance(event, dict) and event.get("scorecard") is True:
        if not config["simulations_table"]:
            return {"scorecard": "no simulations table configured"}
        message, summary = scorecard(boto3.client("dynamodb"), config["simulations_table"], datetime.now(timezone.utc))
        send(message)
        print(json.dumps({"scorecard": summary}))
        return summary
    if isinstance(event, dict) and event.get("test") is True:
        send({"text": ":white_check_mark: Cloud Detection Alerts test message. The alert pipeline can reach Slack."})
        return {"test_message_sent": True}
    try:
        return run(boto3.client("athena"), boto3.client("dynamodb"), send, config, datetime.now(timezone.utc))
    except QueryError as error:
        raise RuntimeError(f"detection query failed: {error.message}") from None
