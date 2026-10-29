"""Small local slice; no cloud calls or credentials required."""

from datetime import datetime, timezone
import re


def _object(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _text(value, field, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def normalize(record: dict) -> dict:
    if not isinstance(record, dict):
        raise ValueError("CloudTrail event must be an object")
    event_id = _text(record.get("eventID"), "eventID", required=True)
    try:
        if isinstance(record.get("eventTime"), str) and re.search(r"[T ]\d{2}:\d{2}:\d{2}\.\d{7}", record["eventTime"]):
            raise ValueError("timestamp precision exceeds supported microseconds")
        timestamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timestamp requires timezone")
        timestamp = timestamp.astimezone(timezone.utc)
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError(f"Invalid eventTime for {event_id}") from exc

    identity = _object(record.get("userIdentity"), "userIdentity")
    response = _object(record.get("responseElements"), "responseElements")
    extra = _object(record.get("additionalEventData"), "additionalEventData")
    source = _text(record.get("eventSource"), "eventSource", required=True)
    name = _text(record.get("eventName"), "eventName", required=True)
    region = _text(record.get("awsRegion"), "awsRegion", required=True)
    if len(region) > 32 or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d+", region):
        raise ValueError("awsRegion must be a valid region identifier")
    account = _text(record.get("recipientAccountId") or identity.get("accountId"), "accountId")
    if account is not None and not re.fullmatch(r"\d{12}", account):
        raise ValueError("accountId must contain 12 digits")
    error_code = _text(record.get("errorCode"), "errorCode")
    console = source == "signin.amazonaws.com" and name == "ConsoleLogin"
    mfa_value = _text(extra.get("MFAUsed"), "MFAUsed")
    mfa = {"Yes": True, "No": False}.get(mfa_value) if console else None
    console_result = _text(response.get("ConsoleLogin"), "ConsoleLogin")
    outcome = "unknown"
    if error_code or (console and console_result == "Failure"):
        outcome = "failure"
    elif (console and console_result == "Success") or not console:
        outcome = "success"

    return {
        "event_id": event_id,
        "event_time": timestamp.isoformat().replace("+00:00", "Z"),
        "event_source": source,
        "event_name": name,
        "region": region,
        "account_id": account,
        "source_ip": _text(record.get("sourceIPAddress"), "sourceIPAddress"),
        "principal": _text(identity.get("arn") or identity.get("principalId"), "principal"),
        "principal_type": _text(identity.get("type"), "userIdentity.type"),
        "error_code": error_code,
        "outcome": outcome,
        "mfa_used": mfa,
    }


def detect(events: list[dict]) -> list[dict]:
    findings = [
        {
            "rule_id": "console-login-without-mfa",
            "event_id": event["event_id"],
            "event_time": event["event_time"],
            "principal": event["principal"],
            "source_ip": event["source_ip"],
            "summary": "Successful console login explicitly recorded without MFA.",
        }
        for event in events
        if event["event_source"] == "signin.amazonaws.com"
        and event["event_name"] == "ConsoleLogin"
        and event["outcome"] == "success"
        and event["mfa_used"] is False
    ]
    findings.extend(
        {
            "rule_id": "iam-managed-policy-attached",
            "event_id": event["event_id"],
            "event_time": event["event_time"],
            "principal": event["principal"],
            "source_ip": event["source_ip"],
            "summary": "Managed IAM policy attached to a user; review the target and permissions in the source event.",
        }
        for event in events
        if event["event_source"] == "iam.amazonaws.com"
        and event["event_name"] == "AttachUserPolicy"
        and event["outcome"] == "success"
    )
    return findings
