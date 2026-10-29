"""Read-only findings API: validated HTTP requests become fixed, parameterized Athena queries.

API Gateway (HTTP API, IAM authorization) invokes ``handler``. User input never becomes
part of the SQL text: table names come from an allowlist, every filter value is checked
against a strict pattern and passed through Athena execution parameters, and row limits
are applied when reading results.
"""

from datetime import date, timedelta
import ipaddress
import json
import os
import re
import time

DATABASE = "cloud_detection"
DATASETS = {"automated": "automated_events", "live": "security_events", "synthetic": "synthetic_events"}
MAX_DAYS = 31
MAX_LIMIT = 100
DEFAULT_LIMIT = 50
EARLIEST = date(2020, 1, 1)
COLUMNS = "event_id, event_time_iso, event_source, event_name, account_id, principal, source_ip, outcome, error_code, mfa_used, region, event_date"

DETECTIONS = {
    "console_login_without_mfa": {
        "name": "Console login without MFA",
        "description": "Successful AWS console login where CloudTrail explicitly records that MFA was not used.",
        "mitre_attack": {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
        "severity": "medium",
        "condition": "event_source = 'signin.amazonaws.com' AND event_name = 'ConsoleLogin' AND outcome = 'success' AND mfa_used = FALSE",
        "sql": "sql/detections/console_login_without_mfa.sql",
    },
    "iam_managed_policy_attached": {
        "name": "Managed policy attached to IAM user",
        "description": "Successful AttachUserPolicy call. Requires investigation; the rule does not judge whether the permissions are excessive.",
        "mitre_attack": {"id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles"},
        "severity": "medium",
        "condition": "event_source = 'iam.amazonaws.com' AND event_name = 'AttachUserPolicy' AND outcome = 'success'",
        "sql": "sql/detections/iam_managed_policy_attached.sql",
    },
}

REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-\d+")
PRINCIPAL = re.compile(r"[A-Za-z0-9+=,.@_:/-]{1,256}")
EVENT_NAME = re.compile(r"[A-Za-z0-9]{1,128}")
DETECTION_ID = re.compile(r"[a-z_]{1,64}")
OUTCOMES = {"success", "failure", "unknown"}


class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _literal(value):
    """Athena execution parameters are SQL literals. Values are pattern-checked first and
    can never contain a quote; doubling quotes is a second, independent safeguard."""
    return "'" + value.replace("'", "''") + "'"


def _date(params, name):
    value = params.get(name)
    if value is None:
        raise RequestError(400, f"{name} is required (YYYY-MM-DD, UTC)")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise RequestError(400, f"{name} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise RequestError(400, f"{name} is not a valid date") from None


def _window(params, today):
    start, end = _date(params, "start"), _date(params, "end")
    if end < start:
        raise RequestError(400, "end must not be before start")
    if start < EARLIEST or end > today + timedelta(days=1):
        raise RequestError(400, "dates are outside the supported range")
    if (end - start).days + 1 > MAX_DAYS:
        raise RequestError(400, f"date range is limited to {MAX_DAYS} days")
    region = params.get("region")
    if region is None or len(region) > 32 or not REGION.fullmatch(region):
        raise RequestError(400, "region is required and must be an AWS region such as us-east-1")
    dataset = params.get("dataset", "automated")
    if dataset not in DATASETS:
        raise RequestError(400, "dataset must be one of: " + ", ".join(sorted(DATASETS)))
    return {"start": start.isoformat(), "end": end.isoformat(), "region": region, "dataset": dataset}


def _limit(params):
    value = params.get("limit", str(DEFAULT_LIMIT))
    if not re.fullmatch(r"\d{1,3}", value) or not 1 <= int(value) <= MAX_LIMIT:
        raise RequestError(400, f"limit must be between 1 and {MAX_LIMIT}")
    return int(value)


def _allowed(params, names):
    unknown = sorted(set(params) - set(names))
    if unknown:
        raise RequestError(400, "unsupported query parameter: " + unknown[0])


def build_findings_query(params, today):
    """Return (sql, parameters, window, limit). Exposed for tests."""
    _allowed(params, {"start", "end", "region", "dataset", "detection", "limit"})
    window, limit = _window(params, today), _limit(params)
    selected = params.get("detection")
    if selected is not None and (not DETECTION_ID.fullmatch(selected) or selected not in DETECTIONS):
        raise RequestError(400, "detection must be one of: " + ", ".join(sorted(DETECTIONS)))
    table = DATASETS[window["dataset"]]
    parts, parameters = [], []
    for detection_id, rule in DETECTIONS.items():
        if selected not in (None, detection_id):
            continue
        parts.append(f"SELECT '{detection_id}' AS detection_id, {COLUMNS} FROM {table} "
                     f"WHERE event_date BETWEEN ? AND ? AND region = ? AND {rule['condition']}")
        parameters += [_literal(window["start"]), _literal(window["end"]), _literal(window["region"])]
    sql = " UNION ALL ".join(parts) + f" ORDER BY event_time_iso DESC LIMIT {MAX_LIMIT + 1}"
    return sql, parameters, window, limit


def build_events_query(params, today):
    _allowed(params, {"start", "end", "region", "dataset", "principal", "source_ip", "event_name", "outcome", "limit"})
    window, limit = _window(params, today), _limit(params)
    table = DATASETS[window["dataset"]]
    clauses = ["event_date BETWEEN ? AND ?", "region = ?"]
    parameters = [_literal(window["start"]), _literal(window["end"]), _literal(window["region"])]
    if "principal" in params:
        if not PRINCIPAL.fullmatch(params["principal"]):
            raise RequestError(400, "principal may contain only ARN characters and up to 256 characters")
        clauses.append("principal = ?")
        parameters.append(_literal(params["principal"]))
    if "source_ip" in params:
        try:
            address = str(ipaddress.ip_address(params["source_ip"]))
        except ValueError:
            raise RequestError(400, "source_ip must be an IPv4 or IPv6 address") from None
        clauses.append("source_ip = ?")
        parameters.append(_literal(address))
    if "event_name" in params:
        if not EVENT_NAME.fullmatch(params["event_name"]):
            raise RequestError(400, "event_name must be an API action name such as AttachUserPolicy")
        clauses.append("event_name = ?")
        parameters.append(_literal(params["event_name"]))
    if "outcome" in params:
        if params["outcome"] not in OUTCOMES:
            raise RequestError(400, "outcome must be one of: failure, success, unknown")
        clauses.append("outcome = ?")
        parameters.append(_literal(params["outcome"]))
    sql = f"SELECT {COLUMNS} FROM {table} WHERE " + " AND ".join(clauses) + f" ORDER BY event_time_iso DESC LIMIT {MAX_LIMIT + 1}"
    return sql, parameters, window, limit


def _convert(column, value):
    if value is None:
        return None
    if column == "mfa_used":
        return {"true": True, "false": False}.get(value)
    return value


def run_query(athena, sql, parameters, limit, config, clock=time.monotonic, sleep=time.sleep):
    """Run one query within a deadline. Returns (rows, truncated, execution_id)."""
    started = athena.start_query_execution(
        QueryString=sql, ExecutionParameters=parameters, WorkGroup=config["workgroup"],
        QueryExecutionContext={"Database": DATABASE})
    execution_id = started["QueryExecutionId"]
    deadline = clock() + config["timeout_seconds"]
    delay = 0.25
    while True:
        status = athena.get_query_execution(QueryExecutionId=execution_id)["QueryExecution"]["Status"]
        state = status["State"]
        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            print(json.dumps({"query_execution_id": execution_id, "state": state,
                              "reason": status.get("StateChangeReason", "")[:500]}))
            raise RequestError(502, "query did not complete")
        if clock() + delay > deadline:
            athena.stop_query_execution(QueryExecutionId=execution_id)
            raise RequestError(504, "query exceeded the time limit; narrow the date range")
        sleep(delay)
        delay = min(delay * 2, 2.0)
    result = athena.get_query_results(QueryExecutionId=execution_id, MaxResults=limit + 2)
    rows = result["ResultSet"]["Rows"]
    header = [cell.get("VarCharValue") for cell in rows[0]["Data"]] if rows else []
    items = [{column: _convert(column, cell.get("VarCharValue")) for column, cell in zip(header, row["Data"])}
             for row in rows[1:]]
    return items[:limit], len(items) > limit, execution_id


def _response(status, body):
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, separators=(",", ":"))}


def route(event, athena, config, today):
    route_key = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}
    if route_key == "GET /detections":
        _allowed(params, set())
        return _response(200, {"detections": [
            {"id": key, **{k: v for k, v in rule.items() if k != "condition"}} for key, rule in DETECTIONS.items()]})
    if route_key == "GET /findings":
        sql, parameters, window, limit = build_findings_query(params, today)
    elif route_key == "GET /events":
        sql, parameters, window, limit = build_events_query(params, today)
    else:
        raise RequestError(404, "route not found")
    items, truncated, execution_id = run_query(athena, sql, parameters, limit, config)
    return _response(200, {**window, "count": len(items), "truncated": truncated,
                           "query_execution_id": execution_id, "items": items})


def handler(event, context):
    import boto3
    config = {"workgroup": os.environ["ATHENA_WORKGROUP"],
              "timeout_seconds": float(os.environ.get("QUERY_TIMEOUT_SECONDS", "20"))}
    caller = ((event.get("requestContext") or {}).get("authorizer") or {}).get("iam", {}).get("userArn")
    try:
        response = route(event, boto3.client("athena"), config, date.today())
    except RequestError as error:
        response = _response(error.status, {"error": error.message})
    print(json.dumps({"route": event.get("routeKey"), "status": response["statusCode"], "caller": caller}))
    return response
