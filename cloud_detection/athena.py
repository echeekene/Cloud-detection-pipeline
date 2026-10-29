"""Run one parameterized Athena query within a deadline. Shared by the API and the scheduled runner."""

import json
import time

DATABASE = "cloud_detection"


class QueryError(Exception):
    """Carries an HTTP-style status so callers can map failures consistently."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def literal(value):
    """Athena execution parameters are SQL literals. Callers pattern-check values first; doubling
    quotes is a second, independent safeguard."""
    return "'" + value.replace("'", "''") + "'"


def _convert(column, value):
    if value is None:
        return None
    if column == "mfa_used":
        return {"true": True, "false": False}.get(value)
    return value


def run_query(athena, sql, parameters, limit, config, clock=time.monotonic, sleep=time.sleep):
    """Returns (rows, truncated, execution_id). Raises QueryError 502 on failure, 504 on timeout."""
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
            raise QueryError(502, "query did not complete")
        if clock() + delay > deadline:
            athena.stop_query_execution(QueryExecutionId=execution_id)
            raise QueryError(504, "query exceeded the time limit; narrow the date range")
        sleep(delay)
        delay = min(delay * 2, 2.0)
    result = athena.get_query_results(QueryExecutionId=execution_id, MaxResults=limit + 2)
    rows = result["ResultSet"]["Rows"]
    header = [cell.get("VarCharValue") for cell in rows[0]["Data"]] if rows else []
    items = [{column: _convert(column, cell.get("VarCharValue")) for column, cell in zip(header, row["Data"])}
             for row in rows[1:]]
    return items[:limit], len(items) > limit, execution_id
