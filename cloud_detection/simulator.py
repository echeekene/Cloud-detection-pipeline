"""Attack simulator: perform one harmless, reversible action that a detection rule should catch.

EventBridge invokes ``handler`` on a schedule. Each scenario acts only on dedicated canary
resources (or briefly on the project trail), always restores the original setting in a
``finally`` block, and records ground truth in DynamoDB so the alert runner can score
whether and how quickly the action was detected.
"""

from datetime import datetime, timezone
import json
import os
import random
import time
import uuid

TTL_DAYS = 30


def access_key(clients, config):
    """CreateAccessKey on a canary user with no permissions, then delete the key at once."""
    key = clients["iam"].create_access_key(UserName=config["canary_user"])["AccessKey"]["AccessKeyId"]
    clients["iam"].delete_access_key(UserName=config["canary_user"], AccessKeyId=key)


def attach_policy(clients, config):
    """Attach a deny-all policy to the canary user, then detach it."""
    clients["iam"].attach_user_policy(UserName=config["canary_user"], PolicyArn=config["canary_policy_arn"])
    try:
        time.sleep(2)
    finally:
        clients["iam"].detach_user_policy(UserName=config["canary_user"], PolicyArn=config["canary_policy_arn"])


def public_access_block(clients, config):
    """Remove the empty canary bucket's public access block, then restore it fully."""
    clients["s3"].delete_public_access_block(Bucket=config["canary_bucket"])
    try:
        time.sleep(2)
    finally:
        clients["s3"].put_public_access_block(Bucket=config["canary_bucket"], PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})


def trail_stop(clients, config):
    """Stop the project trail for a few seconds, then start it again."""
    clients["cloudtrail"].stop_logging(Name=config["trail"])
    try:
        time.sleep(5)
    finally:
        clients["cloudtrail"].start_logging(Name=config["trail"])


SCENARIOS = {
    "access_key": ("iam_access_key_created", access_key),
    "attach_policy": ("iam_managed_policy_attached", attach_policy),
    "public_access_block": ("s3_public_access_block_removed", public_access_block),
    "trail_stop": ("cloudtrail_logging_disabled", trail_stop),
}


def simulate(name, clients, dynamodb, config, clock=time.time):
    if name not in SCENARIOS:
        raise ValueError("unknown scenario")
    rule_id, action = SCENARIOS[name]
    sim_id = str(uuid.uuid4())
    started = int(clock())
    item = {"sim_id": {"S": sim_id}, "scenario": {"S": name}, "rule_id": {"S": rule_id},
            "started_at": {"N": str(started)}, "status": {"S": "running"},
            "expires_at": {"N": str(started + TTL_DAYS * 86400)}}
    dynamodb.put_item(TableName=config["table"], Item=item)
    status, error = "completed", None
    try:
        action(clients, config)
    except Exception as exc:
        status, error = "failed", type(exc).__name__
        raise
    finally:
        names = {"#s": "status"}
        values = {":s": {"S": status}, ":f": {"N": str(int(clock()))}}
        expression = "SET #s = :s, finished_at = :f"
        if error:
            expression += ", error_type = :e"
            values[":e"] = {"S": error}
        dynamodb.update_item(TableName=config["table"], Key={"sim_id": {"S": sim_id}},
                             UpdateExpression=expression, ExpressionAttributeNames=names,
                             ExpressionAttributeValues=values)
        print(json.dumps({"sim_id": sim_id, "scenario": name, "rule_id": rule_id, "status": status,
                          "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat()}))
    return {"sim_id": sim_id, "scenario": name, "rule_id": rule_id, "status": status}


def handler(event, context):
    import boto3
    config = {"table": os.environ["SIMULATIONS_TABLE"], "canary_user": os.environ["CANARY_USER"],
              "canary_policy_arn": os.environ["CANARY_POLICY_ARN"], "canary_bucket": os.environ["CANARY_BUCKET"],
              "trail": os.environ["TRAIL_NAME"]}
    enabled = [s for s in os.environ.get("SCENARIOS", ",".join(SCENARIOS)).split(",") if s in SCENARIOS]
    requested = event.get("scenario") if isinstance(event, dict) else None
    name = requested if requested in SCENARIOS else random.choice(enabled)
    clients = {"iam": boto3.client("iam"), "s3": boto3.client("s3"), "cloudtrail": boto3.client("cloudtrail")}
    return simulate(name, clients, boto3.client("dynamodb"), config)
