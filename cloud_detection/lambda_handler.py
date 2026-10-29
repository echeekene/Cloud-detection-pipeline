"""Process one versioned CloudTrail object into stable S3 Parquet output."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import unquote_plus

from .dataset import DEFAULT_DOCUMENT_LIMIT, DEFAULT_TOTAL_LIMIT, PIPELINE_VERSION, build_dataset


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _read(s3, bucket, key, *, limit=DEFAULT_DOCUMENT_LIMIT, **kwargs):
    response = s3.get_object(Bucket=bucket, Key=key, **kwargs)
    body = response["Body"]
    try:
        if response.get("ContentLength", 0) > limit:
            raise ValueError("S3 object exceeds the input limit")
        payload = body.read(limit + 1)
        if len(payload) > limit:
            raise ValueError("S3 object exceeds the input limit")
        return payload
    finally:
        body.close()


def _put(s3, bucket, key, payload):
    s3.put_object(Bucket=bucket, Key=key, Body=payload, ServerSideEncryption="AES256",
                  Metadata={"sha256": hashlib.sha256(payload).hexdigest()})


def process_record(record, s3, config):
    """Stable output keys make retries reuse a checked completed publication."""
    if record.get("eventSource") != "aws:s3" or not record.get("eventName", "").startswith("ObjectCreated:"):
        raise ValueError("Expected an S3 object creation event")
    bucket = record["s3"]["bucket"]["name"]
    source = record["s3"]["object"]
    key = unquote_plus(source["key"])
    if bucket != config["raw_bucket"] or not key.startswith(config["input_prefix"]) or not key.endswith(".json.gz"):
        raise ValueError("Unexpected source bucket or CloudTrail key")
    if config["raw_bucket"] == config["analytics_bucket"]:
        raise ValueError("Input and output buckets must differ")
    version = source.get("versionId")
    etag = source.get("eTag")
    if not version or version == "null":
        if not isinstance(etag, str) or not etag:
            raise ValueError("Source requires a version ID or ETag")
        version = None
    identity = {"bucket": bucket, "key": key, "version": version, "etag": etag,
                "pipeline_version": PIPELINE_VERSION}
    run_id = hashlib.sha256(_json_bytes(identity)).hexdigest()
    output = config["analytics_bucket"]
    run_prefix = f"automated/runs/{run_id}/"
    marker_key = run_prefix + "_SUCCESS"
    # A prefix-scoped ListBucket avoids needing broad list permission just to
    # distinguish an absent marker from S3's access-denied response on GetObject.
    listed = s3.list_objects_v2(Bucket=output, Prefix=marker_key, MaxKeys=1)
    if any(item["Key"] == marker_key for item in listed.get("Contents", [])):
        marker = json.loads(_read(s3, output, marker_key))
        manifest_data = _read(s3, output, run_prefix + "manifest.json")
        if marker["manifest_sha256"] != hashlib.sha256(manifest_data).hexdigest():
            raise ValueError("Published manifest integrity check failed")
        manifest = json.loads(manifest_data)
        if manifest["source"] != identity:
            raise ValueError("Published source identity differs")
        for artifact in manifest["published_artifacts"]:
            if hashlib.sha256(_read(s3, output, artifact["key"], limit=DEFAULT_TOTAL_LIMIT)).hexdigest() != artifact["sha256"]:
                raise ValueError("Published artifact integrity check failed")
        return {"run_id": run_id, "accepted_records": manifest["accepted_records"], "reused": True}

    arguments = {"VersionId": version} if version else {"IfMatch": '"' + etag.strip('"') + '"'}
    payload = _read(s3, bucket, key, **arguments)
    with tempfile.TemporaryDirectory(prefix="cloud-detection-") as temp:
        temp = Path(temp)
        input_file = temp / "source.json.gz"
        input_file.write_bytes(payload)
        snapshot = temp / "snapshot"
        manifest = build_dataset([input_file], snapshot, total_limit=DEFAULT_DOCUMENT_LIMIT)
        published = []
        for artifact in manifest["artifacts"]:
            relative = artifact["path"]
            if relative.startswith("parquet/"):
                partition = relative.removeprefix("parquet/").rsplit("/", 1)[0]
                destination = f"automated/parquet/{partition}/{run_id}.parquet"
            else:
                destination = run_prefix + relative
            data = (snapshot / relative).read_bytes()
            if len(data) > DEFAULT_TOTAL_LIMIT:
                raise ValueError("Published artifact exceeds the output limit")
            _put(s3, output, destination, data)
            published.append({"key": destination, "sha256": hashlib.sha256(data).hexdigest()})
        manifest.update(source=identity, published_artifacts=published)
        data = _json_bytes(manifest)
        _put(s3, output, run_prefix + "manifest.json", data)
        _put(s3, output, marker_key, _json_bytes({"manifest_sha256": hashlib.sha256(data).hexdigest()}))
    return {"run_id": run_id, "accepted_records": manifest["accepted_records"],
            "quarantined_records": manifest["quarantined_records"], "failed_documents": manifest["failed_documents"], "reused": False}


def handler(event, context):
    import boto3
    config = {"raw_bucket": os.environ["RAW_BUCKET"], "analytics_bucket": os.environ["ANALYTICS_BUCKET"],
              "input_prefix": os.environ["INPUT_PREFIX"]}
    # S3 sends a separate validation message when the destination is configured.
    if event.get("Event") == "s3:TestEvent":
        return {"test_event": True}
    records = event.get("Records")
    if not isinstance(records, list) or not 1 <= len(records) <= 10:
        raise ValueError("Expected between one and ten S3 event records")
    s3 = boto3.client("s3")
    results = [process_record(record, s3, config) for record in records]
    print(json.dumps({"processed_objects": len(results), "accepted_records": sum(item["accepted_records"] for item in results),
                      "reused_objects": sum(item["reused"] for item in results)}))
    return {"results": results}
