"""Bounded local snapshots; publishing to S3 is a separate deployment concern."""

from collections import defaultdict
from datetime import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile

import pyarrow as pa
import pyarrow.parquet as pq

from .pipeline import normalize

PIPELINE_VERSION = "0.2.0"
DEFAULT_DOCUMENT_LIMIT = 8 * 1024 * 1024
DEFAULT_TOTAL_LIMIT = 64 * 1024 * 1024

EVENT_SCHEMA = pa.schema([
    pa.field("event_id", pa.string(), nullable=False),
    pa.field("event_time", pa.timestamp("ms"), nullable=False),
    pa.field("event_time_iso", pa.string(), nullable=False),
    pa.field("event_source", pa.string(), nullable=False),
    pa.field("event_name", pa.string(), nullable=False),
    pa.field("account_id", pa.string()),
    pa.field("source_ip", pa.string()),
    pa.field("principal", pa.string()),
    pa.field("principal_type", pa.string()),
    pa.field("outcome", pa.string(), nullable=False),
    pa.field("error_code", pa.string()),
    pa.field("mfa_used", pa.bool_()),
], metadata={b"pipeline_version": PIPELINE_VERSION.encode(), b"time_semantics": b"UTC; milliseconds; full precision preserved in event_time_iso"})


class DocumentError(ValueError):
    """An input document cannot be parsed safely."""


def _hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _read_records(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DocumentError("compressed_or_plain_document_exceeds_limit")
    if path.name.endswith(".gz"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                data = stream.read(limit + 1)
        except (OSError, EOFError):
            raise DocumentError("invalid_gzip") from None
    if len(data) > limit:
        raise DocumentError("decompressed_document_exceeds_limit")
    try:
        payload = json.loads(data.decode("utf-8-sig"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError):
        raise DocumentError("invalid_json") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("Records"), list):
        raise DocumentError("invalid_cloudtrail_envelope")
    return payload["Records"], len(data)


def discover_inputs(inputs, output):
    output = Path(output).resolve()
    found = set()
    for item in inputs:
        path = Path(item).resolve()
        if path.is_dir():
            if output == path or path in output.parents:
                raise ValueError("Output must be outside input directories")
            found.update(p.resolve() for p in path.rglob("*") if p.is_file() and p.name.endswith((".json", ".json.gz")))
        elif path.is_file() and path.name.endswith((".json", ".json.gz")):
            found.add(path)
        else:
            raise ValueError("Inputs must be JSON/gzip files or directories containing them")
    if not found:
        raise ValueError("No CloudTrail input files found")
    if len(found) > 1000:
        raise ValueError("A local snapshot supports at most 1000 input files")
    if any(output == path or path in output.parents for path in found):
        raise ValueError("Output cannot replace an input file")
    return sorted(found)


def _existing_snapshot(output, fingerprint):
    try:
        marker = json.loads((output / "_SUCCESS").read_text(encoding="ascii"))
        if marker["manifest_sha256"] != _hash_file(output / "manifest.json"):
            raise ValueError("Existing snapshot manifest failed its integrity check")
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        if marker["input_fingerprint"] != fingerprint or manifest["input_fingerprint"] != fingerprint:
            raise ValueError("Existing snapshot uses different inputs; choose a new output directory")
        for item in manifest["artifacts"]:
            path = (output / item["path"]).resolve()
            if output.resolve() not in path.parents or _hash_file(path) != item["sha256"]:
                raise ValueError("Existing snapshot failed its integrity check")
        expected = {item["path"] for item in manifest["artifacts"] if item["path"].endswith(".parquet")}
        actual = {path.relative_to(output).as_posix() for path in output.rglob("*.parquet")}
        if actual != expected:
            raise ValueError("Existing snapshot contains unexpected Parquet files")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Existing output is incomplete or corrupt; choose a new output directory") from exc
    return {**manifest, "reused": True}


def verify_snapshot(output):
    """Check a completed snapshot before using its files outside the local run."""
    output = Path(output).resolve()
    try:
        fingerprint = json.loads((output / "manifest.json").read_text(encoding="utf-8"))["input_fingerprint"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Snapshot manifest is missing or invalid") from exc
    return _existing_snapshot(output, fingerprint)


def build_dataset(inputs, output, *, document_limit=DEFAULT_DOCUMENT_LIMIT, total_limit=DEFAULT_TOTAL_LIMIT):
    """Publish an immutable complete snapshot, or reuse one with identical verified inputs."""
    if document_limit < 1 or total_limit < 1:
        raise ValueError("Input limits must be positive")
    output = Path(output).resolve()
    paths = discover_inputs(inputs, output)
    sources = [(path, _hash_file(path)) for path in paths]
    fingerprint = hashlib.sha256(_canonical({
        "pipeline_version": PIPELINE_VERSION,
        "inputs": sorted(digest for _, digest in sources),
        "document_limit": document_limit,
        "total_limit": total_limit,
    }).encode()).hexdigest()
    if output.exists():
        return _existing_snapshot(output, fingerprint)

    grouped = defaultdict(list)
    rejected = []
    total_bytes = 0
    records_seen = 0
    failed_documents = 0
    for path, source_id in sources:
        try:
            records, size = _read_records(path, document_limit)
        except DocumentError as exc:
            failed_documents += 1
            rejected.append({"kind": "document", "source_id": source_id, "reason": str(exc)})
            continue
        total_bytes += size
        if total_bytes > total_limit:
            raise ValueError("Snapshot exceeds total decompressed input limit")
        # Detect source changes between fingerprinting and parsing before publishing.
        if _hash_file(path) != source_id:
            raise ValueError("An input changed during the run; retry with stable input files")
        for index, record in enumerate(records):
            records_seen += 1
            evidence = {"kind": "record", "source_id": source_id, "record_index": index, "record": record}
            try:
                event = normalize(record)
            except ValueError as exc:
                rejected.append({**evidence, "reason": str(exc)})
                continue
            grouped[(event["account_id"] or "", event["event_id"])].append({
                "event": event, "evidence": evidence, "canonical": _canonical(record)
            })

    accepted = []
    duplicates = 0
    conflicts = 0
    for key in sorted(grouped):
        group = grouped[key]
        if len({item["canonical"] for item in group}) > 1:
            conflicts += len(group)
            rejected.extend({**item["evidence"], "reason": "conflicting_event_identity"} for item in group)
        else:
            accepted.append(group[0]["event"])
            duplicates += len(group) - 1
    record_rejections = sum(item["kind"] == "record" for item in rejected)
    assert records_seen == len(accepted) + duplicates + record_rejections

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}-", dir=output.parent) as temp:
        staging = Path(temp) / "snapshot"
        staging.mkdir()
        partitions = defaultdict(list)
        for event in accepted:
            row = {key: value for key, value in event.items() if key != "region"}
            instant = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
            row["event_time_iso"] = row["event_time"]
            row["event_time"] = instant.replace(tzinfo=None, microsecond=(instant.microsecond // 1000) * 1000)
            partitions[(instant.date().isoformat(), event["region"])].append(row)
        artifacts = []
        for (day, region), rows in sorted(partitions.items()):
            relative = Path("parquet") / f"event_date={day}" / f"region={region}" / "part-00000.parquet"
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            pq.write_table(pa.Table.from_pylist(rows, schema=EVENT_SCHEMA), destination, compression="snappy", version="1.0")
            artifacts.append({"path": relative.as_posix(), "rows": len(rows), "sha256": _hash_file(destination)})
        quarantine = staging / "quarantine" / "records.jsonl"
        quarantine.parent.mkdir()
        quarantine.write_text("".join(_canonical(item) + "\n" for item in rejected), encoding="utf-8")
        artifacts.append({"path": "quarantine/records.jsonl", "sha256": _hash_file(quarantine)})
        manifest = {
            "pipeline_version": PIPELINE_VERSION, "input_fingerprint": fingerprint,
            "input_documents": len(paths), "failed_documents": failed_documents,
            "records_seen": records_seen, "accepted_records": len(accepted),
            "duplicate_records": duplicates, "conflicting_records": conflicts,
            "quarantined_records": record_rejections, "partitions": len(partitions),
            "artifacts": artifacts,
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        marker = {"input_fingerprint": fingerprint, "manifest_sha256": _hash_file(staging / "manifest.json")}
        (staging / "_SUCCESS").write_text(json.dumps(marker) + "\n", encoding="ascii")
        staging.rename(output)
    return {**manifest, "reused": False}
