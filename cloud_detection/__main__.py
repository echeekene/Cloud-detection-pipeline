import argparse
import json
from pathlib import Path
import sys

from .pipeline import detect, normalize


def etl_main(argv):
    from .dataset import build_dataset

    parser = argparse.ArgumentParser(description="Build a local partitioned CloudTrail Parquet snapshot")
    parser.add_argument("--input", required=True, action="append", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = build_dataset(args.input, args.output)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    keys = ("input_documents", "failed_documents", "records_seen", "accepted_records", "duplicate_records", "conflicting_records", "quarantined_records", "partitions", "reused")
    print(json.dumps({key: result[key] for key in keys}, indent=2))
    # A complete snapshot can still contain rejects. Make that visible to automation.
    return 2 if result["failed_documents"] or result["quarantined_records"] else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["etl"]:
        return etl_main(argv[1:])
    parser = argparse.ArgumentParser(description="Run the local CloudTrail detection demo")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    records = payload.get("Records")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        parser.error("Input must contain a Records array of CloudTrail objects")
    try:
        events = [normalize(record) for record in records]
    except ValueError as exc:
        parser.error(str(exc))
    findings = detect(events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"events": events, "findings": findings}, indent=2) + "\n", encoding="utf-8")
    print(f"Normalized {len(events)} events; found {len(findings)} findings. Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
