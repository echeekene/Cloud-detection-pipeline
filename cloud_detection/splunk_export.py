"""Write one normalized JSON event per line for a small manual Splunk upload."""

import argparse
import json
from pathlib import Path
import re

import pyarrow.parquet as pq

from .dataset import verify_snapshot


def export_snapshot(snapshot, output, sample_kind):
    if sample_kind not in ("live", "synthetic"):
        raise ValueError("Choose live or synthetic so the samples stay clearly labeled")
    snapshot = Path(snapshot).resolve()
    output = Path(output).resolve()
    if output == snapshot or snapshot in output.parents:
        raise ValueError("Keep the export outside the completed snapshot")
    if output.exists():
        raise ValueError("The export already exists; choose another output path")
    manifest = verify_snapshot(snapshot)
    if manifest["failed_documents"] or manifest["quarantined_records"] or not manifest["accepted_records"]:
        raise ValueError("Use a nonempty snapshot without rejects for this first Splunk example")
    events = []
    for artifact in manifest["artifacts"]:
        if not artifact["path"].endswith(".parquet"):
            continue
        match = re.fullmatch(r"parquet/event_date=(\d{4}-\d{2}-\d{2})/region=([a-z0-9-]+)/[a-zA-Z0-9_.-]+\.parquet", artifact["path"])
        if not match:
            raise ValueError("Unexpected Parquet partition path")
        day, region = match.groups()
        for row in pq.ParquetFile(snapshot / artifact["path"]).read().to_pylist():
            event = {key: value for key, value in row.items() if key not in ("event_time", "event_time_iso")}
            event.update({
                "event_time": row["event_time_iso"], "event_date": day, "region": region,
                "project": "cloud_detection", "sample_kind": sample_kind,
                "dataset_id": manifest["input_fingerprint"],
            })
            events.append(event)
    if len(events) != manifest["accepted_records"]:
        raise ValueError("Export row count does not match the snapshot")
    data = "".join(json.dumps(event, sort_keys=True, allow_nan=False) + "\n" for event in events)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids accidentally replacing an earlier export.
    with output.open("x", encoding="utf-8") as stream:
        stream.write(data)
    return {"sample_kind": sample_kind, "events_exported": len(events), "dataset_id": manifest["input_fingerprint"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sample-kind", required=True, choices=("live", "synthetic"))
    args = parser.parse_args()
    try:
        result = export_snapshot(args.snapshot, args.output, args.sample_kind)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
