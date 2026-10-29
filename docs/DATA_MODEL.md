# How we clean and store the logs

We start with a small set of CloudTrail files and turn each good event into one row. The original logs stay unchanged so we can go back and check our work. This step runs on our computer for now. VPC Flow Logs will need their own reader later.

Some terms used below:

- **Normalize:** give events the same field names and data types.
- **Partition:** put related rows in folders, such as one folder per day and region.
- **Quarantine:** set bad or conflicting records aside so we can inspect them.
- **Snapshot:** the complete output folder from one run.
- **Manifest:** a small report listing output files and record counts.

The detailed notes below are here to help us follow the code. We can revisit these choices as we get more experience with real logs.

## Run it

From the repository root, with Python 3.11 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[test]"
.\.venv\Scripts\python.exe -m cloud_detection etl --input examples/cloudtrail.json --output work/demo-dataset
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On Linux/macOS, use `.venv/bin/python` in place of the Windows interpreter path. The installed `cloud-detection` command accepts the same arguments as `python -m cloud_detection`.

Use repeated `--input` arguments to combine files, or pass a directory to discover `.json` and `.json.gz` files recursively. CloudTrail digest documents are not event envelopes and are rejected if included; point the command at event logs, not digest folders. Keep outputs outside input directories so replay cannot ingest its own metadata.

## Snapshot layout

```text
snapshot/
  parquet/
    event_date=<UTC day>/
      region=<AWS region>/
        part-00000.parquet
  quarantine/
    records.jsonl
  manifest.json
  _SUCCESS
```

We derive partitions from the event's UTC time and source region, not the time the file arrives. Partition fields are encoded in Hive-style directory names and omitted from the Parquet payload. Files use Snappy compression and an explicit Arrow schema, so a column that happens to contain only nulls does not change type between runs.

`event_time` is stored as a UTC timestamp with millisecond precision for the initial Athena table. Submillisecond digits are retained in `event_time_iso`, up to Python's supported microsecond precision. Higher-precision input is rejected rather than silently losing digits. Partition dates use the UTC instant before precision reduction.

The timestamp and partition choices follow [Athena's timestamp guidance](https://docs.aws.amazon.com/athena/latest/ug/data-types-timestamps.html), [Athena engine precision considerations](https://docs.aws.amazon.com/athena/latest/ug/engine-versions-reference-0003.html), and [Arrow's Parquet writer documentation](https://arrow.apache.org/docs/python/generated/pyarrow.parquet.write_table.html).

## What one row contains

The deduplication key is `(account_id, event_id)`. Account ID comes from `recipientAccountId`, falling back to the identity's account. When neither is present, it stays null and events are deduplicated by event ID within that unknown-account group. This assumes CloudTrail event IDs identify the same event; it does not infer identity from timestamps or source IPs.

| Field | Parquet type | Meaning |
| --- | --- | --- |
| event_id | string, required | CloudTrail event ID |
| event_time | timestamp in milliseconds, required | UTC instant, with submillisecond digits removed |
| event_time_iso | string, required | UTC ISO representation retaining supported source precision |
| event_source | string, required | AWS service that produced the event |
| event_name | string, required | Action name |
| account_id | nullable string | Recipient account, or identity account fallback |
| source_ip | nullable string | CloudTrail source address; can also be a service name |
| principal | nullable string | Identity ARN, falling back to principal ID |
| principal_type | nullable string | CloudTrail identity type |
| outcome | string, required | success, failure, or unknown |
| error_code | nullable string | AWS error code, when present |
| mfa_used | nullable boolean | Explicit console-login MFA evidence only |
| event_date | partition string | UTC event day |
| region | partition string | Validated source AWS region |

For console logins, success/failure comes from the console response or an error code; a missing result remains unknown. For other API events, an error code means failure, and absence of an error code is classified as success. That is an event outcome convention, not an independent authorization check.

MFA `Yes` and `No` are mapped to true and false for console login events. Missing or unrecognized strings remain null. API-session MFA context and federated identity assurance are separate concerns; we do not interpret them as console-login MFA evidence.

## Data quality and quarantine

- Missing IDs, source/action/region fields, invalid timestamps, invalid field types, malformed nested objects, and unsafe region strings are rejected individually. Valid neighboring records continue.
- Unreadable gzip, invalid JSON, or missing `Records` envelopes are counted as failed documents. Their bytes are not copied into the quarantine file; the original input and its content hash remain the reference.
- Exact repeated records sharing an event key produce one accepted row. JSON object key order does not affect equality.
- If records sharing a key have different canonical raw content, every copy in that group is quarantined. We do not pick a winner or count those copies as accepted duplicates.
- The manifest reconciles `records_seen = accepted_records + duplicate_records + quarantined_records`. Failed documents have a separate count because their record count is unknown.

Quarantine entries include reason, source-content hash, record index, and raw record where parsing succeeded. These files can contain sensitive account details. Keep them private with the inputs; do not commit them. The console command prints aggregate counts only.

## What happens when we run it again

The input fingerprint includes source-file hashes, pipeline version, and input limits. Repeating the exact input set against a complete snapshot checks the manifest hash and every listed artifact hash, rejects unexpected Parquet files, and reuses the existing output. New inputs require a new output directory. Incomplete or corrupt outputs are refused rather than overwritten.

Publication writes into a temporary sibling directory, then renames the completed snapshot into place. Consumers must require `_SUCCESS` and its matching manifest. `_SUCCESS` means the run completed, not that every source record was valid. The CLI returns status 2 when a completed snapshot contains rejected documents or records, and status 0 for a clean snapshot. Fatal input-limit and output errors do not publish a partial snapshot.

Deduplication applies within one snapshot. Do not point a query at multiple overlapping snapshots and assume cross-snapshot deduplication. This design is a local, single-writer checkpoint; it is not an S3 transaction protocol or a replacement for a persistent ingestion ledger.

Limits: at most 1,000 source files, 8 MiB compressed/plain and decompressed bytes per document, and 64 MiB total parsed document bytes by default. Limits constrain input size rather than exact process memory. We retain a snapshot's event groups in memory, so larger workloads need streaming or persistent state. There is no incremental merge, file compaction, automated source retry, or star-schema dimension layer yet.

## Getting ready to query with SQL

`sql/schema/security_events.sql` defines the external-table template and Hive partitions. Replace its location with one selected snapshot's `parquet/` prefix after cloud publication. Keep quarantine and manifests outside the table location.

`sql/detections/console_login_without_mfa.sql` uses three positional parameters: start UTC day, end UTC day, and region. Dates are strings in ISO day format, and Athena string execution parameters need single quotes around their values. See [AWS's parameter documentation](https://docs.aws.amazon.com/athena/latest/ug/querying-with-prepared-statements.html). The partition filters bound the selected scope, and our deployed workgroup adds a 10 MiB scan limit per query.

We tested this SELECT against Parquet using DuckDB, then ran it in Athena against separate real and synthetic tables. The Athena checks matched our local results. The standalone DDL file remains a reference template; Terraform created the actual Glue tables and registered their partitions. See [the Athena steps and results](ATHENA.md).

## Observed results

- All 26 Python tests passed, including real Parquet round trips, UTC partitioning, rejection handling, duplicate/conflict behavior, replay integrity, and SQL detection behavior.
- Three downloaded live CloudTrail files yielded 26 accepted records, no duplicates, no rejects, and one partition. SQL read back all 26 rows.
- The live sample yielded no no-MFA login findings. We did not manufacture a live insecure login.
- The three-event synthetic fixture yielded exactly one no-MFA finding through the SQL query.
- Exact replay of the live sample reused the existing snapshot without creating new dataset files.

See the [local verification summary](evidence/data-layer-verification.json) and the later [Athena results](evidence/athena-verification.json). The selected samples are now in a private analytics bucket. Account logs and live Parquet files remain outside Git.
