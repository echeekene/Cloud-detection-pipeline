# Automatic CloudTrail processing

## Status

The processor is deployed, and the filtered S3 notification is enabled. A newly delivered CloudTrail file was processed without manual invocation, and its harmless verification event was found once in Athena. Manual snapshots and the local Splunk examples remain separate and usable.

The [provisioning policy](../infra/access/automation-policy.json.tftpl) passed AWS Access Analyzer validation without findings and was attached as a customer-managed policy. It covers the named project function, log group, failure queue, and automated table. Lambda account capacity and log-group discovery require read-only actions with wildcard resources. Existing broader IAM and S3 permissions remain a separate limitation.

## Data path

1. A new compressed event log arrives under the project account's `CloudTrail/` prefix in the raw bucket.
2. An S3 object-created notification invokes the Python Lambda. The filter excludes digest files and unrelated objects.
3. The handler reads the indicated object version, or uses an ETag condition when no version ID is supplied.
4. The existing processor validates and normalizes the records, quarantines bad records, and writes Parquet.
5. The handler publishes Parquet into the analytics bucket under `automated/parquet/event_date=.../region=.../`. Manifests, quarantine records, and completion markers go under `automated/runs/`.
6. A separate `cloud_detection.automated_events` Glue table uses Athena partition projection. Queries must supply a region filter. The manual sample tables remain separate.

The runtime reads only the project CloudTrail input prefix and reads or writes only the automated output prefix. Its list permission is restricted to completion-marker prefixes. It has no Glue, Athena, IAM, or object-deletion permissions. Separate input and output buckets prevent output files from triggering the input notification.

This change automates transformation and queryable storage. It does not automatically forward events to local Splunk or schedule Athena detections.

## Retries and completion

S3 notifications can be delivered more than once and out of order. A run ID includes the source bucket, key, version or ETag, and pipeline version. Output names are stable for that run. The completion marker is written last, and a replay verifies the manifest and published artifact hashes before reusing the result.

If a write fails partway through publication, a retry writes the same object keys. This avoids creating a new Parquet filename for every retry. It is not a transaction across partitions: Athena can see a published partition before the completion marker is written.

Different source objects or versions produce different runs. Events repeated across files may therefore still appear more than once in the table. Query-time deduplication and cross-object conflict handling need a separate design. The local processor still deduplicates and quarantines conflicting copies within each input object.

Malformed records are kept in quarantine while valid neighbors continue. Invalid compressed documents are recorded as failed documents with quarantine metadata and a completed run. Infrastructure failures and oversize source objects fail the invocation instead of being marked complete.

## Resource and failure limits

- Python 3.12 on x86_64, 512 MB memory, and a 60-second timeout. The account has a shared concurrency limit of ten. Its quota cannot support a separate reservation of one, so the function uses shared capacity and has no independent concurrency cap. The module supports a reservation where the account quota allows it.
- An 8 MiB compressed and decompressed source-document limit. Published artifacts are limited to 64 MiB.
- One asynchronous retry and a one-hour maximum event age.
- Failed invocations go to a managed-encrypted SQS queue with one-day retention. A person must inspect and replay failures; there is no automatic queue consumer.
- CloudWatch logs retain count summaries for three days. The handler does not intentionally print raw events.
- Existing analytics lifecycle rules expire the automated data and deployment archive after seven days. Lambda retains its deployed code, but a later deployment may need to upload the package again.

These settings bound individual invocations and retention. They do not impose a hard account spending cap. Lambda concurrency availability must be checked before deployment; increasing the account quota later would also increase this function's possible shared concurrency.

## Package construction

The bundle contains the pipeline modules and the official PyArrow 26 wheel for CPython 3.12, manylinux 2.28, x86_64. The wheel is downloaded from PyPI and checked against its published SHA256. The builder rejects other platforms, unexpected dependencies, unsafe paths, and packages over Lambda's uncompressed limit. Stable archive ordering and metadata make the output reproducible for unchanged inputs.

```powershell
python scripts/build_lambda_package.py --wheel work/pyarrow-linux.whl --wheel-sha256 <published-sha256> --output work/cloud-detection-lambda.zip
```

Use the actual wheel path and checksum. Windows-native PyArrow files cannot be copied into the Lambda zip. The AWS runtime supplies Boto3; its version is not bundled or pinned by this package. Native imports must still be verified by invoking the deployed function.

## Deployment and validation sequence

1. Review the proposed permissions and attach them only after approval.
2. Confirm the raw bucket has no unrelated notification configuration. The Terraform notification resource owns the whole configuration, so it must not overwrite another system's destinations.
3. Check Lambda concurrency capacity. Build the package and put its path and checksums into a private Terraform variable file.
4. Plan and deploy `infra/automation` with `enable_notifications = false`.
5. Invoke the function with one existing versioned CloudTrail object. Verify the output schema, encryption, record counts, quarantine, and Athena result. Invoke the same event again and confirm no new output keys appear.
6. Explicitly enable the filtered notification, generate a harmless account action, and verify that a newly delivered log is processed without a manual invocation.
7. Inspect the failure queue and logs. Keep raw event records and account-specific receipts private; publish only checked aggregate results.

To pause new automatic invocations, disable the bucket notification. Full cleanup must also account for pending asynchronous invocations, the function, queue, log group, table, role, deployment archive, and output versions.

## Local checks and costs

The full Python suite passes 52 tests. New checks cover replay, partial publication, artifact corruption, wrong input sources, object versioning, ETag pinning, quarantine, separate buckets, and deterministic Linux packaging. The automation module adds three Terraform mock tests to the existing nine.

The current billing console showed an estimated USD 0.00 with the bill pending. This is an account-wide estimate for the selected current period, not a finalized project total or a guarantee of zero cost. The whole-build ceiling remains USD 20. No new service subscription or plan upgrade was started.

## Verified live results and stopping point

- Deployment created nine resources with the trigger disabled, then added the single filtered bucket notification after manual verification.
- The deployed function processed an existing versioned CloudTrail object into 17 accepted records, with no rejected records or failed documents. Athena read all 17.
- Replaying that notification reused the checked output. Published Parquet and quarantine artifacts were verified as encrypted.
- After enabling notifications, a new delivered CloudTrail file produced 75 accepted records with no rejects or failed documents. The harmless verification event appeared once in Athena without a manual Lambda invocation for that file.
- One deliberately invalid notification failed with ValueError. After the initial attempt and one retry, its failure record reached SQS. The exact test message was acknowledged, and both visible and in-flight queue counts were zero.
- The manual sample tables and Splunk datasets were not replaced by the automated output.

The [aggregate verification report](evidence/automation-verification.json) records these results. Original event payloads, source objects, runtime receipts, and billing screenshots remain private outside Git. Logging and the automatic processing trigger remain enabled at this stopping point; local Splunk test alerts remain disabled.

## Deployment issues encountered

The deployment identity exceeded its inline-policy size limit, so the same scoped permissions were attached as a customer-managed policy. The developer session then needed a normal sign-in refresh before the new permissions were available.

Terraform also needed GetFunctionCodeSigningConfig to read function metadata. Adding that read action for the same function allowed deployment to resume. The function had already been created and passed a real invocation and replay test, so its interrupted Terraform status was reconciled before applying the two remaining configuration resources. No duplicate function was created.

The small account concurrency quota prevented a one-execution reservation. Shared capacity was used without a quota increase. The retry behavior is therefore based on stable object names and integrity checks, not on an assumption that only one invocation can run at a time. Cross-object deduplication and atomic publication across partitions remain limitations.

## References

- [AWS S3 event notification delivery](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html)
- [AWS Lambda Python deployment packages](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html)
- [Athena partition projection](https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html)
