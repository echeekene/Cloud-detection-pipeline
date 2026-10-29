# Testing and results

These notes keep track of what we actually tried and what happened. They help us avoid saying a feature works before we have checked it. We will add more results as we build.

## Checking the Terraform code

Environment: Windows AMD64, Terraform 1.9.8, HashiCorp AWS provider 6.71.0. The Terraform distribution checksum was checked against HashiCorp's published SHA256 sums; provider initialization verified the HashiCorp signature. The selected provider and registry checksums are recorded in `infra/foundation/.terraform.lock.hcl`.

| Check | Observed result |
| --- | --- |
| `terraform fmt -check -recursive` | Passed |
| `terraform validate` | Passed: configuration is valid |
| `terraform test` | Passed: 4 runs, 0 failed |
| `git diff --check` | Passed |

Mock test runs:

- `secure_foundation`: public access blocking, ownership, encryption, versioning, logging, multi-region/global management-event collection, digest generation, scoped delivery policy, HTTPS requirement, and default refusal to empty a bucket.
- `reject_invalid_account`: malformed account ID rejected.
- `reject_short_retention`: zero-day retention rejected.
- `explicit_teardown_opt_in`: deletion capability enabled only by explicit input.

These tests do not contact AWS. They validate the declared configuration, not the behavior of deployed services. Live checks are recorded separately below. Hosted [Python tests](https://github.com/echeekene/Cloud-detection-pipeline/actions/runs/40805347850) and [Terraform checks](https://github.com/echeekene/Cloud-detection-pipeline/actions/runs/40805347584) both passed. The first Terraform run exposed a Windows-only package hash in the lock file; adding the official Linux package hash resolved validation on the GitHub runner. Both platforms are now recorded in each module's lock file.

The first local Python milestone was also verified: 7 unit tests passed, and the sample run produced 3 normalized events and 1 finding. All sample events are synthetic.

## Planning the first AWS setup

The refreshed temporary-credential session was verified with STS. A real `terraform plan` succeeded for the selected account in `us-east-1`: **8 to add, 0 to change, 0 to destroy**. We reviewed and applied that scope. Account-specific settings, state, and plans remain local and excluded from Git. Existing trail status was checked without changes. The existing $5 monthly budget and its actual-spend and forecast alerts were verified in the billing console using a separate root browser session. Existing recipients are active; email delivery has not been tested. No budget or IAM permissions were changed. See [the foundation review](FOUNDATION_REVIEW.md).

## Checking the resources in AWS

| Check | Observed result |
| --- | --- |
| Terraform apply | 8 added, 0 changed, 0 destroyed |
| Post-deployment Terraform plan | No changes; infrastructure matches configuration |
| All four S3 public-access-block settings | Enabled |
| S3 policy exposure status | Not public |
| Default encryption and downloaded log encryption | AES256 |
| S3 versioning | Enabled |
| Object ownership | Bucket owner enforced |
| HTTPS-only policy and scoped CloudTrail delivery | Verified against live policy |
| Current and noncurrent log expiration | 30 days each |
| Trail logging, multi-region scope, global service events | Enabled |
| Log-file digest generation | Enabled; digest-chain validation not performed |
| Delivered log inspection | 3 nonempty gzip JSON files; 26 records |
| Harmless action matched inside delivered logs | Successful GetBucketVersioning from our deployment identity against the project bucket |
| CloudTrail delivery error | None reported |

The [sanitized evidence summary](evidence/foundation-verification.json) records inspection counts and original file hashes. Raw downloaded records are retained privately outside Git. Original console screenshots of logging/delivery status and public-access protection are also retained separately for later public evidence preparation.

These first checks verified collection. The later Athena and synthetic Splunk alert results are below. Measured costs, digest-chain validation, and AWS teardown still need work.

## Trying the local Parquet step

Environment: Python 3.12, PyArrow 26.0.0, DuckDB 1.5.6. Editable package installation and the installed command-line entry point were verified in a project-only environment.

- **26 Python tests passed**, covering both the original detector and the new Parquet data layer.
- Three live gzip CloudTrail documents yielded **26 accepted records**, **0 rejected records/documents**, and **1 partition**. SQL against the resulting Parquet returned all 26 rows.
- Exact replay reused the complete snapshot after artifact and manifest integrity checks.
- The SQL no-MFA rule returned **1 finding from 3 synthetic events** and agreed with the Python rule. The live sample returned **0 findings**; it contains no deliberately generated insecure login.
- Tests verified UTC day boundaries, timestamp precision, typed nulls, Snappy compression, invalid documents, bounded decompression, malformed nested fields, cross-file duplicates, account-scoped keys, conflict quarantine, total-limit failure, unexpected artifacts, and refusal to overwrite changed or incomplete outputs.

The [data-layer evidence summary](evidence/data-layer-verification.json) contains the initial local results. Private raw logs, quarantine records, and live Parquet remain outside Git. The [model and run guide](DATA_MODEL.md) documents the contract and limitations. The standalone DDL remains a reference template; Terraform created the actual tables in the next step.

## Trying the samples in Athena

The full Python suite now passes **32 tests**. The additional tests cover selecting only Parquet uploads, checking snapshot integrity, matching Glue columns to Parquet, and checking the proposed query helper with fake AWS responses. The helper stops before submitting a query if the account or scan-limit settings differ.

The analytics Terraform configuration validates and its **3 mock test runs pass**. AWS Access Analyzer returned **no findings** for the Athena/Glue policy, which we attached as `CloudDetectionAnalytics`. After refreshing our developer login, access worked and Terraform created **15 resources**, without changing or deleting existing resources. A follow-up plan reported no changes.

| Athena check | Result |
| --- | --- |
| Real sample row count | 26, matching the local snapshot |
| Real sample no-MFA finding count | 0 |
| Synthetic sample row count | 3, matching the local snapshot |
| Synthetic sample no-MFA finding count | 1 |

All four queries completed successfully through our workgroup. The workgroup enforces the 10 MiB per-query scan limit and encrypted results. The uploaded files matched their local hashes when read back; bucket protections and encryption on all four result files were also checked. The query statistics report 322 bytes scanned in total; this is not a bill or a guarantee of zero cost.

The [Athena evidence report](evidence/athena-verification.json) records the query IDs, counts, scan sizes, and storage checks. A console screenshot of the synthetic result is saved privately outside Git. This verifies a manual SQL detection against synthetic input, not a scheduled alert or a live attack simulation. See [the Athena notes](ATHENA.md).

## Checking the Splunk example

The full Python suite passes **38 tests**. New tests cover the labeled Splunk export, boolean/null handling, original event times, protection against overwriting existing files, and dashboard XML parsing. The prepared exports contain **3 synthetic events** and **26 real events**.

Splunk indexed the samples locally. The private Cloud Detection Lab dashboard shows 26 real events, 3 synthetic events, 1 synthetic no-MFA finding, and 0 real no-MFA findings. These agree with Athena. We corrected a time-zone mistake and restricted the searches to the corrected source type; the first imports remain in the lab index as troubleshooting history. A private scheduled synthetic alert fired and was disabled after verification. Trigger evidence is saved privately. No collector token or outbound notification was created, and this step added no AWS resources or queries. See [the Splunk notes](SPLUNK.md).
