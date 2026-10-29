# Notes on our first AWS setup

Our first goal was to collect real account logs in a separate bucket. These notes explain what we created, what it costs to run, and what still needs checking.

Status: deployed; bucket protections and live CloudTrail delivery verified.

## What we created

Target region: US East (N. Virginia), `us-east-1`. The account in the authenticated AWS session matches the required local account configuration. Account-specific settings and the saved plan are excluded from Git.

Terraform applied **8 additions, 0 changes, 0 deletions**:

1. Dedicated raw-log S3 bucket.
2. Public-access-block configuration.
3. Bucket-owner-enforced object ownership.
4. Default SSE-S3 encryption.
5. Bucket versioning.
6. Lifecycle configuration for lab logs and expired delete markers.
7. HTTPS-only bucket policy with CloudTrail delivery scoped to the new trail ARN and account log prefix.
8. Multi-region management-event trail with global service events and log-file validation enabled.

The existing account trail is single-region and stopped. Its status was checked through AWS; this plan does not manage or change it. The account-wide trail list returned only that existing trail at review time. Recheck overlap if other trails are enabled later.

## Keeping costs small

Our spending ceiling is **USD 20 total for the build**, and we aim to spend less. We are reserving most of that budget for later milestones.

This plan adds no EC2 instances, NAT gateways, RDS databases, CloudWatch log ingestion, customer-managed KMS keys, Insights, or CloudTrail Lake. It collects management events only; S3 object data events and VPC Flow Logs are not enabled yet.

[CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) lists the first copy of management events delivered to S3 at no CloudTrail event charge; additional copies are billable. [S3 storage and requests](https://aws.amazon.com/s3/pricing/) remain usage-based. No exact dollar estimate or fixed spending guarantee is claimed without measuring event volume and storage. Existing unrelated account usage is outside this project's cost scope. Credit balances are not a substitute for measuring costs.

We verified the existing account-wide **$5 monthly cost budget** through the billing console. It reports healthy status, with alerts when actual spending exceeds **$4.25**, actual spending exceeds **$5**, or forecasted spending exceeds **$5**. All three existing email recipients are marked **Active (legacy)** and do not require verification. Alert configuration is verified; actual email delivery has not been tested.

We are retaining these early warnings. The monthly budget resets each month and does not enforce our **$20 total build ceiling**. Alerts do not impose a hard spending cap and may arrive after usage occurs. The deployment identity still lacks budget-view permissions; no permission expansion or budget change was needed.

## What we checked and what is left

- Budget alerts are verified; continue tracking cumulative project usage across billing months.
- The deployment ran through our MFA-protected IAM identity, without using root credentials for Terraform.
- Live read-back checks confirmed the bucket protections, retention settings, scoped delivery policy, and trail configuration.
- We inspected 3 delivered log files containing 26 records and matched a successful `GetBucketVersioning` event to our verification action. Downloaded log objects were encrypted with AES256, and CloudTrail reported successful delivery without a delivery error.
- A follow-up Terraform plan reported no differences between AWS and the configuration.
- Original screenshots are kept privately outside Git. The [sanitized verification summary](evidence/foundation-verification.json) contains counts and file hashes, without account identifiers or raw event records.
- Cost measurement, digest-chain validation, public screenshot preparation, and live teardown verification remain pending.
- Retain local Terraform state for teardown. Never publish the saved plan, local account settings, state, or raw account logs.

The observed results verify this foundation's deployment and collection path. They do not establish that an Athena detection or Splunk alert has fired; those components are still to be built.
