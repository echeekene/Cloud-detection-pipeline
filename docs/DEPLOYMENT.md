# Setting up AWS and cleaning up afterward

These are the commands for the first AWS part of our project. We keep them here so we can follow the setup again and know how to remove what we created. Run through the plan before applying changes, and keep the state file for cleanup.

Status: foundation deployed and live log delivery verified. This guide covers only the dedicated lab trail and raw-log bucket. See [validation evidence](VALIDATION.md) for observed results. Teardown is documented but has not been executed.

## What this creates

- One dedicated S3 bucket, named with project, account ID, and home region.
- Public access blocked, bucket-owner-enforced object ownership, HTTPS-only bucket policy, default SSE-S3 encryption, and versioning.
- Lifecycle rules that expire current and noncurrent lab logs after 30 days by default. Versioned object removal can take longer than 30 days because current and noncurrent retention periods are separate; expiration is asynchronous.
- One multi-region CloudTrail trail collecting read and write management events, including global service events, with digest generation enabled.
- CloudTrail delivery permission restricted to this trail ARN and this account's log prefix, following [AWS's bucket policy guidance](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html).

This stage does not create VPC resources, Flow Logs, S3 data-event logging, Lambda, Athena, Splunk, Bedrock, IAM users, access keys, budgets, or a GitHub deployment role. S3 object-level activity such as GetObject requires later data-event configuration; management events alone do not cover it.

## Before deployment

1. Choose the existing AWS account or a new dedicated account, then confirm the region. `us-east-1` is an editable example default.
2. Enable MFA for root and the identity used for human access. Use a named temporary-credential AWS CLI profile for Terraform. Do not put passwords, access keys, or MFA recovery material in this repository.
3. Inspect existing trails and organization logging. This lab creates an additional trail and does not import or change an existing one. Review duplication and [current CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) before applying; additional management-event copies and S3 storage/requests can incur charges.
4. Agree on a spending ceiling and configure an AWS budget alert. This module does not create a budget or enforce a spending cap.
5. Install AWS CLI v2 and Terraform 1.9.8 or later. The initial local validation uses Terraform 1.9.8; the provider lock file records the actual AWS provider selected.

Run commands from the repository root. Substitute your own configured AWS profile name:

```powershell
$env:AWS_PROFILE = "your-lab-profile"
aws sts get-caller-identity
Copy-Item infra/foundation/terraform.tfvars.example infra/foundation/terraform.tfvars
```

Edit `terraform.tfvars`: replace the placeholder account ID with the account shown by STS, confirm the region, and keep `allow_log_deletion = false`. The provider's `allowed_account_ids` setting rejects credentials from a different account during real operations. Mock tests do not prove this runtime account check.

The deploying identity needs permissions to manage this project's S3 bucket configuration and trail, plus read account identity. This module stays a manual deploy and does not require root. Later modules deploy through GitHub Actions with OIDC; see [CICD.md](CICD.md).

## Validate and review

```powershell
terraform -chdir=infra/foundation init
terraform -chdir=infra/foundation fmt -check -recursive
terraform -chdir=infra/foundation validate
terraform -chdir=infra/foundation test
terraform -chdir=infra/foundation plan -out=foundation.tfplan
terraform -chdir=infra/foundation show foundation.tfplan
```

The tests use a mocked AWS provider. They check configuration intent without credentials or resources. A real plan needs valid credentials and confirms compatibility with the selected account. Review the plan for only the intended bucket, its configuration, and the trail. Resolve bucket-name collisions rather than importing unrelated storage.

After we review the real plan together, deploy that saved plan:

```powershell
terraform -chdir=infra/foundation apply foundation.tfplan
```

Applying a saved plan executes it without a further Terraform confirmation prompt. Treat the plan as the exact approval artifact. Re-plan after configuration or account changes. State and plan files stay local and are excluded from Git; preserve state securely because it is needed to manage and remove the resources. This initial module uses local state. A secured remote backend is required before shared automated deployments.

## Verify delivery and capture evidence

```powershell
terraform -chdir=infra/foundation output
$trailArn = terraform -chdir=infra/foundation output -raw trail_arn
aws cloudtrail get-trail-status --name $trailArn --region us-east-1
$logPrefix = terraform -chdir=infra/foundation output -raw cloudtrail_log_prefix
aws s3 ls $logPrefix --recursive
```

Replace `us-east-1` in the status command if a different home region was selected. Allow delivery time, then confirm `IsLogging`, a successful recent delivery time, and absence of delivery errors. Perform a harmless read-only console/API action and locate its event in a delivered `.json.gz` file. Capture the event ID and timestamp as evidence. Do not claim successful collection based only on an applied plan.

Capture public-access-block, encryption, and versioning settings along with trail status. Digest generation is enabled; validating the digest chain with CloudTrail's validation tooling is a separate verification step. Versioning and digests do not prevent a sufficiently privileged administrator from deleting logs. This short-lived lab deliberately omits Object Lock; it is not an immutable production audit archive.

Keep screenshots and sample events sanitized before committing: remove account IDs, identity details, actual source IPs, and other identifying metadata. Keep MFA recovery material out of all screenshots.

## Teardown

Export sanitized evidence first. This procedure removes this lab trail and its bucket, including stored object versions after opt-in. It does not touch other trails, the AWS account, or MFA settings. Keep independent account audit logging if needed after the lab ends.

By default, `force_destroy` is false and a nonempty bucket blocks deletion. Merely passing an opt-in to `terraform destroy` is insufficient: first apply the setting so Terraform records it in state.

1. Set `allow_log_deletion = true` in your local `terraform.tfvars`.
2. Review and apply the opt-in plan. It should only change the bucket's deletion setting at this milestone.

```powershell
terraform -chdir=infra/foundation plan -out=teardown-opt-in.tfplan
terraform -chdir=infra/foundation show teardown-opt-in.tfplan
terraform -chdir=infra/foundation apply teardown-opt-in.tfplan
```

3. Generate and inspect a separate destroy plan. Applying it permanently removes the lab logs and their versions.

```powershell
terraform -chdir=infra/foundation plan -destroy -out=destroy.tfplan
terraform -chdir=infra/foundation show destroy.tfplan
terraform -chdir=infra/foundation apply destroy.tfplan
terraform -chdir=infra/foundation state list
```

Terraform's dependency graph removes the trail before removing its destination configuration and bucket. Confirm the state list is empty and verify the named trail and bucket are absent in AWS. If any deletion fails, retain state, inspect the error, and finish cleanup; do not assume costs have stopped. Restore the local opt-in to false before a later deployment.

## Known tradeoffs

- SSE-S3 avoids a customer-managed KMS key in this first slice. A later KMS design can add key-policy control and associated cost/operations.
- Lifecycle expiry favors a temporary portfolio lab over long-term evidence retention. It must be revisited for production.
- The bucket policy does not deny all authenticated readers; access also depends on account IAM permissions. Reader roles will be scoped when the processing layer is added.
- AWS deployment and log delivery are verified, and original screenshots are retained privately. Cost measurement, public screenshot preparation, digest-chain validation, and live teardown evidence remain **To be documented**.
