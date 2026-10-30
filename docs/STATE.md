# Terraform state

## Design

All modules keep their state in one S3 bucket, `cloud-detection-<account>-us-east-1-tfstate`, created by [infra/state](../infra/state/main.tf).

- **Locking:** S3 native locking (`use_lockfile = true`, Terraform 1.11 or newer). A second `apply` waits instead of corrupting state. No DynamoDB table is needed.
- **Recovery:** versioning keeps earlier state files; old versions expire after 90 days.
- **Protection:** public access blocked, SSE-S3 encryption, and a policy that denies requests without TLS. The bucket cannot be deleted by Terraform unless `allow_state_deletion` is set.
- **One key per module:** `foundation/`, `analytics/`, `scenario/`, `automation/`, and `api/` each have their own state file, so a mistake in one module cannot overwrite another.

Shared settings live in `infra/backend.hcl`, copied from [backend.hcl.example](../infra/backend.hcl.example). Git ignores it because it contains the account ID. Each module's `backend "s3"` block supplies only its key.

The `infra/state` module itself keeps local state. It cannot store state in a bucket that does not exist yet. It manages a single bucket, so a lost state file is recovered with `terraform import`.

## Using it

```powershell
cd infra\<module>
terraform init -backend-config=..\backend.hcl
terraform plan
```

CI runs `terraform init -backend=false`, so GitHub Actions never needs access to state.

## Migration record (October 30, 2026)

Before this change, state lived in two places: four modules on the laptop and the API module in AWS CloudShell. Each was moved with `terraform init -migrate-state` using Terraform 1.16.6, then checked with `terraform plan`.

| Module | Result after migration |
| --- | --- |
| foundation | Moved. Plan shows only `enable_logging` false to true: the trail was deliberately paused on October 29, not changed by the migration. |
| analytics | Moved. Plan shows only the three sample files' local source paths, which moved out of a temporary working folder. Content and hashes are unchanged. |
| scenario | Nothing to move: the controlled scenario's resources were removed after the exercise, so its state was empty. A state file appears on its next apply. |
| automation | Moved. Plan shows only the pause being reversed (S3 trigger and Lambda concurrency) and the package's new local path. |
| api | Moved from CloudShell. Plan: no changes. |

`aws s3 ls` on the state bucket listed `foundation/`, `analytics/`, `automation/`, and `api/` state files. Superseded local state files were moved to a private backup outside the repository.

**Lesson:** drift showed up immediately. The first plan after migration exposed the paused trail, which is exactly the kind of out-of-band change remote state and regular plans are meant to surface.

## Teardown order

Destroy every other module first, then remove the state bucket:

1. Destroy `api`, `automation`, `scenario`, `analytics`, and `foundation`.
2. In `infra/state`, set `allow_state_deletion = true`, apply, then destroy.
