# Trying our data in Athena

The goal for this step was simple: put a small Parquet sample in S3 and run the same SQL in AWS that we tested on our computer.

**This part is deployed and working.** We attached the reviewed project policy, deployed the setup, and ran four query checks successfully. The steps below explain how we did it and how to repeat it with the same small samples.

## What we created

Terraform created **15 resources**, without changing or deleting existing resources:

- One private analytics S3 bucket and six related settings: public-access blocking, ownership, encryption, versioning, expiration rules, and an HTTPS-only policy.
- One Athena workgroup, which is a named place for our query settings.
- One Glue database, two tables, and one registered partition for each table. Glue stores descriptions of the files so Athena knows how to read them.
- Two small Parquet objects, uploaded from the snapshots we already checked locally.

`security_events` holds our 26 real records. `synthetic_events` holds the three made-up records. They use different S3 prefixes, so our demonstration event will not be mistaken for real suspicious account activity.

This is a manual sample upload through Terraform. We are not adding Lambda, a crawler, a scheduler, or a continuously running service yet.

## Cost and storage choices

The workgroup enforces a **10 MiB data-scan limit per query**, the lowest supported cutoff for this setting. It also requires encrypted results in our analytics bucket. These are helpful limits for a small demo, but a per-query limit does not cap the number of queries or our total spending.

The bucket's current and old object versions each have seven-day expiration rules. Actual cleanup can take longer because version retention is separate and S3 expiration is asynchronous. We should save useful evidence and remove the lab when finished rather than relying only on expiry.

There is no reserved capacity or Spark session. Athena SQL, S3, and Glue have their own pricing; our $20 whole-project ceiling still applies. See [Athena pricing](https://aws.amazon.com/athena/pricing/) and [the workgroup settings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup.html).

## The permission change

The deployment user already had S3 and CloudTrail access, but AWS denied Athena and Glue access. We added the `CloudDetectionAnalytics` inline policy from `infra/access/analytics-policy.json.tftpl` for:

- Creating, reading, updating, and removing the `cloud-detection-queries` workgroup, plus running and checking queries there.
- Reading the default Athena catalog.
- Managing the `cloud_detection` Glue database and its two project tables and partitions.
- Listing workgroup names and database names for navigation.

It grants no new IAM, billing, or root access. It does not replace or reduce the user's existing permissions, including its broad S3 and IAM policies. It is a small addition for this stage, not a claim that the whole deployment identity has minimum permissions.

The analytics Terraform code outputs the policy but does **not** attach it. We reviewed and attached that access change separately through the deployment identity's existing IAM permissions. Root was not used for the attachment.

## Prepare the local inputs

Build two clean snapshots first: a small real sample and the three-event synthetic fixture. Keep actual account logs and Parquet files private. From the repository root, use the project environment:

```powershell
python scripts/prepare_analytics.py --live-snapshot work/live-dataset --synthetic-snapshot work/demo-dataset --account-id YOUR_ACCOUNT_ID
```

Substitute the paths where the actual snapshots were written. The helper checks their hashes and completion markers, then writes `infra/analytics/terraform.tfvars.json`. This private file contains the account ID, local paths, chosen partitions, and file hashes. Git ignores it. Only Parquet files are selected for upload; rejected records are not uploaded.

## Check and apply the setup

After the permission change is reviewed and applied, check for an existing project workgroup or database before creating new ones. Do not import or replace an unrelated resource.

```powershell
terraform -chdir=infra/analytics init
terraform -chdir=infra/analytics validate
terraform -chdir=infra/analytics test
terraform -chdir=infra/analytics plan -out=analytics.tfplan
terraform -chdir=infra/analytics show analytics.tfplan
terraform -chdir=infra/analytics apply analytics.tfplan
```

Use the same temporary-credential AWS profile as the first deployment. Check the account with STS before applying. A saved plan applies without another Terraform confirmation prompt, so review it first. Keep the selected local snapshot files unchanged until the upload completes.

Terraform registers the known partitions directly. We do not need to run the standalone table template or `MSCK REPAIR TABLE` for these Terraform-managed tables.

## Run a small check

```powershell
python scripts/check_athena.py --live-snapshot work/live-dataset --synthetic-snapshot work/demo-dataset --profile default --output work/athena-results.json
```

For our one-region samples, the helper runs four queries: a row count and the no-MFA detection count for each table. It checks the account, workgroup settings, local snapshot hashes, and table locations before starting. It waits up to a minute for each query and stops a query that takes longer. The report saves counts, query IDs, and scanned bytes, without copying event identities into the report.

Our results were **26 real rows** and **3 synthetic rows**, with exactly **one no-MFA finding in the synthetic sample** and **none in the real sample**. All four queries completed successfully. They reported 322 bytes scanned in total; this is query statistics, not a measured bill or a claim that the queries are free.

We opened the completed synthetic query in the console and captured its result. Original screenshots with account details stay outside Git. The [query evidence report](evidence/athena-verification.json) keeps counts and query IDs without copying account identities or raw event rows.

## Cleaning up this part

This is a separate Terraform directory with its own state. When we finish, clean up analytics before removing the raw-log foundation. First save useful evidence. Set `allow_data_deletion = true` in the private analytics input file, plan and apply that setting, then review a destroy plan:

```powershell
terraform -chdir=infra/analytics plan -out=allow-cleanup.tfplan
terraform -chdir=infra/analytics show allow-cleanup.tfplan
terraform -chdir=infra/analytics apply allow-cleanup.tfplan
terraform -chdir=infra/analytics plan -destroy -out=destroy.tfplan
terraform -chdir=infra/analytics show destroy.tfplan
terraform -chdir=infra/analytics apply destroy.tfplan
```

The destroy removes the lab tables, partitions, workgroup, sample objects, and bucket. The deletion opt-in lets Terraform empty remaining object versions and query results. Do not run it until we are ready to remove this part. The separately attached access policy needs separate cleanup; this module does not manage that attachment. Cleanup has not been tested yet.

## Checks completed so far

- The analytics configuration passes Terraform validation and three mock test runs. Mock resources are fake; those tests did not create anything in AWS.
- The full Python suite passes 32 tests, including input preparation, Glue/Parquet column agreement, and mocked query checks that stop for a wrong account or changed scan limit.
- The deployment created 15 resources. A follow-up Terraform plan reported no changes.
- AWS IAM Access Analyzer reports no findings for the rendered policy. It is attached to the deployment user; IAM's simulator allows the checked Athena and Glue actions.
- All four live query checks passed, and an original result screenshot was saved privately.
- Both uploaded Parquet files matched their local SHA256 hashes when downloaded again. The bucket is private, has versioning and an HTTPS-only policy, and uses AES256 encryption. All four stored query-result files were also encrypted.

## Something that caught us out

After attaching the policy, IAM's simulator showed the new actions as allowed, but our existing temporary session still received access-denied errors. Refreshing the developer login fixed access for this session. We checked again before deploying, rather than adding a broader policy.

The console also started on the default `primary` workgroup. We switched to `cloud-detection-queries`, where our policy and query limits apply.

## Expanded IAM sample

The controlled IAM scenario added eight selected real records to the original 26, giving 34 real rows across two UTC partitions. The synthetic table still contains three rows. The IAM attachment SQL returned one finding, while the no-MFA checks stayed at zero real findings and one synthetic finding. Storage protections and the workgroup query limit stayed unchanged. See the [scenario investigation](INVESTIGATION_IAM_POLICY.md) and its separate evidence report for the new result; the earlier 26-row evidence remains the baseline.
