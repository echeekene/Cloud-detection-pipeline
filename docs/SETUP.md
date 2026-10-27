# Setup: Logging Foundation

## What this builds

| Resource | Purpose |
|---|---|
| S3 log bucket | Central evidence store, encrypted, versioned, private, 30 day expiry |
| CloudTrail | Every API call in every region, with tamper proof digests |
| VPC + Flow Logs | Network visibility, and a home for Splunk |
| GuardDuty | AWS managed detection, used as a baseline against custom rules |
| Athena + Glue | SQL over the logs, with a 1 GB per query cost cap |

## Before you run anything

1. **Create a sandbox account.** In the account hosting ekeneeche.com, open AWS Organizations and add a new member account (for example `detection-sandbox`). Stratus Red Team creates intentionally insecure resources, so keep them away from your real site.
2. **Set a budget alert** in the sandbox account ($15 is a sensible ceiling).
3. **Install tools:** Terraform (via `winget install Hashicorp.Terraform` or `brew install terraform`) and the AWS CLI.
4. **Configure a CLI profile** named `detection-sandbox` that points at the new account (IAM Identity Center is the cleanest option).

## Deploy

```bash
cd terraform
terraform init
terraform plan      # read this output, every resource should make sense to you
terraform apply
```

Check that the `account_id` output matches your sandbox account.

## Create the Athena tables

Open Athena, select the `cdp-detections` workgroup, then Saved queries. Run `00`, then `01`. Wait about 15 minutes for CloudTrail to deliver logs, then run `02`.

## Evidence to capture

- `terraform apply` output
- GuardDuty console showing the detector enabled
- Sanity check query returning rows
- S3 bucket showing the `AWSLogs/` folder structure

## Teardown

```bash
terraform destroy
```

Then close the sandbox account from AWS Organizations.
