# Scheduled detections and Slack alerts

## Status

Code, Terraform, deploy policy, and tests are written. Deployment results are recorded below once verified.

## How it works

1. An EventBridge rule invokes the `cloud-detection-alert-runner` Lambda every 15 minutes.
2. The runner queries `cloud_detection.automated_events` in Athena for every rule in [detections.py](../cloud_detection/detections.py), looking back 90 minutes. The overlap covers CloudTrail's delivery delay of up to about 15 minutes.
3. Each finding is checked against a DynamoDB table keyed by rule and event ID. New findings are posted to Slack, then recorded with a seven-day expiry.
4. Slack messages carry the rule name and severity, the action and principal, source IP, region, MITRE ATT&CK link, and a link to the rule's [runbook](runbooks/).

## Design choices

- **At-least-once delivery.** A finding is recorded only after Slack accepts it. A crash between the two can repeat one alert but never drop it.
- **No retries, overlapping windows.** A failed run goes to the `cloud-detection-alert-failures` queue; the next run's 90-minute lookback covers the gap.
- **Burst cap.** At most 20 alerts per run, plus a notice if more are waiting.
- **Secret handling.** The Slack webhook is a SecureString parameter, `/cloud-detection/slack-webhook`, created outside Terraform so the value never enters Terraform state. Only the runner role can read it, and the code refuses any URL that is not a Slack incoming webhook.
- **Least privilege.** The runner can query one workgroup, read the automated table's data, write query results, read the webhook, and get and put dedupe records. It cannot write to Glue, delete records, or change the parameter.
- **Pause without drift.** Setting `enabled = false` disables the schedule through Terraform, a lesson from the earlier out-of-band pause.

## Deploying

Deploy permissions are in [alerts-policy.json.tftpl](../infra/access/alerts-policy.json.tftpl), attached as `CloudDetectionAlertsDeploy` to the `cloud-detection-deployers` group.

```powershell
$u = Read-Host "Paste Slack webhook URL"
aws ssm put-parameter --name /cloud-detection/slack-webhook --type SecureString --value $u
Remove-Variable u

python scripts\build_api_package.py --target alerts --output work\alerts-package.zip --tfvars infra\alerts\terraform.tfvars.json --account <ACCOUNT_ID>
cd infra\alerts
terraform init "-backend-config=..\backend.hcl"
terraform test
terraform plan -out alerts.tfplan
```

Send a test message after applying:

```powershell
aws lambda invoke --function-name cloud-detection-alert-runner --cli-binary-format raw-in-base64-out --payload '{\"test\": true}' work\alert-test.json
```

## Cost

Ninety-six runs a day, each one Athena query per region within the 10 MiB scan limit, plus on-demand DynamoDB and a small Lambda. Expected cost is a few cents a month.
