# Pipeline health monitoring

## Status

Deployed October 30, 2026. All eight alarms reported to Slack. New alarms send one recovery notice when they first leave `INSUFFICIENT_DATA`; that burst confirmed the CloudWatch to SNS to Lambda to Slack path end to end.

![Slack messages from pipeline health alarms](images/slack-health-alarms.png)

## Why

Detections only help if the pipeline that feeds them is running. These alarms watch the pipeline itself and post to the same Slack channel as security findings, with a recovery message when each problem clears.

## Alarms

| Alarm | Fires when | Missing data |
| --- | --- | --- |
| `cloud-detection-processor-errors` | The log processor Lambda reports an error in a 5 minute window | Healthy |
| `cloud-detection-alert-runner-errors` | The detection runner reports an error | Healthy |
| `cloud-detection-simulator-errors` | An attack simulation fails | Healthy |
| `cloud-detection-processing-failures-queued` | A failed processing event is waiting in its queue | Healthy |
| `cloud-detection-alert-failures-queued` | A failed detection run is waiting in its queue | Healthy |
| `cloud-detection-alert-runner-silent` | The runner, scheduled every 15 minutes, has not run for an hour | Alarm |
| `cloud-detection-logs-stale` | No CloudTrail file has been processed for two hours | Alarm |
| `cloud-detection-api-5xx` | The findings API returns server errors | Healthy |

For the two heartbeat alarms, silence is the failure: a stopped function produces no metrics, so missing data counts as breaching. The log freshness alarm relies on the runner's own Athena calls, which create CloudTrail events every 15 minutes, so a healthy pipeline always has files to process.

## Delivery path

CloudWatch alarm, then the `cloud-detection-health` SNS topic, then the alert runner Lambda, which formats the message and posts it to Slack. Only CloudWatch in this account may publish to the topic.

An optional email subscription (`alert_email`) is a backup channel for the case the Slack path itself breaks, such as an invalid webhook. AWS sends a confirmation email before delivering anything.

## Tradeoffs

- **Self-monitoring limit.** Alarms about the alert runner are delivered by the alert runner. If it cannot run at all, only the email backup would notice.
- **Unencrypted topic.** CloudWatch cannot publish to topics encrypted with the AWS managed SNS key, and a customer managed key adds cost. The topic carries alarm metadata only, never log contents.
- **Pausing.** Pausing scheduled detections will trigger the silent runner alarm. That is expected and confirms the alarm works.

## Cost

Eight standard alarms fall within the CloudWatch free tier of ten. SNS and Lambda deliveries cost fractions of a cent.
