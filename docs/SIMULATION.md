# Continuous detection validation

## Results

First scorecard, October 30, 2026: **2 of 2 simulated attacks detected, 0 missed, median time to detect 10 minutes** (`access_key` and `trail_stop`). The `access_key` detection was found and recorded correctly but its Slack message was lost to the malformed webhook described in [ALERTS.md](ALERTS.md).

## Why

A detection that never fires might be broken, and nobody would know. Every six hours an attack simulator performs one harmless, reversible action that a rule should catch, records what it did, and the daily scorecard reports whether the pipeline noticed and how fast.

## Scenarios

| Scenario | Action, always reversed | Rule it should trigger | MITRE ATT&CK |
| --- | --- | --- | --- |
| `access_key` | Create an access key on the canary user, then delete it | `iam_access_key_created` | T1098.001 |
| `attach_policy` | Attach a deny-all policy to the canary user, then detach it | `iam_managed_policy_attached` | T1098.003 |
| `public_access_block` | Remove the empty canary bucket's public access block, then restore it | `s3_public_access_block_removed` | T1530 |
| `trail_stop` | Stop the project trail for five seconds, then start it | `cloudtrail_logging_disabled` | T1562.008 |

Root sign-in and console login without MFA cannot be simulated without a person signing in. Those rules stay covered by synthetic events in the test suite.

## How scoring works

1. The simulator writes a record to `cloud-detection-simulations` before acting, then marks it `completed` or `failed`.
2. CloudTrail delivers the event, the processor writes it to `automated_events`, and the alert runner finds it on its next 15-minute run.
3. Findings whose principal is the simulator's role are posted to Slack as **[SIMULATION]** so they are never mistaken for an incident. The runner links each one to the nearest simulation record for the same rule within ten minutes and stores `detected_at`.
4. At 14:05 UTC daily the runner posts a scorecard: simulations caught, missed (no detection within an hour), still pending, failed to run, and median time to detect.

## Safety

- **Canary resources only.** The canary user has no password, no standing keys, and no permissions. The attachable policy denies everything. The canary bucket is empty and never has a bucket policy.
- **Scoped role.** The simulator may create and delete keys only on the canary user, attach only the deny-all policy (enforced with an `iam:PolicyARN` condition), change only the canary bucket's public access block, and stop or start only the project trail.
- **Always restored.** Each scenario restores the original setting in a `finally` block, which unit tests verify even when a step fails.
- **Accepted risk.** The role can briefly stop the project trail. If the function were misused, the same detection it exercises would raise a high-severity alert, and CloudTrail event history still records management events for 90 days regardless of trail status.
- **Off switch.** `enabled = false` disables the schedule through Terraform. Everything is removed at teardown.

## Running one on demand

```bash
aws lambda invoke --function-name cloud-detection-attack-simulator --cli-binary-format raw-in-base64-out --payload '{"scenario": "access_key"}' /tmp/sim.json && cat /tmp/sim.json
aws lambda invoke --function-name cloud-detection-alert-runner --cli-binary-format raw-in-base64-out --payload '{"scorecard": true}' /tmp/score.json && cat /tmp/score.json
```
