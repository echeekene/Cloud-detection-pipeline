# Managed policy attached to IAM user

**Severity:** medium  
**MITRE ATT&CK:** [T1098.003 Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

Successful AttachUserPolicy call. Requires investigation; the rule does not judge whether the permissions are excessive.

## Triage

1. Open the source CloudTrail event to see the target user and policy ARN.
2. Confirm the change matches an approved request or Terraform change.
3. Review what the policy grants; treat admin or wildcard permissions as high priority.
4. If unapproved, detach the policy and review what the user did while it was attached.

## Logic

```sql
event_source = 'iam.amazonaws.com' AND event_name = 'AttachUserPolicy' AND outcome = 'success'
```
