# IAM access key created

**Severity:** medium  
**MITRE ATT&CK:** [T1098.001 Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)

A new long-lived access key was created for an IAM user.

## Triage

1. Identify which user the key belongs to and who created it.
2. Confirm the key was expected; long lived keys should be rare.
3. If unexpected, deactivate the key immediately, then delete it after review.
4. Search for activity using the new key ID to see whether it was used.

## Logic

```sql
event_source = 'iam.amazonaws.com' AND event_name = 'CreateAccessKey' AND outcome = 'success'
```
