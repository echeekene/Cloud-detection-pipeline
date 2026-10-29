# CloudTrail logging stopped or trail deleted

**Severity:** high  
**MITRE ATT&CK:** [T1562.008 Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)

A trail was stopped or deleted, which can hide later activity.

## Triage

1. Treat as high priority: logging was turned off or a trail was removed.
2. Re-enable logging or recreate the trail through Terraform right away.
3. Identify the principal and review everything they did before and after the change.
4. Expect a gap in logs for the period logging was off and note it in the incident record.

## Logic

```sql
event_source = 'cloudtrail.amazonaws.com' AND event_name IN ('StopLogging', 'DeleteTrail') AND outcome = 'success'
```
