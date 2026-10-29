# Console login without MFA

**Severity:** medium  
**MITRE ATT&CK:** [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

Successful AWS console login where CloudTrail explicitly records that MFA was not used.

## Triage

1. Confirm who signed in: check the principal and source IP against known users and locations.
2. Check what the session did next by searching events for the same principal over the following hour.
3. If unexpected, disable console access for the user, rotate their password, and require MFA.
4. If expected, enforce MFA for that user so the alert does not recur.

## Logic

```sql
event_source = 'signin.amazonaws.com' AND event_name = 'ConsoleLogin' AND outcome = 'success' AND mfa_used = FALSE
```
