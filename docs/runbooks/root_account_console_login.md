# Root account console login

**Severity:** high  
**MITRE ATT&CK:** [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

Successful console sign-in by the account root user, which should be rare and planned.

## Triage

1. Confirm with the account owner that the root sign in was planned.
2. Review every action taken by the root principal in the same session.
3. If unplanned, reset the root password, confirm MFA on root, and review billing and IAM changes.
4. Record the reason; routine work should use an IAM identity, not root.

## Logic

```sql
event_source = 'signin.amazonaws.com' AND event_name = 'ConsoleLogin' AND outcome = 'success' AND principal_type = 'Root'
```
