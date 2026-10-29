# Synthetic no-MFA test alert

This alert checks the small made-up sample. It is a demonstration of a scheduled search and internal trigger history, not continuous monitoring of the AWS account.

| Setting | Value |
| --- | --- |
| Name | Cloud Detection - Synthetic No MFA Test |
| Search | `splunk/searches/synthetic_no_mfa_login.spl` |
| Sharing | Private |
| Search range | All time |
| Temporary test schedule | Every minute |
| Trigger condition | Number of results greater than zero |
| Trigger mode | Once per search run |
| Action | Add to Triggered Alerts |
| Severity | Medium |
| Trigger record expiry | 24 hours |
| External notifications | None |

The sample has one successful login explicitly recorded without MFA. The login with MFA and failed login should not match. Unknown MFA values should not match either.

All time lets the schedule find the older sample. This would repeatedly rediscover the same event if left running, so disable the test schedule after checking the trigger. A future live alert needs a bounded time window, late-arrival handling, and a way to avoid repeated findings.

Splunk warns that scheduled searches stop working after the existing Enterprise trial expires. This test does not change the license or start a subscription.

## Result and stopping point

The saved schedule ran and produced an entry in Trigger History. An original screenshot is saved privately outside Git. The test alert is now disabled. Splunk removed its trigger history and related search results when disabling it; the saved screenshot, alert definition, dashboard, and imported samples remain.
