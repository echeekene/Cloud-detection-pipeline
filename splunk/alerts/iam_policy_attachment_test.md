# Controlled IAM policy attachment alert

The private alert named Cloud Detection - IAM Policy Attachment Test uses `splunk/searches/iam_managed_policy_attached.spl` over All time. It triggers once per search run when the result count is greater than zero and adds an internal Triggered Alerts record with Medium severity. The temporary verification schedule was every minute, with duplicate triggering suppressed for one day.

The schedule ran against imported records from the real controlled AWS scenario and created a Trigger History entry. An original screenshot is saved privately outside Git. The alert is now disabled; trigger history and related search results were removed by Splunk. The alert definition, imported events, dashboard, and saved screenshots remain.

No email, webhook, or external notification action was added. The All time range was used to find a recorded scenario, not to implement continuous monitoring. The existing Splunk trial limits future use of scheduled searches.
