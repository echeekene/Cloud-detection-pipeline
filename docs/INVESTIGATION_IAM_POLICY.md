# Controlled IAM policy attachment

## Scenario

This exercise generates a real IAM permission-change event in the project account. A dedicated user receives a customer-managed policy that allows only `s3:GetBucketLocation` on the project's raw log bucket. The user has no password or access keys. The change is reversed by removing the attachment, policy, and user.

The activity is a controlled simulation of a permission-change pattern. It does not demonstrate an account compromise, administrator access, or use of the added permission by an attacker.

MITRE ATT&CK [Additional Cloud Roles T1098.003](https://attack.mitre.org/techniques/T1098/003/) specifically includes `AttachUserPolicy` as a way to add permissions to an AWS user. The mapping describes the behavior; it does not make every policy attachment malicious.

## Execution and reversal

The Terraform plan added three dedicated resources and changed no existing resources. Live read-back checks confirmed one expected policy attachment, zero access keys, and no login profile. Terraform then removed the attachment, policy, and user. Separate IAM reads confirmed that the user and policy no longer exist.

The AWS session could not read Cost Explorer because it lacks `ce:GetCostAndUsage`. Actual charges remain unverified. The scenario did not deploy Lambda, API Gateway, or compute infrastructure. Existing audit logging and storage remain active.

## Detection logic

The Python, SQL, and SPL rules flag successful `AttachUserPolicy` events from `iam.amazonaws.com`. Denied or otherwise failed requests and `DetachUserPolicy` reversal events do not match.

The normalized schema retains the actor, action, outcome, source IP, time, and event ID. It does not yet retain the target username or policy ARN. Investigators must pivot from the event ID to the original CloudTrail record and review `requestParameters.userName` and `requestParameters.policyArn`.

This is a review rule for managed-policy attachments, not a determination that the policy is excessive or that the actor is unauthorized. Legitimate provisioning will also match. Inline policies, role attachments, group changes, and policy version changes are outside this rule's scope.

## Investigation findings

The attachment's actor matched the IAM identity used to run Terraform. Its target was the dedicated lab user, and its policy ARN matched the temporary bucket-location policy. The source record had no error code. The policy document granted only `s3:GetBucketLocation` on the project raw bucket, with no wildcard resource or administrator permissions.

The same delivered sample contained one `DetachUserPolicy` event for the test attachment. Live IAM read-back separately confirmed removal of the user and policy. This supports the conclusion that the observed attachment was the expected controlled change and that it was reversed. The event alone would not establish whether an unfamiliar policy attachment was legitimate; that requires checking the actor, target, policy document, and surrounding activity.

## Evidence and results

Eight matching IAM records were selected from a delivered CloudTrail file. They included the attachment and detachment plus supporting policy and read-back activity. Original compressed files, hashes, selection receipts, and account-specific event records remain private. The selected sample is not a claim that every lifecycle event has been included.

Python accepted all eight records and produced one IAM finding. The combined Parquet snapshot contains the earlier 26 records plus these eight, with no rejects. Athena read 34 real events and returned one attachment finding. Splunk indexed the eight additions, showed 34 total real events, and returned the same attachment event ID.

A private scheduled IAM alert ran against the imported real events and created a Trigger History entry. Its only action was Add to Triggered Alerts, with a temporary one-minute schedule, All time search, and one-day duplicate suppression. It is now disabled; Splunk removed its trigger history and related search results, while saved screenshots, the definition, dashboard, and imported records remain. No outbound notification was added.

This verifies a manually transported, recorded AWS permission change and a scheduled alert on that data. It does not measure continuous detection latency or demonstrate automatic delivery to Splunk. The earlier synthetic no-MFA test remains a separate check.

The [sanitized evidence report](evidence/iam-scenario-verification.json) contains counts and checks without raw account identifiers. The dashboard includes a real IAM attachment panel.

## Reproducing the controlled change

Review the account ID and exact policy before applying `infra/scenario`. The module defines only the dedicated user, one narrow policy, and its attachment. It creates no credentials. Keep its state private and separate from the foundation and analytics modules.

After collecting the required read-back evidence, destroy only the scenario module. Confirm that the test user and policy are absent. Do not destroy the logging foundation as part of this scenario.
