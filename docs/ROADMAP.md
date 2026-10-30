# Build plan

We are building this to learn cloud security and data processing. This list helps us keep track of what works and what we want to try next. We can adjust the later steps instead of forcing every idea into the first version.

## Progress

| Part | What we want to learn or build | Where we are |
| --- | --- | --- |
| Local example | Read a log and spot a login without MFA | Working with made-up events |
| AWS setup | Use Terraform, S3, and CloudTrail | Deployed; real log delivery checked |
| Clean the data | Read compressed files, handle bad records, write Parquet | Working locally and automatically through Lambda |
| Query in AWS | Put the cleaned files in S3 and try Athena | Working; 34 real rows, 3 synthetic rows, and both expected findings verified |
| Splunk | Send events to a SIEM and try an alert/dashboard | Sample imports, searches, dashboard, and scheduled synthetic alert checked; test alert now disabled |
| Simulations | Generate controlled test activity and see what gets caught | Real IAM policy change detected in Python, Athena, and Splunk; alert verified and disabled; temporary resources removed |
| Automation | Process newly delivered logs with an S3-triggered Lambda | Deployed; automatic delivery, Athena read-back, replay, and failure destination verified |
| Findings API | Read findings and events through a protected API | Deployed; 403 unsigned, 200 signed, live findings returned. See [API.md](API.md) |
| AI | Try explaining a finding in plain English | Later; scope still open |
| Finish and clean up | Explain the project, record costs, remove lab resources | Still to finish |

## What we are keeping simple

1. Start with one CloudTrail detection before adding more log types and rules.
2. Process small samples manually before automating the full path.
3. Use the existing local Splunk installation before adding event forwarding.
4. Use made-up or controlled activity for testing. Keep MFA and our normal account logging protections in place.
5. Add AI after the basic data and detection steps work.

## Budget and setup

We are using the existing AWS account in US East (N. Virginia). Our maximum is **$20 for the whole build**, including work across billing months, and we want to spend less. The existing $5 monthly budget alerts give us an earlier warning, but they do not stop spending automatically.

The build is published at [echeekene/Cloud-detection-pipeline](https://github.com/echeekene/Cloud-detection-pipeline), with passing hosted Python and Terraform checks. Splunk Enterprise runs locally in a separate project index.

## Documentation

The Motorsport sample is a reference for explaining the architecture, choices, limitations, and lessons. Our README should describe what we actually built in language we can talk through. Add results and screenshots after checking them. Keep detailed commands in the setup guide so the main README is easier to read.

## Next piece to review together

1. Completed: publish the existing repository and verify hosted Python and Terraform workflows.
2. Completed: controlled IAM policy attachment, investigation, scheduled alert verification, and resource reversal using a dedicated test identity.
3. Completed: S3-triggered Lambda processing with checked replay and a verified failure destination.
4. Completed: [investigation report](INVESTIGATION_IAM_POLICY.md), MITRE ATT&CK mapping (T1098.003), and updated architecture diagram in the README.
5. Completed: protected read-only findings API, deployed and verified with signed and unsigned requests. See [API.md](API.md).
6. Production upgrades: shared rules with four new detections and runbooks (done), remote Terraform state in S3 with native locking (done, see [STATE.md](STATE.md)), then scheduled detections with Slack alerts, health alarms, and CI/CD with a dedicated deploy role. Then validate the CloudTrail digest chain.
7. Measure costs, test AWS teardown (including the deployer group and policy), and publish the portfolio writeup. The README rewrite is done.

Automation and the controlled scenario are complete and verified; the API is deployed and verified. A randomized simulator, AI explanation, natural-language query endpoint, and findings website are optional stretch additions. The current data model is a normalized event table; a star schema has not been implemented.
