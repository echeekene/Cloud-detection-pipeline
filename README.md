# Cloud Detection Pipeline

A cloud detection and response pipeline built on AWS. Real attack techniques are run against a sandbox account, the resulting logs are collected and queried with SQL, alerts are forwarded to Splunk, and an AI layer summarizes each alert for triage.

This is a portfolio project. The environment was built, tested, documented, and then torn down. Screenshots, query results, and sample alerts in [`evidence/`](evidence/) show it working.

## Tech Stack

| Component | Tool | Purpose |
|---|---|---|
| Cloud Provider | AWS | Sandbox account isolated through AWS Organizations |
| API Logging | CloudTrail | Every API call, all regions, tamper evident |
| Network Logging | VPC Flow Logs | Network level visibility |
| Managed Detection | GuardDuty | Baseline to compare custom detections against |
| Log Storage | S3 | Encrypted, versioned, private evidence store |
| Query Engine | Athena + Glue | SQL detections directly over S3 |
| Attack Simulation | Stratus Red Team | Real techniques mapped to MITRE ATT&CK |
| Alert Routing | EventBridge + Lambda (Python) | Moves detections to the SIEM and triggers response |
| SIEM | Splunk | Alert triage, dashboards, investigation |
| AI Triage | Amazon Bedrock | Plain language alert summaries and next steps |
| IaC | Terraform | Every resource defined as code |

## Architecture

_To be documented._

```
Stratus Red Team attacks
        |
        v
CloudTrail, VPC Flow Logs, GuardDuty --> S3
        |
        v
Athena SQL detections
        |
        v
EventBridge --> Lambda --> Splunk
                  |
                  +--> Bedrock summary
                  +--> Automated remediation
```

## Detections

_To be documented._

## Tradeoffs

_To be documented._

## Known Limitations

_To be documented._

## What I Would Do Differently

_To be documented._

## Repository Layout

```
terraform/   Infrastructure as code
sql/ddl/     Athena table definitions
sql/         Detection queries
evidence/    Screenshots and sanitized outputs
docs/        Setup and teardown runbook
```
