# Read-only findings API

## Status

**Deployed and verified on October 29, 2026.** All 12 resources exist. The first apply stopped before the `$default` stage because `apigateway:TagResource` was denied; after adding that action to the deploy policy, the same plan applied cleanly about nine hours later, so the earlier denials were IAM propagation delay.

Live checks:

- Unsigned requests to all three routes return **403**.
- Signed requests as a member of `cloud-detection-api-readers` return **200** on `/detections`, `/findings`, and `/events`.
- `/events` and `/findings` on the `automated` dataset work with the region passed as an execution parameter, so partition projection accepts it.
- `/findings` for October 22 to 29 returned one real `iam_managed_policy_attached` finding, which needs review against the controlled scenario record.

The deployed function predates the shared rule module, so it serves two rules. The repository now defines six; redeploying the API package picks them up.

Terraform state is in CloudShell (us-east-1, `ekene-security-admin`) at `~/cdp/infra/api/terraform.tfstate` until remote state is set up. CloudShell deletes home files after 120 days without use.

## IAM changes made for deployment and testing

- Group `cloud-detection-deployers` (member `ekene-security-admin`, who was at the ten managed policy limit) with `AWSCloudShellFullAccess` and the customer managed `CloudDetectionApiDeploy` built from [api-policy.json.tftpl](../infra/access/api-policy.json.tftpl).
- Group `cloud-detection-api-readers` (member `ekene-security-admin`) with an inline policy allowing `execute-api:Invoke` on the three routes only.
- Root was used once, only to create the deployer group and attach its policies.
- `ekene-security-admin` already holds `IAMFullAccess`, so it can grant itself further permissions. Remove both groups and the policy during teardown.

## Request path

1. A caller signs a GET request with AWS Signature Version 4.
2. API Gateway (HTTP API) checks the signature with `AWS_IAM` authorization on every route and throttles to 2 requests per second with a burst of 5.
3. A Python Lambda validates every query parameter against a strict pattern and rejects unknown parameters.
4. The handler picks a fixed SQL template and a table from an allowlist, then passes all filter values as Athena execution parameters.
5. Athena runs the query in the existing `cloud-detection-queries` workgroup, which keeps the 10 MiB scan limit and encrypted results.
6. The handler returns JSON, or cancels the query and returns 504 after 20 seconds.

## Endpoints

| Route | Purpose | Required parameters |
| --- | --- | --- |
| `GET /detections` | Detection rules with MITRE ATT&CK mapping | None |
| `GET /findings` | Rule hits, newest first | `start`, `end`, `region` |
| `GET /events` | Event search by `principal`, `source_ip`, `event_name`, `outcome` | `start`, `end`, `region` |

Optional on both query routes: `dataset` (`automated` by default, `live`, or `synthetic`) and `limit` (1 to 100, default 50). Date ranges are UTC, inclusive, and limited to 31 days. The full contract is in [openapi.yaml](openapi.yaml).

## Security choices

- **No SQL built from input.** Table names come from a fixed map, values are passed as execution parameters, and the row limit is applied when reading results. Patterns reject quotes, semicolons, and comment markers before a value reaches Athena; quote doubling is a second safeguard. Tests send common injection strings to every filter.
- **No anonymous access.** Every route requires IAM authorization. The module outputs a route-scoped `execute-api:Invoke` policy for a dedicated reader identity but does not attach it.
- **Read-only runtime.** The Lambda role can run queries in one workgroup, read three Glue tables and their data prefixes, and write only Athena results. It has no Glue write, IAM, or delete permissions.
- **No internal detail leaks.** Failed query reasons go to CloudWatch Logs, not the response. Responses carry `cache-control: no-store`.
- **Short-lived logs.** Lambda and API access logs keep three days. Access logs record caller ARN, route, status, and latency.

## Deploying

Run from the repository root on Windows. Build the package into `work/`, which Git ignores:

```powershell
.\.venv\Scripts\python.exe scripts\build_api_package.py --output work\api-package.zip
```

Copy the printed `path`, `sha256`, and `base64sha256` into `infra/api/terraform.tfvars.json` with `expected_account_id`, then:

```powershell
cd infra\api
terraform init
terraform test
terraform plan -out api.tfplan
```

Review the plan before applying. Then attach the `invoke_policy` output to a dedicated reader identity and call the API:

```powershell
.\.venv\Scripts\python.exe scripts\call_api.py --endpoint <api_endpoint> --path /findings --param start=2026-10-20 --param end=2026-10-28 --param region=us-east-1
```

## Known limitations

- Athena takes several seconds per query, so responses are not instant.
- Scheduled runs and the API query only the regions they are given; global services such as IAM and sign in log to us-east-1.
- Results reflect the selected tables, not all account activity, and events repeated across source files can appear more than once.
- Lambda uses shared account concurrency, matching the processing function.
- There is no browser front end, so no CORS is configured. A findings page would need that added.

## Cost

API Gateway, Lambda, and Athena are charged per request or per data scanned. With throttling and the 10 MiB scan limit, expected cost for portfolio testing is a few cents. Destroy the module during teardown.
