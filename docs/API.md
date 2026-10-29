# Read-only findings API

## Status

The API code, Terraform module, OpenAPI specification, and tests are written. **It has not been deployed**, so no live request has been made yet. Unit tests cover validation, injection attempts, query building, timeouts, failed queries, routing, and packaging. Terraform mock tests cover authorization, throttling, timeouts, log retention, and the read-only runtime policy.

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
- The `automated_events` table uses partition projection with an injected region. Passing the region as an execution parameter needs a live check after deployment.
- Results reflect the selected tables, not all account activity, and events repeated across source files can appear more than once.
- Lambda uses shared account concurrency, matching the processing function.
- There is no browser front end, so no CORS is configured. A findings page would need that added.

## Cost

API Gateway, Lambda, and Athena are charged per request or per data scanned. With throttling and the 10 MiB scan limit, expected cost for portfolio testing is a few cents. Destroy the module during teardown.
