# CI/CD

GitHub Actions plans and deploys the delivery modules with short lived AWS credentials. No AWS keys are stored in GitHub.

## How a change reaches AWS

1. **Pull request.** The [deploy workflow](../.github/workflows/deploy.yml) runs the Python tests, then `terraform plan` for each module with a read only role. The changes appear on the run's summary page.
2. **Merge or push to `main`.** The same plan runs again. Its fingerprint (which resources change, and how) is saved.
3. **Approval.** The deploy job targets the `production` environment, so GitHub pauses until I click **Review deployments** and approve.
4. **Deploy.** The deploy role plans once more and compares the fingerprint with the reviewed one. If anything changed in between, the job stops. Otherwise it applies that plan.

Each run gets credentials from GitHub's OIDC token, valid for at most one hour.

## Roles

Defined in [infra/cicd](../infra/cicd/main.tf).

| Role | Who can assume it | What it can do |
| --- | --- | --- |
| `cloud-detection-github-plan` | This repository, on pull requests and on `main` | AWS `ReadOnlyAccess`, with explicit denies on secrets (SSM parameters, Secrets Manager, KMS decrypt) and data (log contents, DynamoDB items, Athena results, S3 objects other than Terraform state) |
| `cloud-detection-github-deploy` | This repository, only in the `production` environment | The same scoped policies used for manual deploys ([infra/access](../infra/access)), plus read and write on the state of api, alerts, simulator and monitoring |

Trust conditions match exact `sub` values. GitHub's subject includes numeric owner and repository IDs (`repo:echeekene@201620574/Cloud-detection-pipeline@1440299891:...`), so forks, other branches, other repositories, and even a recreated repository with the same name cannot assume either role. Pull requests from forks skip the AWS jobs entirely.

## Scope

CI deploys **api, alerts, simulator and monitoring**. Foundation, analytics and automation stay manual, because they were built before I wrote scoped deploy policies, and the deploy role should not get broad S3 or CloudTrail rights to cover them. The `cicd` module is also manual, so a pipeline can never widen its own access.

## Safety details

- Lambda packages are built fresh from the commit. The build is deterministic and `.gitattributes` forces LF line endings, so the same commit gives the same checksum on Windows, CloudShell and CI.
- Package paths in tfvars are relative to the module, so plans do not differ by checkout location.
- The account ID is a GitHub secret, so it is masked in logs, and the summary also replaces it with `<account-id>`.
- Actions are pinned to commit SHAs.
- One deploy runs at a time per branch, and modules apply one after another.

## One time setup

From CloudShell, as `ekene-security-admin`:

```bash
aws iam list-open-id-connect-providers   # if GitHub's provider is missing, add -var create_oidc_provider=true
cd ~/cloud-detection-pipeline && git pull
terraform -chdir=infra/cicd init -backend-config=../backend.hcl
terraform -chdir=infra/cicd test
terraform -chdir=infra/cicd plan -var expected_account_id=<ACCOUNT_ID> -out=cicd.tfplan
terraform -chdir=infra/cicd apply cicd.tfplan
```

In GitHub, under **Settings**:

1. **Environments**, new environment `production`, add myself as a required reviewer, and limit deployment branches to `main`.
2. **Secrets and variables, Actions**, new repository secret `AWS_ACCOUNT_ID`.

## Lesson

The first runs failed twice. The account ID was saved as an environment secret, which the plan jobs cannot see, so the role ARN was empty. Then AWS rejected the token because I trusted the older subject format without IDs. CloudTrail's `AssumeRoleWithWebIdentity` events showed the exact subject GitHub sent, which is the fastest way to debug OIDC trust.

## Trade offs

- The approval happens before the deploy job runs its own plan. The fingerprint check makes sure that plan matches the one already reviewed.
- Pushing straight to `main` still deploys after approval. Branch protection that requires a pull request would be the next step on a team.
