mock_provider "aws" {
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/cloud-detection-github" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/cloud-detection-github-deploy" }
  }
}

variables {
  expected_account_id = "111122223333"
}

run "only_this_repository_can_assume_the_roles" {
  command = apply
  assert {
    condition     = jsondecode(aws_iam_role.plan.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "Tokens must be minted for AWS STS."
  }
  assert {
    condition     = alltrue([for s in concat(jsondecode(aws_iam_role.plan.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"], jsondecode(aws_iam_role.deploy.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]) : startswith(s, "repo:echeekene@201620574/Cloud-detection-pipeline@1440299891:") && !strcontains(s, "*")])
    error_message = "Trust exact subjects from this repository only, with no wildcards."
  }
}

run "only_the_protected_environment_can_deploy" {
  command = apply
  assert {
    condition     = jsondecode(aws_iam_role.deploy.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == ["repo:echeekene@201620574/Cloud-detection-pipeline@1440299891:environment:production"]
    error_message = "Deploys must come from the production environment, which needs approval."
  }
  assert {
    condition     = !contains(jsondecode(aws_iam_role.plan.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"], "repo:echeekene@201620574/Cloud-detection-pipeline@1440299891:environment:production")
    error_message = "The plan role is not a deploy path."
  }
}

run "plan_role_cannot_read_data_or_secrets" {
  command = apply
  assert {
    condition     = aws_iam_role_policy_attachment.plan_read_only.policy_arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"
    error_message = "Plans use the AWS read only policy."
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.plan_no_data.policy).Statement : s.Effect == "Deny"]) && contains(jsondecode(aws_iam_role_policy.plan_no_data.policy).Statement[0].Action, "ssm:GetParameter")
    error_message = "Deny secret and data reads on top of ReadOnlyAccess."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.plan_no_data.policy).Statement[1].Condition.StringNotEquals["kms:ViaService"] == "lambda.us-east-1.amazonaws.com"
    error_message = "KMS decrypt is denied except when Lambda reads function configuration."
  }
}

run "deploy_role_gets_only_the_delivery_modules" {
  command = apply
  assert {
    condition     = output.deploy_policy_names == tolist(["cloud-detection-github-deploy-alerts", "cloud-detection-github-deploy-api", "cloud-detection-github-deploy-monitoring", "cloud-detection-github-deploy-simulator"])
    error_message = "CI deploys api, alerts, simulator and monitoring only."
  }
  assert {
    condition     = !strcontains(aws_iam_role_policy.deploy_state.policy, "foundation/") && !strcontains(aws_iam_role_policy.deploy_state.policy, "cicd/")
    error_message = "CI must not touch foundation state or its own access."
  }
}

run "existing_oidc_provider_is_reused_by_default" {
  command = apply
  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 0
    error_message = "Reuse the account's GitHub OIDC provider unless asked to create one."
  }
}
