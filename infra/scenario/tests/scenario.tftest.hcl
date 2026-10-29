mock_provider "aws" {
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/cloud-detection-lab/cloud-detection-scenario-bucket-location" }
  }
}

variables {
  expected_account_id = "111122223333"
}

run "bounded_permission_and_dedicated_identity" {
  command = apply
  assert {
    condition = (
      jsondecode(aws_iam_policy.metadata.policy).Statement[0].Action == ["s3:GetBucketLocation"] &&
      jsondecode(aws_iam_policy.metadata.policy).Statement[0].Resource == "arn:aws:s3:::cloud-detection-111122223333-us-east-1-raw"
    )
    error_message = "Scenario access must stay limited to the project bucket's location."
  }
  assert {
    condition     = aws_iam_user.test.path == "/cloud-detection-lab/" && !aws_iam_user.test.force_destroy
    error_message = "Use a dedicated lab identity and refuse destructive credential cleanup."
  }
}

run "reject_invalid_account" {
  command = plan
  variables { expected_account_id = "invalid" }
  expect_failures = [var.expected_account_id]
}
