output "analytics_bucket_name" {
  value = aws_s3_bucket.analytics.id
}

output "database_name" {
  value = aws_glue_catalog_database.project.name
}

output "workgroup_name" {
  value = aws_athena_workgroup.queries.name
}

output "dataset_prefixes" {
  value = { for name, dataset in var.datasets : name => "datasets/${name}/${dataset.snapshot_id}/" }
}

output "analytics_access_policy" {
  description = "Policy prepared for separate review; this module does not attach IAM permissions."
  value = templatefile("${path.module}/../access/analytics-policy.json.tftpl", {
    partition    = data.aws_partition.current.partition
    account_id   = var.expected_account_id
    aws_region   = var.aws_region
    project_name = var.project_name
    database     = local.database_name
  })
}
