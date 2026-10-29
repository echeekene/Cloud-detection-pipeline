-- Template only: replace the S3 location with the selected published snapshot.
-- No resources or tables have been created from this file.
CREATE EXTERNAL TABLE IF NOT EXISTS security_events (
    event_id STRING,
    event_time TIMESTAMP,
    event_time_iso STRING,
    event_source STRING,
    event_name STRING,
    account_id STRING,
    source_ip STRING,
    principal STRING,
    principal_type STRING,
    outcome STRING,
    error_code STRING,
    mfa_used BOOLEAN
)
PARTITIONED BY (event_date STRING, region STRING)
STORED AS PARQUET
LOCATION 's3://YOUR_ANALYTICS_BUCKET/snapshots/SELECTED_SNAPSHOT/parquet/';

-- Register Hive-style partitions after publishing the selected snapshot.
MSCK REPAIR TABLE security_events;
