-- VPC Flow Logs table (default version 2 format) with partition projection.
-- Each row is one network conversation: who talked to whom, on which port,
-- how much data, and whether it was ACCEPTED or REJECTED.

CREATE EXTERNAL TABLE IF NOT EXISTS ${database}.vpc_flow_logs (
    version      INT,
    account_id   STRING,
    interface_id STRING,
    srcaddr      STRING,
    dstaddr      STRING,
    srcport      INT,
    dstport      INT,
    protocol     BIGINT,
    packets      BIGINT,
    bytes        BIGINT,
    start_time   BIGINT,
    end_time     BIGINT,
    action       STRING,
    log_status   STRING
)
PARTITIONED BY (day STRING)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '
LOCATION 's3://${bucket}/AWSLogs/${account}/vpcflowlogs/${region}/'
TBLPROPERTIES (
    'skip.header.line.count'      = '1',
    'projection.enabled'          = 'true',
    'projection.day.type'         = 'date',
    'projection.day.format'       = 'yyyy/MM/dd',
    'projection.day.range'        = '2026/10/01,NOW',
    'projection.day.interval'     = '1',
    'projection.day.interval.unit' = 'DAYS',
    'storage.location.template'   = 's3://${bucket}/AWSLogs/${account}/vpcflowlogs/${region}/$${day}'
);
