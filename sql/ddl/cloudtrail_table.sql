-- CloudTrail table with partition projection.
-- Projection means Athena computes partitions from the S3 path pattern, so
-- there is no crawler to run and no MSCK REPAIR step. Filtering on
-- `timestamp` keeps queries cheap because Athena only reads those days.

CREATE EXTERNAL TABLE IF NOT EXISTS ${database}.cloudtrail_logs (
    eventversion        STRING,
    useridentity        STRUCT<
                            type: STRING,
                            principalid: STRING,
                            arn: STRING,
                            accountid: STRING,
                            invokedby: STRING,
                            accesskeyid: STRING,
                            username: STRING,
                            sessioncontext: STRUCT<
                                attributes: STRUCT<
                                    mfaauthenticated: STRING,
                                    creationdate: STRING>,
                                sessionissuer: STRUCT<
                                    type: STRING,
                                    principalid: STRING,
                                    arn: STRING,
                                    accountid: STRING,
                                    username: STRING>>>,
    eventtime           STRING,
    eventsource         STRING,
    eventname           STRING,
    awsregion           STRING,
    sourceipaddress     STRING,
    useragent           STRING,
    errorcode           STRING,
    errormessage        STRING,
    requestparameters   STRING,
    responseelements    STRING,
    additionaleventdata STRING,
    requestid           STRING,
    eventid             STRING,
    readonly            STRING,
    resources           ARRAY<STRUCT<arn: STRING, accountid: STRING, type: STRING>>,
    eventtype           STRING,
    apiversion          STRING,
    recipientaccountid  STRING,
    sharedeventid       STRING,
    vpcendpointid       STRING
)
PARTITIONED BY (region STRING, `timestamp` STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://${bucket}/AWSLogs/${account}/CloudTrail/'
TBLPROPERTIES (
    'projection.enabled'             = 'true',
    'projection.region.type'         = 'enum',
    'projection.region.values'       = 'us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,eu-west-1,eu-west-2,eu-central-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,ap-south-1,sa-east-1',
    'projection.timestamp.type'      = 'date',
    'projection.timestamp.format'    = 'yyyy/MM/dd',
    'projection.timestamp.range'     = '2026/10/01,NOW',
    'projection.timestamp.interval'  = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'storage.location.template'      = 's3://${bucket}/AWSLogs/${account}/CloudTrail/$${region}/$${timestamp}'
);
