-- Run after the tables exist and CloudTrail has had about 15 minutes to
-- deliver logs. If this returns rows, the logging layer is working.
-- Screenshot the result for the evidence folder.

SELECT
    eventtime,
    eventsource,
    eventname,
    useridentity.arn AS actor,
    sourceipaddress
FROM ${database}.cloudtrail_logs
WHERE region = '${region}'
  AND "timestamp" >= date_format(current_date - interval '1' day, '%Y/%m/%d')
ORDER BY eventtime DESC
LIMIT 25;
