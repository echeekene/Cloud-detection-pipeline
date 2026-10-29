-- Parameters: start UTC date, end UTC date, AWS region.
-- Review the original CloudTrail event for target user and policy ARN.
SELECT event_id, event_time, account_id, principal, source_ip, region, event_date
FROM security_events
WHERE event_date BETWEEN ? AND ?
  AND region = ?
  AND event_source = 'iam.amazonaws.com'
  AND event_name = 'AttachUserPolicy'
  AND outcome = 'success';
