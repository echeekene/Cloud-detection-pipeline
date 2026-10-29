-- Execution parameters: start UTC date, end UTC date, AWS region (all strings).
-- Example values: '2026-01-01', '2026-01-02', 'us-east-1'.
SELECT
    event_id,
    event_time,
    account_id,
    principal,
    source_ip,
    region,
    event_date
FROM security_events
WHERE event_date BETWEEN ? AND ?
  AND region = ?
  AND event_source = 'signin.amazonaws.com'
  AND event_name = 'ConsoleLogin'
  AND outcome = 'success'
  AND mfa_used = FALSE;
