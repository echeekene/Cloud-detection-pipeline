# S3 public access block removed

**Severity:** high  
**MITRE ATT&CK:** [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

A bucket or account public access block was deleted, a common step before exposing data publicly.

## Triage

1. Identify the bucket or account setting that was removed and who removed it.
2. Restore the public access block through Terraform right away.
3. Check the bucket policy and ACLs for public grants and review recent object reads.
4. If data may have been exposed, start the data exposure incident process.

## Logic

```sql
event_source = 's3.amazonaws.com' AND event_name IN ('DeleteBucketPublicAccessBlock', 'DeleteAccountPublicAccessBlock') AND outcome = 'success'
```
