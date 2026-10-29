# Learning notes

This is a place for questions and observations as we build. The questions below are things to work through together, not claims that every topic has already been learned.

## Things to explain using our project

- What is inside a CloudTrail event, and which fields does our detection use?
- Why does the log bucket need both a delivery policy and public-access blocking?
- What does Terraform state keep track of, and why do we keep it out of Git?
- Why do we write Parquet instead of querying every raw JSON file?
- What does grouping files by day and region help with?
- How is a made-up detection test different from seeing a real alert fire?

## Observations from the build

**Logging being on and a file being delivered are separate checks.** We first confirmed that the trail was logging, then waited for files and found our harmless API action inside one of them.

**A budget warning does not stop spending.** The account has monthly alerts, while our project budget covers the whole build. We still need to watch the total.

**A missing MFA value is not the same as “No.”** Our rule only flags a successful console login when the event explicitly records no MFA.

**Running the same input twice can count events twice.** The local processor checks for repeated events and reuses a completed output for an exact rerun. We still need to consider how that should work for automatic cloud processing.

**Changing permissions and refreshing a session were separate steps here.** After we attached the Athena/Glue policy, IAM's simulator allowed the actions, but the existing temporary session still failed. We refreshed the developer login and checked access again before deploying.

**Athena needs both files and a description of them.** S3 holds our Parquet files. Glue describes their fields and partitions, and Athena uses that information to run SQL. We checked the row counts against the local outputs to make sure they agreed.

**A query finding is only one part of an alert.** Our synthetic no-MFA event is found by SQL in Athena. Scheduling that query, deciding when to notify, and checking the notification are still separate tasks.

## Tradeoffs to revisit

- Is manual processing enough for the first full demonstration, or would a small scheduled job help?
- Which detections are worth adding now that the first one works in Athena?
- How much Splunk and AI work fits the learning goals and budget?
- Is the current amount of code easy enough to explain, and where could we simplify it?

## Reflections to add together

What was confusing, what was useful, and what we would do differently: **To be documented** after reviewing the working pieces.

**Parsing a timestamp and interpreting its time zone are separate checks.** Our first Splunk import recognized the date and clock time but used the computer time zone. Explicit GMT settings fixed the new import.

**Extracting JSON twice can change the fields.** Splunk had already extracted our JSON. Adding `spath` again produced duplicate field values, so we removed that extra extraction from the searches.
