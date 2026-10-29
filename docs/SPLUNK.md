# Trying the same events in Splunk

The goal here is to compare our SQL result with a SIEM search. We are starting with a manual file upload so we can see what Splunk does with each event before adding a collector or forwarding code.

Splunk Enterprise is already installed and running on our computer. We imported the samples and checked a private Classic dashboard. It shows **26 real events, 3 synthetic events, 1 synthetic no-MFA finding, and 0 real no-MFA findings**, matching Athena.

## What is working

- An exporter that reads a checked Parquet snapshot and writes one JSON event per line.
- Separate labels for real and synthetic data, plus the snapshot ID so we can recognize repeated imports.
- Searches for event counts and successful console logins explicitly recorded without MFA.
- A small Classic dashboard showing real/synthetic counts, findings, and event outcomes.

These files live under `splunk/`. The Python exporter is `cloud_detection/splunk_export.py`.

## Export the small samples

From the repository root, using the project Python environment:

```powershell
python -m cloud_detection.splunk_export --snapshot work/demo-dataset --sample-kind synthetic --output work/splunk/synthetic-events.ndjson
python -m cloud_detection.splunk_export --snapshot work/live-dataset --sample-kind live --output work/splunk/live-events.ndjson
```

Use the actual path of the real snapshot for the second command. The synthetic file has 3 events and the real sample has 26. Every event keeps its original UTC event time. The exporter also restores the day and region from the Parquet folder names and preserves boolean/null values.

The first command can be tried entirely with the repository's made-up sample. The real export contains account details, so keep it private. Generated `.ndjson` files are ignored by Git. Exporting refuses to overwrite an existing file or modify a completed snapshot.

## Import into the existing local Splunk

1. Open the local Splunk page and sign in with the account set up for that installation.
2. Check the current license and available features. Avoid starting a new paid subscription or changing existing lab settings.
3. Create a separate event index named `cloud_detection_lab`, unless that exact project index already exists. Leave other indexes and the existing forwarder alone.
4. Use **Add Data → Upload** for the synthetic file first.
5. In the preview, check that Splunk sees **three separate events**, with JSON fields and sensible event times. Start from `_json`, then save a separate source type named `cloud_detection_json_utc`. Use timestamp field `event_time`, timestamp format `%Y-%m-%dT%H:%M:%SZ`, and the fixed **(GMT) Greenwich Mean Time** zone. Check the displayed local time against the original UTC value. Keep the shared `_json` settings unchanged.
6. Choose `cloud_detection_lab` as the destination index and finish the upload.
7. Run the count and synthetic detection searches with **All time** selected.
8. Repeat for the small real export after the synthetic check works.

The sample event times can be older than the default search range. That is why this first demonstration uses All time. We are keeping the original event times instead of making old account activity look new.

## Searches to try

`splunk/searches/event_counts.spl` should show:

| Sample | Expected unique events |
| --- | --- |
| live | 26 |
| synthetic | 3 |

`synthetic_no_mfa_login.spl` should return the one synthetic event with a successful login and explicit no-MFA value. `live_no_mfa_login.spl` should return no matches for the current real sample, matching Athena.

Our JSON source type extracts fields when indexing. Running `spath` again duplicated these fields and broke the event-key calculation, so the checked searches use the existing fields. They turn the MFA value into lowercase text for an explicit `false` comparison. Missing or null MFA values do not match. All searches select `cloud_detection_json_utc` so the initial incorrectly timed imports stay out of the results.

The event key uses the account and event ID, with an unknown-account fallback for the made-up examples. The searches remove repeated imports within the same labeled snapshot before counting. That makes the displayed counts easier to compare; it does not remove duplicate records from Splunk's storage or solve cross-snapshot replay.

## Dashboard

After the searches work, create a **Classic / Simple XML** dashboard and use `splunk/dashboards/cloud_detection_lab.xml` as its source. Keep it private while checking it. Expected panels are:

- Real sample events: 26.
- Synthetic sample events: 3.
- Synthetic logins without MFA: 1.
- Real logins without MFA: 0.
- Event outcomes grouped by sample type.

Splunk accepted the XML and displayed all four expected numbers. The outcome table showed 20 successful and 6 failed real API events, plus 2 successful and 1 failed synthetic login events. API success here means that no error code was recorded; it is not a claim that every action was safe.

## Alerts come after the search works

We saved a private synthetic test alert with a temporary one-minute schedule, an All time range, and a result-count condition greater than zero. The schedule ran and created an entry in Trigger History. Its only action is Add to Triggered Alerts; no outbound notification was added. See [the alert settings and stopping point](../splunk/alerts/synthetic_no_mfa_test.md). The test alert is now disabled. Splunk removed its trigger history and related results; the original trigger screenshot and alert definition remain.

A scheduled live search also needs a sensible time window and a plan for data arriving late. The All time sample search is useful for learning, but is not the final schedule for ongoing detection.

## What we have checked locally

The full Python suite passes **38 tests**. The new checks cover event labels, one-record-per-line output, MFA booleans and nulls, keeping source timestamps, refusing to overwrite files, and parsing the dashboard XML.

The corrected import contains the expected 3 synthetic and 26 real records. Indexing, detection searches, the private dashboard, and a scheduled synthetic alert were checked in Splunk. Original dashboard and trigger screenshots were saved outside Git. No new AWS resources or queries were added for this step.

## Issues we found while importing

Our first imports used the computer time zone even though the source values ended in `Z`. This moved the indexed times forward and hid real events from the dashboard. We saved a corrected UTC source type and reimported the labeled samples together. The searches explicitly select that corrected source type. The original 29 incorrectly timed records remain stored in the separate lab index; displayed counts are not the total storage count. Reimporting did not repair the old records.

The existing Splunk trial was close to ending when checked. We did not change the license or start a paid subscription. Future alert work depends on the features available in the installation.

## References

- [Splunk's JSON field extraction command](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.1/search-commands/spath)
- [Splunk configuration reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.4-configuration-file-reference/props.conf)

HTTP Event Collector is a possible later step. The first manual upload helps us check the event format before adding a token and a network endpoint.
