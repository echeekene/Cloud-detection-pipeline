# Why we chose these things

These are short notes about our choices as we build. They can change if we find a simpler approach that helps us learn the same thing.

## Keep MFA enabled

We want our real account to be secure while we learn. The no-MFA login rule uses made-up events for now. We can practice detecting a weakness without leaving our normal sign-in unprotected.

## Build one useful piece at a time

We are working in larger pieces and reviewing them together. The first piece was collecting logs. The next was cleaning a small sample locally. We do not need to add every tool at once.

## Use a separate log bucket and trail

Our project has its own S3 bucket and CloudTrail trail. That makes it easier to see what Terraform created and what needs to be removed later. The existing account trail is left alone. Terraform also checks the account ID to help us avoid deploying to the wrong account.

## Make deleting logs a deliberate step

The bucket keeps versions of its objects. Terraform does not empty it during cleanup unless we first turn on the deletion option. That gives us a chance to save useful evidence before removing the lab. The actual cleanup still needs to be tested.

## Test locally before adding more cloud services

Local tests let us check the Python code without making AWS calls. Terraform mock tests check the planned settings without creating resources. We also checked the real bucket and a delivered log, because passing a local test does not show that AWS delivery works.

## Start with a complete dataset per run

For now, each run creates a folder containing all its cleaned data. Exact repeats are counted once. If two copies have the same event ID and account but different contents, we set both aside to inspect later.

Rerunning the same input reuses the existing output after checking its files. New input needs a new output folder. This is manageable for our small samples; keeping track of new events over time will need more work.

## Keep timestamps understandable

We convert event times to UTC before grouping files by day. The Parquet timestamp uses milliseconds for the initial Athena table, and a separate text field keeps any supported extra digits. The [data notes](DATA_MODEL.md) explain the details if we need to revisit this.

## Try a small Splunk upload before a collector

Splunk is already installed locally. We will first upload small JSON files, check the fields, and compare the search result with Athena. That lets us learn Splunk's part of the project before adding an HTTP Event Collector token or automatic forwarding. A separate lab index keeps the project apart from existing Splunk data.
