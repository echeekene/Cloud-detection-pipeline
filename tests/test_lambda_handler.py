import copy
import gzip
import io
import json
from pathlib import Path
import unittest

from cloud_detection.lambda_handler import process_record


class MissingObject(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class MemoryS3:
    def __init__(self):
        self.objects = {}
        self.puts = []
        self.gets = []
        self.fail_key = None

    def get_object(self, Bucket, Key, **kwargs):
        self.gets.append((Bucket, Key, kwargs))
        if (Bucket, Key) not in self.objects:
            raise MissingObject()
        data = self.objects[Bucket, Key]
        return {"Body": io.BytesIO(data), "ContentLength": len(data)}

    def put_object(self, **kwargs):
        if self.fail_key and self.fail_key in kwargs["Key"]:
            raise RuntimeError("Simulated publication failure")
        self.objects[kwargs["Bucket"], kwargs["Key"]] = kwargs["Body"]
        self.puts.append(kwargs)

    def list_objects_v2(self, Bucket, Prefix, MaxKeys):
        return {"Contents": [{"Key": key} for bucket, key in self.objects if bucket == Bucket and key.startswith(Prefix)][:MaxKeys]}


class LambdaHandlerTests(unittest.TestCase):
    def setUp(self):
        self.s3 = MemoryS3()
        self.config = {"raw_bucket": "raw", "analytics_bucket": "analytics", "input_prefix": "cloudtrail/AWSLogs/111122223333/CloudTrail/"}
        self.key = self.config["input_prefix"] + "us-east-1/sample.json.gz"
        self.event = {"eventSource": "aws:s3", "eventName": "ObjectCreated:Put", "s3": {"bucket": {"name": "raw"}, "object": {"key": self.key, "versionId": "v1", "eTag": "etag1"}}}
        data = (Path(__file__).resolve().parents[1] / "examples/cloudtrail.json").read_bytes()
        self.s3.objects['raw', self.key] = gzip.compress(data)

    def test_publish_then_replay_checks_artifacts_without_duplicate_writes(self):
        result = process_record(self.event, self.s3, self.config)
        self.assertEqual(result["accepted_records"], 3)
        self.assertFalse(result["reused"])
        puts = len(self.s3.puts)
        replay = process_record(self.event, self.s3, self.config)
        self.assertTrue(replay["reused"])
        self.assertEqual(len(self.s3.puts), puts)
        self.assertEqual(self.s3.puts[-1]["Key"].split('/')[-1], '_SUCCESS')
        self.assertTrue(all(item['ServerSideEncryption'] == 'AES256' for item in self.s3.puts))
        self.assertTrue(any(kwargs == {'VersionId': 'v1'} for bucket, key, kwargs in self.s3.gets if bucket == 'raw'))

    def test_partial_failure_retries_into_the_same_keys(self):
        self.s3.fail_key = 'manifest.json'
        with self.assertRaises(RuntimeError): process_record(self.event, self.s3, self.config)
        before = {key for bucket, key in self.s3.objects if bucket == 'analytics' and key.endswith('.parquet')}
        self.s3.fail_key = None
        process_record(self.event, self.s3, self.config)
        after = {key for bucket, key in self.s3.objects if bucket == 'analytics' and key.endswith('.parquet')}
        self.assertEqual(before, after)

    def test_corrupt_published_artifact_is_not_silently_reused(self):
        process_record(self.event, self.s3, self.config)
        key = next(key for bucket, key in self.s3.objects if bucket == 'analytics' and key.endswith('.parquet'))
        self.s3.objects['analytics', key] = b'corrupt'
        with self.assertRaisesRegex(ValueError, 'artifact integrity'): process_record(self.event, self.s3, self.config)

    def test_wrong_bucket_digest_key_and_missing_version_evidence_are_rejected(self):
        events = []
        wrong_bucket = copy.deepcopy(self.event)
        wrong_bucket['s3']['bucket']['name'] = 'unrelated'
        events.append(wrong_bucket)
        digest = copy.deepcopy(self.event)
        digest['s3']['object']['key'] = self.key.replace('/CloudTrail/', '/CloudTrail-Digest/')
        events.append(digest)
        unversioned = copy.deepcopy(self.event)
        unversioned['s3']['object'].pop('versionId')
        unversioned['s3']['object'].pop('eTag')
        events.append(unversioned)
        for event in events:
            with self.subTest(event=event):
                with self.assertRaises(ValueError): process_record(event, self.s3, self.config)
        self.assertEqual(self.s3.puts, [])

    def test_etag_pins_unversioned_notification_and_keys_are_url_decoded(self):
        self.event['s3']['object'].pop('versionId')
        self.event['s3']['object']['key'] = self.key.replace('/', '%2F')
        process_record(self.event, self.s3, self.config)
        self.assertTrue(any(kwargs == {'IfMatch': '"etag1"'} for bucket, key, kwargs in self.s3.gets if bucket == 'raw'))

    def test_bad_records_are_quarantined_with_valid_neighbors_retained(self):
        payload = json.loads(gzip.decompress(self.s3.objects['raw', self.key]))
        payload['Records'].append({'eventID': 'bad'})
        self.s3.objects['raw', self.key] = gzip.compress(json.dumps(payload).encode())
        result = process_record(self.event, self.s3, self.config)
        self.assertEqual((result['accepted_records'], result['quarantined_records']), (3, 1))
        quarantine = next(value for (bucket, key), value in self.s3.objects.items() if bucket == 'analytics' and key.endswith('records.jsonl'))
        self.assertIn(b'bad', quarantine)

    def test_separate_bucket_requirement_prevents_output_loop(self):
        self.config['analytics_bucket'] = 'raw'
        with self.assertRaisesRegex(ValueError, 'must differ'): process_record(self.event, self.s3, self.config)

    def test_invalid_gzip_is_recorded_as_a_quarantined_document(self):
        self.s3.objects['raw', self.key] = b'not gzip'
        result = process_record(self.event, self.s3, self.config)
        self.assertEqual((result['accepted_records'], result['failed_documents']), (0, 1))
        self.assertTrue(any(item['Key'].endswith('_SUCCESS') for item in self.s3.puts))

    def test_new_source_version_publishes_a_separate_run(self):
        first = process_record(self.event, self.s3, self.config)
        second = copy.deepcopy(self.event)
        second['s3']['object']['versionId'] = 'v2'
        new = process_record(second, self.s3, self.config)
        self.assertNotEqual(first['run_id'], new['run_id'])
        self.assertFalse(new['reused'])
