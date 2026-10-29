"""Send one SigV4-signed GET request to the findings API using the active AWS profile.

Example:
    python scripts/call_api.py --endpoint https://abc123.execute-api.us-east-1.amazonaws.com \
        --path /findings --param start=2026-10-20 --param end=2026-10-28 --param region=us-east-1
"""

import argparse
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--path", required=True, choices=["/findings", "/events", "/detections"])
    parser.add_argument("--param", action="append", default=[], help="key=value, repeatable")
    args = parser.parse_args()

    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    params = dict(item.split("=", 1) for item in args.param)
    url = args.endpoint.rstrip("/") + args.path + ("?" + urlencode(sorted(params.items())) if params else "")
    request = AWSRequest(method="GET", url=url)
    SigV4Auth(boto3.Session().get_credentials(), "execute-api", "us-east-1").add_auth(request)
    try:
        with urlopen(Request(url, headers=dict(request.headers)), timeout=35) as response:
            status, body = response.status, response.read()
    except HTTPError as error:
        status, body = error.code, error.read()
    print(status)
    print(json.dumps(json.loads(body), indent=2))


if __name__ == "__main__":
    main()
