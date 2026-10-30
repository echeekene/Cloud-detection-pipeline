"""Build a deterministic Lambda zip for the findings API or the alert runner (standard library and the runtime's boto3 only)."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

TARGETS = {
    "api": ("__init__.py", "api_handler.py", "athena.py", "detections.py"),
    "alerts": ("__init__.py", "alerting.py", "athena.py", "detections.py"),
    "simulator": ("__init__.py", "simulator.py"),
}
FILES = TARGETS["api"]


def build(output, target="api"):
    output = Path(output)
    files = TARGETS[target]
    if output.exists():
        raise ValueError("Choose a new package output; existing files are not overwritten")
    project = Path(__file__).resolve().parents[1]
    entries = {"cloud_detection/" + name: (project / "cloud_detection" / name).read_bytes() for name in files}
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256(output.read_bytes()).digest()
    return {"path": str(output.resolve()), "sha256": digest.hex(), "base64sha256": base64.b64encode(digest).decode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", choices=sorted(TARGETS), default="api")
    parser.add_argument("--tfvars", type=Path, help="Also write a Terraform variables file for this package")
    parser.add_argument("--account", help="12-digit account ID for --tfvars")
    args = parser.parse_args()
    package = build(args.output, args.target)
    if args.tfvars:
        if not (args.account and args.account.isdigit() and len(args.account) == 12):
            parser.error("--tfvars requires --account with a 12-digit account ID")
        args.tfvars.write_text(json.dumps({"expected_account_id": args.account, "package": package}, indent=2))
    print(json.dumps(package, indent=2))


if __name__ == "__main__":
    main()
