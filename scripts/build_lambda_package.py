"""Build a deterministic Python 3.12 x86_64 Lambda zip from a checked PyArrow wheel."""

import argparse
import base64
from email.parser import Parser
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED


def build(wheel, expected_sha256, output):
    wheel, output = Path(wheel), Path(output)
    if output.exists():
        raise ValueError("Choose a new package output; existing files are not overwritten")
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError("Wheel SHA256 differs from the expected PyPI checksum")
    project = Path(__file__).resolve().parents[1]
    entries = {}
    with ZipFile(wheel) as archive:
        metadata_files = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
        wheel_files = [name for name in archive.namelist() if name.endswith('.dist-info/WHEEL')]
        if len(metadata_files) != 1 or len(wheel_files) != 1:
            raise ValueError("Expected a single wheel distribution")
        metadata = Parser().parsestr(archive.read(metadata_files[0]).decode())
        tags = Parser().parsestr(archive.read(wheel_files[0]).decode()).get_all('Tag', [])
        if metadata['Name'].lower() != 'pyarrow' or metadata['Version'] != '26.0.0' or 'cp312-cp312-manylinux_2_28_x86_64' not in tags:
            raise ValueError("Use PyArrow 26 for CPython 3.12 manylinux 2.28 x86_64")
        if metadata.get_all('Requires-Dist'):
            raise ValueError("Review unexpected wheel dependencies before packaging")
        for item in archive.infolist():
            if item.is_dir():
                continue
            path = PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename:
                raise ValueError("Unsafe wheel member")
            entries[item.filename] = archive.read(item)
    for name in ('__init__.py', 'pipeline.py', 'dataset.py', 'lambda_handler.py'):
        entries['cloud_detection/' + name] = (project / 'cloud_detection' / name).read_bytes()
    size = sum(map(len, entries.values()))
    if size > 250 * 1024 * 1024:
        raise ValueError("Package exceeds Lambda's uncompressed size limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, 'w', compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256(output.read_bytes()).digest()
    return {'path': str(output.resolve()), 'sha256': digest.hex(), 'base64sha256': base64.b64encode(digest).decode(),
            'uncompressed_bytes': size, 'zip_bytes': output.stat().st_size, 'wheel_sha256': expected_sha256}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', required=True, type=Path)
    parser.add_argument('--wheel-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = build(args.wheel, args.wheel_sha256, args.output)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
