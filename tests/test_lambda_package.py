import hashlib
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from scripts.build_lambda_package import build


class LambdaPackageTests(unittest.TestCase):
    def wheel(self, root, tag='cp312-cp312-manylinux_2_28_x86_64', unsafe=False):
        wheel = root / 'pyarrow.whl'
        with ZipFile(wheel, 'w') as archive:
            archive.writestr('pyarrow-26.0.0.dist-info/METADATA', 'Name: pyarrow\nVersion: 26.0.0\n')
            archive.writestr('pyarrow-26.0.0.dist-info/WHEEL', 'Wheel-Version: 1.0\nTag: '+tag+'\n')
            archive.writestr('../unsafe' if unsafe else 'pyarrow/example.so', b'wheel test fixture')
        return wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()

    def test_package_is_deterministic_and_contains_handler(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheel, digest = self.wheel(root)
            first = build(wheel, digest, root/'first.zip')
            second = build(wheel, digest, root/'second.zip')
            self.assertEqual(first['sha256'], second['sha256'])
            with ZipFile(root/'first.zip') as archive:
                self.assertIn('cloud_detection/lambda_handler.py', archive.namelist())
                self.assertNotIn('tests/test_lambda_package.py', archive.namelist())

    def test_wrong_hash_wrong_platform_and_unsafe_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheel, digest = self.wheel(root)
            with self.assertRaisesRegex(ValueError, 'SHA256'): build(wheel, '0'*64, root/'out.zip')
            wheel, digest = self.wheel(root, tag='cp312-cp312-win_amd64')
            with self.assertRaisesRegex(ValueError, 'manylinux'): build(wheel, digest, root/'out.zip')
            wheel, digest = self.wheel(root, unsafe=True)
            with self.assertRaisesRegex(ValueError, 'Unsafe'): build(wheel, digest, root/'out.zip')


class ApiPackageTests(unittest.TestCase):
    def test_api_package_is_deterministic_and_minimal(self):
        from scripts.build_api_package import build as build_api
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, second = build_api(root/'a.zip'), build_api(root/'b.zip')
            self.assertEqual(first['sha256'], second['sha256'])
            with ZipFile(root/'a.zip') as archive:
                self.assertEqual(sorted(archive.namelist()), ['cloud_detection/__init__.py', 'cloud_detection/api_handler.py', 'cloud_detection/athena.py', 'cloud_detection/detections.py'])
            with self.assertRaisesRegex(ValueError, 'existing'):
                build_api(root/'a.zip')
