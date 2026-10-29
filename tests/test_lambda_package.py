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
