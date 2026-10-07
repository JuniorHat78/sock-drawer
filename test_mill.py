import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import unittest
from unittest.mock import patch
import uuid

from cryptography.exceptions import InvalidTag
import mill
import sweep


class Boxes(unittest.TestCase):
    def setUp(self):
        self.root = Path('out') / ('test-' + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.key = os.urandom(32)

    def tearDown(self):
        if not self.root.resolve().is_relative_to(Path('out').resolve()):
            raise ValueError('Test cleanup escaped scratch')
        shutil.rmtree(self.root)

    def test_roundtrip_and_unique_nonce(self):
        raw = self.root / 'raw'; raw.write_bytes(os.urandom(2 * 1024**2 + 17))
        first, second, decoded = (self.root / n for n in ('a.box', 'b.box', 'decoded'))
        mill.seal(raw, first, self.key); mill.seal(raw, second, self.key)
        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        mill.unseal(first, decoded, self.key)
        self.assertEqual(sweep.sha(raw), sweep.sha(decoded))

    def test_tamper_never_commits_plaintext(self):
        raw = self.root / 'raw'; raw.write_bytes(b'checked content' * 100)
        box, decoded = self.root / 'a.box', self.root / 'decoded'
        mill.seal(raw, box, self.key)
        data = bytearray(box.read_bytes()); data[40] ^= 1; box.write_bytes(data)
        with self.assertRaises(InvalidTag): mill.unseal(box, decoded, self.key)
        self.assertFalse(decoded.exists()); self.assertFalse(decoded.with_suffix('.partial').exists())

    def test_wrong_key_and_truncated_boxes(self):
        raw = self.root / 'raw'; raw.write_bytes(b'content')
        box, decoded = self.root / 'a.box', self.root / 'decoded'
        mill.seal(raw, box, self.key)
        with self.assertRaises(InvalidTag): mill.unseal(box, decoded, os.urandom(32))
        box.write_bytes(box.read_bytes()[:19])
        with self.assertRaises(ValueError): mill.unseal(box, decoded, self.key)

    def toolbox(self, extra=None):
        files = {'run.py': b'pass\n', 'requirements.txt': b''}
        manifest = {'entry': 'run.py', 'requirements': 'requirements.txt',
                    'files': {n: sweep.digest(b) for n, b in files.items()}}
        files['bundle.json'] = json.dumps(manifest).encode()
        path = self.root / 'toolbox.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b'x') if extra.isreg() else None)
        return path

    def test_checked_toolbox(self):
        manifest = mill.safe_extract(self.toolbox(), self.root / 'runtime')
        self.assertEqual(manifest['entry'], 'run.py')

    def test_toolbox_rejects_traversal_and_duplicate(self):
        for name in ('../escape', '/escape', 'C:/escape', 'a\\b', 'run.py'):
            member = tarfile.TarInfo(name); member.size = 1
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    mill.safe_extract(self.toolbox(member), self.root / 'runtime')

    def test_toolbox_rejects_links(self):
        member = tarfile.TarInfo('link'); member.type = tarfile.SYMTYPE; member.linkname = 'run.py'
        with self.assertRaises(ValueError): mill.safe_extract(self.toolbox(member), self.root / 'runtime')

    def test_child_has_no_repository_credentials(self):
        with patch.dict(os.environ, {'BOX_KEY': 'private', 'GH_TOKEN': 'private', 'GITHUB_TOKEN': 'private',
                'ACTIONS_RUNTIME_TOKEN': 'private', 'GITHUB_REPOSITORY': 'private', 'PATH': 'ordinary'}):
            values = mill.child_environment()
        self.assertEqual(values['PATH'], 'ordinary')
        self.assertFalse(any('TOKEN' in n or n.startswith(('BOX_', 'GITHUB_', 'ACTIONS_')) for n in values))

    def test_receipt_rejects_different_source(self):
        class Store:
            assets = {'a.box': {'id': 7, 'size': 10, 'digest': 'sha256:abc'}}
        report = {'source_sha256': 'expected', 'failed': 0,
                  'outputs': [{'name': 'a.box', 'id': 7, 'bytes': 10, 'sha256': 'abc'}]}
        mill.receipt_ok(Store(), report, {'source_sha256': 'expected'})
        with self.assertRaises(ValueError): mill.receipt_ok(Store(), report, {'source_sha256': 'other'})
        Store.assets['a.box']['digest'] = 'sha256:other'
        with self.assertRaises(ValueError): mill.receipt_ok(Store(), report, {'source_sha256': 'expected'})

    def test_incremental_source_requires_frozen_attributes_and_unique_coverage(self):
        row = {'id': 7, 'attributes': {'at': 123}, 'files': [{'name': 'payload.gz'}]}
        saved = {'id': 7, 'attributes': row['attributes'], 'source_files': row['files']}
        task = {'shard': 0, 'expected_ids': [7], 'expected_identity_sha256': mill.source_identity([row])}
        report = {'schema': sweep.SCHEMA, 'plan_sha256': 'plan', 'shard': 0, 'assigned_ids': [7],
                  'collected_ids': [7], 'records': [saved], 'packages': [{'ids': [7]}], 'failures': []}
        class Store:
            def json_asset(self, name): return report
            def check_package(self, package): pass
        self.assertEqual(mill.chunk_packages(Store(), task, 'plan'), report['packages'])
        report['records'][0] = {**saved, 'attributes': {'at': 999}}
        with self.assertRaises(ValueError): mill.chunk_packages(Store(), task, 'plan')
        report['records'][0] = saved; report['packages'].append({'ids': [7]})
        with self.assertRaises(ValueError): mill.chunk_packages(Store(), task, 'plan')

    def test_incremental_source_can_wait_without_fabricating_packages(self):
        class Store:
            def json_asset(self, name): return None
        self.assertIsNone(mill.chunk_packages(Store(), {'shard': 12}, 'plan'))

    def test_carrier_preserves_every_compressed_part(self):
        parts = []
        for index in range(3):
            path = self.root / f'data-{index}.tar.gz'; path.write_bytes(os.urandom(1000 + index))
            parts.append({'name': path.name, 'bytes': path.stat().st_size, 'sha256': sweep.sha(path)})
        outputs = mill.carriers(self.root, parts)
        self.assertEqual(len(outputs), 1)
        with tarfile.open(self.root / outputs[0]['name']) as archive:
            manifest = json.load(archive.extractfile('index.json'))
            self.assertEqual(manifest['parts'], parts)
            for part in parts:
                self.assertEqual(sweep.digest(archive.extractfile(part['name']).read()), part['sha256'])
        (self.root / parts[0]['name']).write_bytes(b'changed')
        with self.assertRaises(ValueError): mill.carriers(self.root, parts)

    def test_public_download_never_sends_api_credentials(self):
        class Response(io.BytesIO):
            def geturl(self): return 'https://release-assets.githubusercontent.com/checked'
        requests = []
        def open_url(request, timeout):
            requests.append(request)
            return Response(b'checked')
        with patch.object(mill, 'urlopen', side_effect=open_url), patch.dict(os.environ, {'GH_TOKEN': 'private'}):
            path = self.root / 'file'
            mill.public_file('owner/repo', 'tag', 'asset', path)
        self.assertEqual(path.read_bytes(), b'checked')
        self.assertNotIn('authorization', {k.lower() for k in requests[0].headers})

    def test_public_download_enforces_the_frozen_size_budget(self):
        class Response(io.BytesIO):
            def geturl(self): return 'https://release-assets.githubusercontent.com/checked'
        with patch.object(mill, 'urlopen', return_value=Response(b'too much')):
            with self.assertRaises(ValueError):
                mill.public_file('owner/repo', 'tag', 'asset', self.root / 'file', max_bytes=2)


if __name__ == '__main__':
    unittest.main()
