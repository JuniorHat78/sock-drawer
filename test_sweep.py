from copy import deepcopy
from contextlib import contextmanager
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import tarfile
import shutil
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch
from urllib.error import HTTPError

import sweep


@contextmanager
def directory():
    root = Path(__file__).resolve().parent / 'out'
    root.mkdir(exist_ok=True)
    path = root / uuid.uuid4().hex
    path.mkdir()
    try:
        yield str(path)
    finally:
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Temporary folder escaped test output')
        shutil.rmtree(path)


def plan(count=1):
    return {'schema': sweep.SCHEMA, 'origin': 'https://source.example',
            'records': [{'id': i + 1, 'attributes': {'at': 123}, 'files': [
                {'name': 'payload.gz', 'path': f'/items/{i + 1}', 'kind': 'binary'}]} for i in range(count)],
            'retained_ids': [900000], 'total_records': count + 1, 'chunk_records': 512,
            'parallel': 20, 'origin_rpm': 360, 'release_shards': 64, 'checkpoint_records': 256}


def record(item, raw=b'original\x00\xff' * 100):
    compressed = gzip.compress(raw, mtime=0)
    return {'id': item['id'], 'attributes': item['attributes'], 'source_files': item['files'],
            'files': [{'name': 'payload.gz', 'sha256': sweep.digest(raw), 'bytes': len(raw),
                       'gzip_sha256': sweep.digest(compressed), 'gzip_bytes': len(compressed)}]}, compressed


class Tests(unittest.TestCase):
    def test_live_asset_pagination_deduplicates_same_id_only(self):
        def asset(index):
            return {'id': index, 'name': f'box-{index}', 'size': 12, 'digest': 'sha256:abc', 'state': 'uploaded'}
        page_one = [asset(i) for i in range(100)]
        page_two = [asset(i) for i in range(99, 115)]
        store = object.__new__(sweep.Store)
        store.repo = 'owner/repo'; store.release = {'id': 1}
        with patch.object(sweep, 'gh', side_effect=[json.dumps(page_one), json.dumps(page_two)]):
            store.refresh()
        self.assertEqual(len(store.assets), 115)
        conflict = {**page_two[0], 'id': 9999}
        with patch.object(sweep, 'gh', side_effect=[json.dumps(page_one), json.dumps([conflict])]):
            with self.assertRaises(ValueError): store.refresh()

    def test_transient_asset_server_failures_are_retried_without_auth_retry(self):
        self.assertEqual(sweep.github_pause(b'HTTP 500 (temporary)', 0), 2)
        self.assertEqual(sweep.github_pause(b'HTTP 503 (temporary)', 2), 8)
        self.assertIsNone(sweep.github_pause(b'HTTP 403 forbidden', 0))

    def test_manifest_rejects_duplicates_and_unsafe_sources(self):
        for change in ('duplicate', 'retained', 'http', 'userinfo', 'host', 'slash', 'traversal', 'budget'):
            data = plan(2)
            if change == 'duplicate': data['records'][1]['id'] = 1
            if change == 'retained': data['retained_ids'][0] = 1
            if change == 'http': data['origin'] = 'http://source.example'
            if change == 'userinfo': data['origin'] = 'https://key@source.example'
            if change == 'host': data['records'][0]['files'][0]['path'] = '//other.example/file'
            if change == 'slash': data['records'][0]['files'][0]['path'] = '/\\other.example/file'
            if change == 'traversal': data['records'][0]['files'][0]['name'] = '../payload.gz'
            if change == 'budget': data['parallel'] = 21
            with self.subTest(change=change), self.assertRaises(ValueError):
                sweep.validate(data)

    def test_all_chunks_cover_ids_once_including_partial_tail_and_waves(self):
        data = plan(32769)
        sweep.validate(data)
        chunks = [sweep.assigned(data, i) for i in range(65)]
        self.assertEqual([r['id'] for c in chunks for r in c], list(range(1, 32770)))
        self.assertEqual(len(chunks[-1]), 1)
        self.assertEqual(sweep.wave('b1', 63), 'b1-w00')
        self.assertEqual(sweep.wave('b1', 64), 'b1-w01')
        with self.assertRaises(ValueError): sweep.assigned(data, 65)

    def test_frozen_digest_is_required_before_network_access(self):
        with directory() as folder:
            path = Path(folder) / 'manifest.json'
            sweep.save(path, plan())
            self.assertEqual(len(sweep.read_plan(path, sweep.sha(path))['records']), 1)
            with self.assertRaises(ValueError): sweep.read_plan(path, 'f' * 64)

    def test_source_and_redirect_never_receive_repository_credentials(self):
        class Response:
            headers = {'Content-Type': 'application/octet-stream'}
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, *_): return b'original'
        calls = []
        def opened(request, **_):
            calls.append(request)
            if len(calls) == 1:
                raise HTTPError(request.full_url, 302, 'redirect',
                                {'Location': 'https://download.example/file?temporary=secret'}, None)
            return Response()
        client = sweep.Client('https://source.example', 0)
        client.opener = SimpleNamespace(open=opened)
        with patch.dict(os.environ, {'GH_TOKEN': 'must-stay-here'}):
            raw, receipt = client.get('https://source.example/file')
        self.assertEqual(raw, b'original')
        for call in calls:
            self.assertFalse({'authorization', 'cookie'} & {k.lower() for k, _ in call.header_items()})
        self.assertNotIn('secret', json.dumps(receipt))
        self.assertEqual(receipt['final_url'], 'https://download.example/file')

    def test_pacing_and_429_slowdown_honor_retry_after(self):
        class Response:
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, *_): return b'data'
        calls = []
        def opened(request, **_):
            calls.append(request)
            if len(calls) == 1:
                raise HTTPError(request.full_url, 429, 'slow down', {'Retry-After': '120'}, None)
            return Response()
        client = sweep.Client('https://source.example', 3)
        client.opener = SimpleNamespace(open=opened)
        clock = [100.0]
        waits = []
        def sleep(seconds):
            waits.append(seconds)
            clock[0] += seconds
        with patch.object(sweep.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(sweep.time, 'sleep', side_effect=sleep):
            client.get('https://source.example/file')
        self.assertEqual(client.slowdown, 2)
        self.assertIn(120, waits)
        self.assertGreaterEqual(clock[0], 220)
        self.assertEqual(client.requests['retry_429'], 1)

    def test_concurrent_source_requests_share_one_gate(self):
        gate = sweep.Gate(.01)
        times = []
        lock = threading.Lock()
        def acquire(i):
            gate.acquire()
            with lock:
                times.append(time.monotonic())
            return i
        self.assertEqual(list(sweep.ordered_results(acquire, range(12), 4)), list(range(12)))
        times.sort()
        self.assertGreaterEqual(times[-1] - times[0], .105)

    def test_retry_after_blocks_every_lane_sharing_a_gate(self):
        gate = sweep.Gate(1)
        clock = [100.0]
        def sleep(seconds): clock[0] += seconds
        with patch.object(sweep.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(sweep.time, 'sleep', side_effect=sleep):
            gate.acquire()
            gate.backoff(120)
            self.assertEqual(gate.acquire(), 120)
            self.assertEqual(clock[0], 220)
            self.assertEqual(gate.slowdown, 2)

    def test_more_lanes_do_not_multiply_the_origin_budget(self):
        data = plan()
        args = SimpleNamespace(parallel=40, rpm=1200, lanes=4)
        policy = sweep.execution(args, data)
        self.assertEqual(60 * policy['parallel'] / policy['rpm'], 2)
        args.lanes = 1
        self.assertEqual(sweep.execution(args, data)['rpm'], 1200)
        args.rpm = 1201
        with self.assertRaises(ValueError): sweep.execution(args, data)

    def test_wire_gzip_is_decoded_but_source_gzip_bytes_are_preserved(self):
        raw = gzip.compress(b'original source file', mtime=0)
        class Response:
            headers = {}
            data = raw
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, *_): return self.data
        response = Response()
        client = sweep.Client('https://source.example', 0)
        client.opener = SimpleNamespace(open=lambda *a, **k: response)
        self.assertEqual(client.get('https://source.example/file')[0], raw)
        response.headers = {'Content-Encoding': 'gzip'}
        response.data = gzip.compress(raw, mtime=0)
        self.assertEqual(client.get('https://source.example/file')[0], raw)

    def test_archive_roundtrip_and_scoped_generated_cleanup(self):
        with directory() as folder:
            out = Path(folder)
            item = plan()['records'][0]
            row, compressed = record(item)
            sub = out / 'record-1'
            sub.mkdir()
            (sub / 'payload.gz').write_bytes(compressed)
            sweep.save(sub / 'meta.json', row)
            unrelated = out / 'keep.txt'
            unrelated.write_text('keep')
            path = sweep.package(out, 'chunk-000', 0, [row], 'a' * 64)
            with tarfile.open(path) as archive:
                meta = json.load(archive.extractfile('record-1/meta.json'))
                raw = gzip.decompress(archive.extractfile('record-1/payload.gz').read())
            self.assertEqual(sweep.digest(raw), meta['files'][0]['sha256'])
            sweep.discard(out, path, [row])
            self.assertTrue(unrelated.exists())
            self.assertFalse(sub.exists())

    def test_completed_summary_rejects_missing_coverage_and_changed_assets(self):
        data = plan()
        row, _ = record(data['records'][0])
        package = {'name': 'chunk-000-part-000.tar', 'id': 2, 'bytes': 1000,
                   'sha256': 'a' * 64, 'ids': [1], 'tag': 'b1-w00'}
        summary = {'schema': sweep.SCHEMA, 'plan_sha256': 'hash', 'shard': 0,
                   'assigned_ids': [1], 'collected_ids': [1], 'records': [row], 'packages': [package]}
        store = object.__new__(sweep.Store)
        store.tag = 'b1-w00'
        store.assets = {package['name']: {'id': 2, 'size': 1000, 'state': 'uploaded', 'digest': 'sha256:' + 'a' * 64}}
        store.json_asset = lambda name: summary
        self.assertEqual(sweep.read_summary(store, 0, data, 'hash')['collected_ids'], [1])
        summary['packages'][0]['ids'] = []
        with self.assertRaises(ValueError): sweep.read_summary(store, 0, data, 'hash')
        summary['packages'][0]['ids'] = [1]
        store.assets[package['name']]['digest'] = 'sha256:' + 'b' * 64
        with self.assertRaises(ValueError): sweep.read_summary(store, 0, data, 'hash')

    def test_checkpoint_resume_rejects_changed_source_attributes(self):
        item = plan()['records'][0]
        row, _ = record(item)
        sweep.verify_rows([row], [item])
        item = deepcopy(item)
        item['attributes']['at'] += 1
        with self.assertRaises(ValueError): sweep.verify_rows([row], [item])

    def test_orphan_archive_is_recovered_with_every_file_verified(self):
        with directory() as folder:
            out = Path(folder)
            row, compressed = record(plan()['records'][0])
            sub = out / 'record-1'
            sub.mkdir()
            (sub / 'payload.gz').write_bytes(compressed)
            sweep.save(sub / 'meta.json', row)
            path = sweep.package(out, 'chunk-000', 0, [row], 'a' * 64)
            store = object.__new__(sweep.Store)
            store.repo, store.tag = 'owner/boxes', 'b1-w00'
            asset = {'id': 2, 'size': path.stat().st_size, 'state': 'uploaded', 'digest': 'sha256:' + sweep.sha(path)}
            store.assets = {path.name: asset}
            store.json_asset = lambda name: None
            store.upload = lambda path: {'id': 3}
            with patch.object(sweep, 'gh_download'):
                restored = store.recover('chunk-000', out, 'a' * 64)
            self.assertEqual(restored[0]['package']['ids'], [1])
            self.assertEqual(restored[0]['records'], [row])

    def test_binary_asset_download_streams_without_shell_redirection(self):
        with directory() as folder:
            path = Path(folder) / 'data.tar'
            def run(arguments, stdout, stderr):
                self.assertEqual(arguments[-1], 'repos/owner/boxes/releases/assets/12')
                stdout.write(b'original\x00\xff\x80')
                return subprocess.CompletedProcess(arguments, 0, stderr=b'')
            with patch.object(sweep.subprocess, 'run', side_effect=run):
                sweep.gh_download('owner/boxes', 12, path)
            self.assertEqual(path.read_bytes(), b'original\x00\xff\x80')

    def test_upload_streams_and_verifies_server_sha256(self):
        class Response:
            status = 201
            def getheader(self, name): return None
            def read(self, count): return json.dumps(asset).encode()
        class Connection:
            def __init__(self, host, **kw): self.host = host
            def request(self, method, url, body, headers):
                self_test.assertEqual(self.host, 'uploads.github.com')
                self_test.assertTrue(hasattr(body, 'read'))
                self_test.assertEqual(headers['Authorization'], 'Bearer fake-token')
            def getresponse(self): return Response()
            def close(self): pass
        self_test = self
        store = object.__new__(sweep.Store)
        store.repo, store.tag, store.assets = 'owner/boxes', 'b1', {}
        store.release = {'id': 1, 'upload_url': 'https://uploads.github.com/repos/owner/boxes/releases/1/assets{?name,label}'}
        with directory() as folder:
            path = Path(folder) / 'package.tar'
            path.write_bytes(b'archive')
            asset = {'name': path.name, 'id': 2, 'size': path.stat().st_size, 'state': 'uploaded',
                     'digest': 'sha256:' + sweep.sha(path)}
            with patch.object(sweep.http.client, 'HTTPSConnection', Connection), patch.dict(os.environ, {'GH_TOKEN': 'fake-token'}):
                receipt = store.upload(path)
            self.assertEqual(receipt['sha256'], sweep.sha(path))

    def test_permission_error_is_not_mistaken_for_rate_limit(self):
        with patch.object(sweep.subprocess, 'run') as run:
            self.assertIsNone(sweep.github_pause(b'Resource not accessible by integration (HTTP 403)', 0))
        run.assert_not_called()

    def test_resume_fetches_only_missing_records_and_publishes_complete_inventory(self):
        data = plan(2)
        restored, _ = record(data['records'][0])
        package = {'name': 'chunk-000-part-000.tar', 'id': 2, 'bytes': 1000,
                   'sha256': 'a' * 64, 'ids': [1], 'tag': 'b1-w00'}
        class FakeStore:
            def json_asset(self, name): return None
            def recover(self, *a):
                return [{'records': [restored], 'package': package}]
            def upload(self, path):
                uploaded.append(path.name)
                if path.name.endswith('summary.json'):
                    summaries.append(json.loads(path.read_text()))
                return {'name': path.name, 'id': 3, 'bytes': path.stat().st_size,
                        'sha256': sweep.sha(path), 'tag': 'b1-w00'}
        class FakeClient:
            def get(self, url):
                calls.append(url)
                raw = b'new bytes'
                return raw, {'sha256': sweep.digest(raw), 'bytes': len(raw), 'content_type': 'application/octet-stream'}
            def stats(self): return {}
        calls, uploaded, summaries = [], [], []
        with directory() as folder:
            args = SimpleNamespace(repo='owner/boxes', tag='b1', shard=0, sha256='a' * 64, out=Path(folder))
            with patch.object(sweep, 'Store', return_value=FakeStore()), patch.object(sweep, 'Client', return_value=FakeClient()), patch.object(sweep.time, 'sleep'):
                sweep.fetch(args, data)
        self.assertEqual(calls, ['https://source.example/items/2'])
        self.assertIn('chunk-000-part-001-receipt.json', uploaded)
        self.assertEqual(summaries[0]['collected_ids'], [1, 2])
        self.assertFalse(summaries[0]['failures'])

    def test_binary_error_page_cannot_enter_a_completed_archive(self):
        data = plan()
        class FakeStore:
            def json_asset(self, name): return None
            def recover(self, *a): return []
            def upload(self, path):
                saved.append(json.loads(path.read_text()))
                self_test.assertIn('-attempt-', path.name)
                return {}
        class FakeClient:
            def get(self, url): return b'<html>error</html>', {'content_type': 'text/html'}
            def stats(self): return {}
        self_test, saved = self, []
        with directory() as folder:
            args = SimpleNamespace(repo='owner/boxes', tag='b1', shard=0, sha256='a' * 64, out=Path(folder))
            with patch.object(sweep, 'Store', return_value=FakeStore()), patch.object(sweep, 'Client', return_value=FakeClient()), patch.object(sweep.time, 'sleep'), self.assertRaises(RuntimeError):
                sweep.fetch(args, data)
        self.assertEqual(saved[0]['collected_ids'], [])
        self.assertEqual(saved[0]['failures'][0]['id'], 1)
        self.assertEqual(saved[0]['failures'][0]['reason'], 'Expected binary content')

    def test_completed_aggregate_rerun_reuses_immutable_inventory(self):
        data = plan()
        row, _ = record(data['records'][0])
        package = {'name': 'chunk-000-part-000.tar', 'id': 2, 'bytes': 1000,
                   'sha256': 'a' * 64, 'ids': [1], 'tag': 'b1-w00'}
        chunk = {'schema': sweep.SCHEMA, 'plan_sha256': 'a' * 64, 'shard': 0,
                 'assigned_ids': [1], 'collected_ids': [1], 'records': [row], 'packages': [package]}
        summary = {'schema': sweep.SCHEMA, 'plan_sha256': 'a' * 64, 'complete': True,
                   'queued_records': 1, 'collected_records': 1, 'retained_elsewhere_ids': [900000],
                   'missing_ids': [], 'missing_chunks': [], 'packages': [package], 'stored_bytes': 1000,
                   'completed_utc': 'original timestamp'}
        class FakeStore:
            def json_asset(self, name):
                return summary if name == 'summary.json' else chunk
            def check_package(self, receipt): pass
            def upload(self, path):
                self_test.fail('Completed inventory must not be rewritten on retry')
        self_test = self
        with directory() as folder:
            args = SimpleNamespace(repo='owner/boxes', tag='b1', sha256='a' * 64, out=Path(folder))
            with patch.object(sweep, 'Store', return_value=FakeStore()):
                sweep.aggregate(args, data)
                summary['stored_bytes'] += 1
                with self.assertRaises(ValueError): sweep.aggregate(args, data)


if __name__ == '__main__':
    unittest.main()
