"""Put a frozen list of public URLs into checked release bundles."""
from __future__ import annotations

import argparse
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tarfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

SCHEMA = 'url-bundles-1'
MAX_BYTES = 64 * 1024 * 1024
PACKAGE_BYTES = 1536 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.part')
    temporary.write_text(json.dumps(obj, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def retry_seconds(value, attempt):
    delay = min(60, 2 ** (attempt + 1))
    if value:
        try:
            delay = max(delay, float(value))
        except ValueError:
            try:
                delay = max(delay, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
    return max(0, delay)


def https_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or '\\' in value or any(ord(c) < 33 for c in value)):
        raise ValueError('Only credential-free HTTPS URLs are accepted')
    return parsed


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Gate:
    def __init__(self, interval):
        self.interval, self.last = interval, 0.0
        self.slowdown, self.blocked_until = 1.0, 0.0
        self.lock = threading.Lock()

    def acquire(self):
        waited = 0.0
        while True:
            with self.lock:
                current = time.monotonic()
                delay = max(0, self.last + self.interval * self.slowdown - current,
                            self.blocked_until - current)
                if delay <= 0:
                    self.last = current
                    return waited
            time.sleep(delay)
            waited += delay

    def backoff(self, seconds):
        with self.lock:
            self.slowdown = min(8, self.slowdown * 2)
            self.blocked_until = max(self.blocked_until, time.monotonic() + seconds)


class Client:
    def __init__(self, origin, interval, gate=None):
        self.origin = https_url(origin).netloc
        self.interval, self.last = interval, 0.0
        self.gate = gate or Gate(interval)
        self.opener = build_opener(NoRedirect())
        self.requests = Counter()
        self.wait_seconds = 0.0
        self.slowdown = 1.0
        self.transfer_seconds = Counter()
        self.received_bytes = Counter()

    def get(self, url):
        requested = url
        redirects = attempts = 0
        while True:
            parsed = https_url(url)
            origin = parsed.netloc == self.origin
            if origin:
                self.wait_seconds += self.gate.acquire()
                self.slowdown = self.gate.slowdown
            kind = 'origin' if origin else 'download'
            self.requests[kind] += 1
            began = time.monotonic()
            try:
                request = Request(url, headers={'User-Agent': 'url-bundler/1', 'Accept-Encoding': 'gzip'})
                with self.opener.open(request, timeout=90) as response:
                    raw = response.read(MAX_BYTES + 1)
                    encoding = response.headers.get('Content-Encoding', '').lower()
                    content_type = response.headers.get('Content-Type', '')
                    http_date = response.headers.get('Date')
                if len(raw) > MAX_BYTES:
                    raise ValueError('Response exceeds the size bound')
                wire_bytes = len(raw)
                self.received_bytes[kind] += wire_bytes
                if encoding == 'gzip':
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                        raw = stream.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError('Decoded response exceeds the size bound')
                final = parsed if origin else parsed._replace(query='')
                return raw, {'requested_url': requested, 'final_url': final.geturl(),
                    'query_sha256': digest(parsed.query.encode()) if not origin and parsed.query else None,
                    'fetched_utc': now(), 'content_type': content_type, 'http_date': http_date,
                    'wire_bytes': wire_bytes, 'bytes': len(raw), 'sha256': digest(raw)}
            except HTTPError as error:
                status, location = error.code, error.headers.get('Location')
                retry = error.headers.get('Retry-After')
                error.close()
                if status in (301, 302, 303, 307, 308) and location and redirects < 5:
                    url = urljoin(url, location)
                    redirects += 1
                    continue
                if status not in (429, 500, 502, 503, 504) or attempts >= 5:
                    raise RuntimeError(f'HTTP {status} from {kind}') from None
                delay = retry_seconds(retry, attempts)
                if delay > 600:
                    raise RuntimeError(f'HTTP {status}: requested wait exceeds this attempt') from None
                self.requests[f'retry_{status}'] += 1
                if status == 429:
                    self.gate.backoff(delay)
                    self.slowdown = self.gate.slowdown
            except (URLError, TimeoutError, OSError):
                if attempts >= 5:
                    raise RuntimeError(f'Transfer failed from {kind}') from None
                delay = retry_seconds(None, attempts)
                self.requests['retry_network'] += 1
            finally:
                self.transfer_seconds[kind] += time.monotonic() - began
            time.sleep(delay)
            self.wait_seconds += delay
            attempts += 1

    def stats(self):
        return {'requests': dict(self.requests), 'wait_seconds': self.wait_seconds,
                'interval_seconds': self.interval, 'slowdown': self.gate.slowdown,
                'transfer_seconds': dict(self.transfer_seconds), 'received_bytes': dict(self.received_bytes)}


def execution(args, plan):
    policy = {'parallel': getattr(args, 'parallel', 0) or plan['parallel'],
              'rpm': getattr(args, 'rpm', 0) or plan['origin_rpm'],
              'lanes': getattr(args, 'lanes', 1)}
    if (any(type(v) is not int for v in policy.values()) or not 1 <= policy['parallel'] <= 40
            or not 60 <= policy['rpm'] <= 1200 or not 1 <= policy['lanes'] <= 4):
        raise ValueError('Execution policy outside declared bounds')
    return policy


def ordered_results(function, items, lanes):
    """Bound queued work and preserve input order while transfers overlap."""
    source = iter(items)
    with ThreadPoolExecutor(max_workers=lanes) as pool:
        pending = deque()
        for _ in range(lanes * 2):
            item = next(source, None)
            if item is None:
                break
            pending.append(pool.submit(function, item))
        while pending:
            yield pending.popleft().result()
            item = next(source, None)
            if item is not None:
                pending.append(pool.submit(function, item))


def github_pause(stderr, attempt):
    message = stderr.decode(errors='replace').lower()
    if re.search(r'http (?:500|502|503|504)\b|connection reset|tls handshake timeout', message):
        return min(60, 2 ** (attempt + 1))
    if 'rate limit' not in message and 'http 429' not in message:
        return None
    probe = subprocess.run(['gh', 'api', 'rate_limit'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    delay = min(900, 60 * 2**attempt)
    if not probe.returncode:
        core = json.loads(probe.stdout)['resources']['core']
        if core['remaining'] == 0:
            delay = max(1, core['reset'] - time.time() + 3)
    return delay


def gh(arguments, binary=False):
    for attempt in range(8):
        completed = subprocess.run(['gh', *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not completed.returncode:
            return completed.stdout if binary else completed.stdout.decode('utf-8')
        delay = github_pause(completed.stderr, attempt)
        if delay is None or attempt == 7:
            raise RuntimeError(f'GitHub command {arguments[0]} failed (exit {completed.returncode})')
        print(json.dumps({'github_wait_seconds': round(delay)}), flush=True)
        time.sleep(delay)


def gh_download(repo, asset_id, path):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or type(asset_id) is not int or asset_id <= 0:
        raise ValueError('Unsafe asset identity')
    path = Path(path)
    pending = path.with_name(path.name + '.part')
    for attempt in range(8):
        with pending.open('wb') as stream:
            completed = subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream',
                f'repos/{repo}/releases/assets/{asset_id}'], stdout=stream, stderr=subprocess.PIPE)
        if not completed.returncode:
            pending.replace(path)
            return
        pending.unlink()
        delay = github_pause(completed.stderr, attempt)
        if delay is None or attempt == 7:
            raise RuntimeError('Asset download failed')
        time.sleep(delay)


def identity(repo, tag):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', tag):
        raise ValueError('Invalid release identity')


class Store:
    def __init__(self, repo, tag):
        identity(repo, tag)
        self.repo, self.tag = repo, tag
        info = json.loads(gh(['api', f'repos/{repo}']))
        if info.get('visibility') != 'public' or info.get('private') is not False:
            raise ValueError('This runner requires a public repository')
        self.release = json.loads(gh(['api', f'repos/{repo}/releases/tags/{tag}']))
        self.refresh()

    def refresh(self):
        self.assets = {}
        for page in range(1, 12):
            values = json.loads(gh(['api', f'repos/{self.repo}/releases/{self.release["id"]}/assets?per_page=100&page={page}']))
            for asset in values:
                if asset['name'] in self.assets:
                    prior = self.assets[asset['name']]
                    # Insertions move an identical asset across page boundaries.
                    # Distinct IDs or changed content still fail validation.
                    if any(prior.get(k) != asset.get(k) for k in ('id', 'size', 'digest', 'state')):
                        raise ValueError('Conflicting remote asset name')
                    continue
                self.assets[asset['name']] = asset
            if len(values) < 100:
                return
        raise ValueError('Too many release assets')

    def upload(self, path):
        path = Path(path)
        expected = sha(path)
        asset = self.assets.get(path.name)
        if asset is None:
            url = self.release['upload_url'].split('{', 1)[0] + '?' + urlencode({'name': path.name})
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.netloc != 'uploads.github.com'
                    or parsed.path != f'/repos/{self.repo}/releases/{self.release["id"]}/assets'):
                raise ValueError('Unexpected upload destination')
            token = os.environ.get('GH_TOKEN', '')
            if not token:
                raise ValueError('Upload requires the repository token')
            for attempt in range(4):
                wait = 0
                connection = http.client.HTTPSConnection('uploads.github.com', timeout=600)
                try:
                    with path.open('rb') as stream:
                        connection.request('POST', parsed.path + '?' + parsed.query, body=stream,
                            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/octet-stream',
                                     'Content-Length': str(path.stat().st_size), 'User-Agent': 'url-bundler/1'})
                        response = connection.getresponse()
                        raw, status = response.read(2 * 1024 * 1024), response.status
                        wait = retry_seconds(response.getheader('Retry-After'), attempt)
                        if status in (403, 429) and response.getheader('X-RateLimit-Remaining') == '0':
                            reset = response.getheader('X-RateLimit-Reset')
                            if reset and reset.isdigit():
                                wait = max(wait, int(reset) - time.time() + 3)
                        elif status in (403, 429):
                            wait = max(wait, min(900, 60 * 2**attempt))
                    if status == 201:
                        asset = json.loads(raw)
                        break
                    raise RuntimeError(f'Asset upload HTTP {status}')
                except (RuntimeError, OSError, http.client.HTTPException):
                    self.refresh()
                    asset = self.assets.get(path.name)
                    if asset:
                        break
                    if attempt == 3:
                        raise
                    time.sleep(max(2 ** (attempt + 1), wait))
                finally:
                    connection.close()
        if asset is None or asset['state'] != 'uploaded' or asset['size'] != path.stat().st_size:
            raise ValueError('Remote asset size/state differs')
        if asset.get('digest'):
            if asset['digest'] != 'sha256:' + expected:
                raise ValueError('Remote asset digest differs')
            verification = 'server SHA256'
        else:
            copy = path.with_name(path.name + '.readback')
            gh_download(self.repo, asset['id'], copy)
            if sha(copy) != expected:
                raise ValueError('Asset readback differs')
            copy.unlink()
            verification = 'readback SHA256'
        self.assets[path.name] = asset
        return {'name': path.name, 'id': asset['id'], 'bytes': asset['size'], 'sha256': expected,
                'verified_by': verification, 'uploaded_utc': now(), 'tag': self.tag}

    def json_asset(self, name):
        asset = self.assets.get(name)
        if asset is None:
            return None
        if asset['size'] > MAX_BYTES:
            raise ValueError('JSON asset exceeds size bound')
        raw = gh(['api', '-H', 'Accept: application/octet-stream',
                  f'repos/{self.repo}/releases/assets/{asset["id"]}'], binary=True)
        if len(raw) != asset['size'] or (asset.get('digest') and asset['digest'] != 'sha256:' + digest(raw)):
            raise ValueError('JSON asset identity differs')
        return json.loads(raw)

    def check_package(self, receipt):
        asset = self.assets.get(receipt['name'])
        if (asset is None or asset['id'] != receipt['id'] or asset['state'] != 'uploaded'
                or asset['size'] != receipt['bytes'] or receipt['tag'] != self.tag
                or not asset.get('digest') or asset['digest'] != 'sha256:' + receipt['sha256']):
            raise ValueError('Checkpoint asset identity differs')

    def recover(self, prefix, out, plan_hash):
        result = []
        for name, asset in sorted(list(self.assets.items())):
            if not re.fullmatch(re.escape(prefix) + r'-part-\d{3}\.tar', name):
                continue
            receipt_name = name[:-4] + '-receipt.json'
            record = self.json_asset(receipt_name)
            if record is None:
                path = out / name
                gh_download(self.repo, asset['id'], path)
                checksum = sha(path)
                if asset.get('digest') != 'sha256:' + checksum:
                    raise ValueError('Orphan archive digest differs')
                with tarfile.open(path) as archive:
                    manifest = json.load(archive.extractfile('manifest.json'))
                    if manifest['plan_sha256'] != plan_hash:
                        raise ValueError('Orphan archive belongs to another plan')
                    for row in manifest['records']:
                        meta = json.load(archive.extractfile(f'record-{row["id"]}/meta.json'))
                        if meta != row:
                            raise ValueError('Orphan metadata differs')
                        for file in row['files']:
                            compressed = archive.extractfile(f'record-{row["id"]}/{file["name"]}').read(MAX_BYTES + 1)
                            if len(compressed) > MAX_BYTES or digest(compressed) != file['gzip_sha256']:
                                raise ValueError('Orphan compressed file differs')
                            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                                raw = stream.read(MAX_BYTES + 1)
                            if len(raw) != file['bytes'] or digest(raw) != file['sha256']:
                                raise ValueError('Orphan original file differs')
                receipt = {'name': name, 'id': asset['id'], 'bytes': asset['size'], 'sha256': checksum,
                           'ids': [r['id'] for r in manifest['records']], 'tag': self.tag,
                           'verified_by': 'readback and file SHA256'}
                record = {'schema': SCHEMA, 'plan_sha256': plan_hash, 'package': receipt,
                          'records': manifest['records']}
                receipt_path = out / receipt_name
                save(receipt_path, record)
                self.upload(receipt_path)
                path.unlink()
            if (record.get('schema') != SCHEMA or record['plan_sha256'] != plan_hash
                    or record['package']['name'] != name
                    or record['package']['ids'] != [r['id'] for r in record['records']]):
                raise ValueError('Checkpoint manifest differs')
            self.check_package(record['package'])
            result.append(record)
        return result


def validate(plan):
    if plan.get('schema') != SCHEMA:
        raise ValueError('Unsupported manifest schema')
    parsed = https_url(plan['origin'])
    if parsed.path not in ('', '/') or parsed.query:
        raise ValueError('Origin must contain only scheme and host')
    records, retained = plan['records'], plan['retained_ids']
    if not 1 <= len(records) <= 131072 or len(records) + len(retained) > 150000:
        raise ValueError('Manifest count outside declared bounds')
    ids = [r['id'] for r in records] + retained
    if any(type(i) is not int or i <= 0 for i in ids) or len(ids) != len(set(ids)):
        raise ValueError('Duplicate or invalid record IDs')
    if plan['total_records'] != len(ids):
        raise ValueError('Manifest total differs')
    if (plan['chunk_records'] != 512 or plan['release_shards'] != 64
            or plan['checkpoint_records'] != 256 or type(plan['parallel']) is not int
            or not 1 <= plan['parallel'] <= 20 or type(plan['origin_rpm']) is not int
            or not 60 <= plan['origin_rpm'] <= 360):
        raise ValueError('Unsupported allocation or request budget')
    for row in records:
        if not isinstance(row['attributes'], dict) or not 1 <= len(row['files']) <= 8:
            raise ValueError('Invalid record structure')
        names = []
        for file in row['files']:
            name, path = file['name'], file['path']
            names.append(name)
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,70}\.gz', name) or name == 'meta.json':
                raise ValueError('Unsafe file name')
            if not path.startswith('/') or path.startswith('//') or '\\' in path:
                raise ValueError('Only same-origin relative paths are accepted')
            if https_url(plan['origin'].rstrip('/') + path).netloc != parsed.netloc:
                raise ValueError('File URL escaped origin')
            if file['kind'] not in ('text', 'binary'):
                raise ValueError('Unsupported content kind')
        if len(names) != len(set(names)):
            raise ValueError('Duplicate record file name')


def read_plan(path, expected):
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or sha(path) != expected:
        raise ValueError('Frozen manifest SHA256 differs')
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    validate(plan)
    return plan


def assigned(plan, shard):
    if type(shard) is not int or not 0 <= shard < math.ceil(len(plan['records']) / 512):
        raise ValueError('Invalid chunk number')
    return plan['records'][shard * 512:(shard + 1) * 512]


def wave(tag, shard):
    return f'{tag}-w{shard // 64:02d}'


def verify_rows(rows, expected):
    expected = {r['id']: r for r in expected}
    ids = [r['id'] for r in rows]
    if len(ids) != len(set(ids)) or not set(ids) <= set(expected):
        raise ValueError('Duplicate or unassigned checkpoint records')
    for row in rows:
        item = expected[row['id']]
        if row['attributes'] != item['attributes'] or row['source_files'] != item['files']:
            raise ValueError('Checkpoint source identity differs')
        if [f['name'] for f in row['files']] != [f['name'] for f in item['files']]:
            raise ValueError('Checkpoint file inventory differs')


def read_summary(store, shard, plan, plan_hash):
    summary = store.json_asset(f'chunk-{shard:03d}-summary.json')
    if summary is None:
        return None
    expected = assigned(plan, shard)
    if (summary.get('schema') != SCHEMA or summary['plan_sha256'] != plan_hash
            or summary['shard'] != shard or summary['assigned_ids'] != [r['id'] for r in expected]
            or summary['collected_ids'] != [r['id'] for r in summary['records']]
            or summary.get('failures')):
        raise ValueError('Completed summary does not match manifest')
    verify_rows(summary['records'], expected)
    package_ids = []
    for receipt in summary['packages']:
        store.check_package(receipt)
        package_ids.extend(receipt['ids'])
    if len(package_ids) != len(set(package_ids)) or set(package_ids) != set(summary['collected_ids']):
        raise ValueError('Summary package coverage differs')
    if set(summary['collected_ids']) != {r['id'] for r in expected}:
        raise ValueError('Completed summary has missing records')
    return summary


def package(out, prefix, part, records, plan_hash):
    path = out / f'{prefix}-part-{part:03d}.tar'
    manifest = {'schema': SCHEMA, 'plan_sha256': plan_hash, 'records': records, 'created_utc': now()}
    raw = (json.dumps(manifest, ensure_ascii=True, indent=2) + '\n').encode()
    with tarfile.open(path, 'w') as archive:
        entry = tarfile.TarInfo('manifest.json')
        entry.size = len(raw)
        archive.addfile(entry, io.BytesIO(raw))
        for record in records:
            folder = out / f'record-{record["id"]}'
            for name in ('meta.json', *[f['name'] for f in record['files']]):
                archive.add(folder / name, arcname=f'record-{record["id"]}/{name}', recursive=False)
    if path.stat().st_size >= 2 * 1024 ** 3:
        raise ValueError('Package exceeds asset size limit')
    return path


def discard(out, path, records):
    root = out.resolve()
    targets = [path, *[out / f'record-{r["id"]}' / name for r in records
        for name in ('meta.json', *[f['name'] for f in r['files']])]]
    for target in targets:
        if target.is_symlink() or not target.resolve().is_relative_to(root):
            raise ValueError('Generated file escaped output folder')
    for target in targets:
        target.unlink()
    for row in records:
        (out / f'record-{row["id"]}').rmdir()


def prepare(args, plan):
    policy = execution(args, plan)
    stores, missing = {}, []
    for shard in range(math.ceil(len(plan['records']) / 512)):
        tag = wave(args.tag, shard)
        if tag not in stores:
            probe = subprocess.run(['gh', 'api', f'repos/{args.repo}/releases/tags/{tag}'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if probe.returncode:
                if b'HTTP 404' not in probe.stderr:
                    raise RuntimeError('Cannot inspect release')
                gh(['release', 'create', tag, '--repo', args.repo, '--target', os.environ['GITHUB_SHA'],
                    '--title', tag, '--notes', 'Checked bundles.', '--latest=false'])
            stores[tag] = Store(args.repo, tag)
        if read_summary(stores[tag], shard, plan, args.sha256) is None:
            missing.append(shard)
    output = {'matrix': json.dumps({'shard': missing}, separators=(',', ':')),
              'parallel': str(policy['parallel']), 'count': str(len(missing))}
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            for key, value in output.items():
                stream.write(f'{key}={value}\n')
    print(json.dumps({'queued_chunks': len(missing), 'records': len(plan['records']),
                      'retained_elsewhere': len(plan['retained_ids']), 'execution_policy': policy}), flush=True)


def fetch_record(item, plan, out, gate):
    client = Client(plan['origin'], gate.interval, gate=gate)
    try:
        files, contents = [], []
        for source in item['files']:
            raw, receipt = client.get(plan['origin'].rstrip('/') + source['path'])
            mime = receipt['content_type'].split(';', 1)[0].lower()
            if not raw:
                raise ValueError('Empty source file')
            if source['kind'] == 'binary' and (mime.startswith('text/') or mime.endswith('json')
                    or raw.lstrip()[:30].lower().startswith((b'<!doctype', b'<html', b'{"error"'))):
                raise ValueError('Expected binary content')
            if source['kind'] == 'text':
                raw.decode('utf-8')
            compressed = gzip.compress(raw, compresslevel=6, mtime=0)
            if digest(gzip.decompress(compressed)) != receipt['sha256']:
                raise ValueError('Compression round-trip differs')
            files.append({'name': source['name'], **receipt, 'gzip_bytes': len(compressed),
                          'gzip_sha256': digest(compressed)})
            contents.append(compressed)
        record = {'id': item['id'], 'attributes': item['attributes'], 'source_files': item['files'], 'files': files}
        size = sum(map(len, contents)) + len(json.dumps(record)) + 8192
        folder = out / f'record-{item["id"]}'
        folder.mkdir(exist_ok=True)
        for file, content in zip(files, contents):
            (folder / file['name']).write_bytes(content)
        save(folder / 'meta.json', record)
        return {'record': record, 'bytes': size, 'network': client.stats()}
    except (ValueError, RuntimeError, OSError) as error:
        return {'failure': {'id': item['id'], 'type': type(error).__name__,
                           'reason': str(error)[:240], 'failed_utc': now()}, 'network': client.stats()}


def fetch(args, plan):
    started = time.monotonic()
    rows = assigned(plan, args.shard)
    prefix = f'chunk-{args.shard:03d}'
    store = Store(args.repo, wave(args.tag, args.shard))
    if read_summary(store, args.shard, plan, args.sha256) is not None:
        print(json.dumps({'reused_chunk': args.shard, 'records': len(rows)}), flush=True)
        return
    policy = execution(args, plan)
    time.sleep((args.shard % policy['parallel']) * 60 / policy['rpm'])
    gate = Gate(60 * policy['parallel'] / policy['rpm'])
    counters = {'requests': Counter(), 'transfer_seconds': Counter(), 'received_bytes': Counter()}
    total_wait = 0.0

    def stats():
        return {**{k: dict(v) for k,v in counters.items()}, 'wait_seconds': total_wait,
                'interval_seconds': gate.interval, 'slowdown': gate.slowdown}
    recovered = store.recover(prefix, args.out, args.sha256)
    all_records = [r for c in recovered for r in c['records']]
    verify_rows(all_records, rows)
    packages = [c['package'] for c in recovered]
    done = {r['id'] for r in all_records}
    records, failures, pending_bytes = [], [], 0
    part = 1 + max((int(Path(p['name']).stem.rsplit('-', 1)[1]) for p in packages), default=-1)

    def checkpoint():
        nonlocal records, pending_bytes, part
        if not records:
            return
        path = package(args.out, prefix, part, records, args.sha256)
        receipt = store.upload(path)
        receipt['ids'] = [r['id'] for r in records]
        receipt_path = args.out / (path.stem + '-receipt.json')
        save(receipt_path, {'schema': SCHEMA, 'plan_sha256': args.sha256, 'package': receipt, 'records': records})
        store.upload(receipt_path)
        packages.append(receipt)
        all_records.extend(records)
        discard(args.out, path, records)
        print(json.dumps({'checkpoint': receipt['name'], 'records': len(records), 'bytes': receipt['bytes']}), flush=True)
        records, pending_bytes, part = [], 0, part + 1

    todo = [r for r in rows if r['id'] not in done]
    def work(item):
        return fetch_record(item, plan, args.out, gate)
    for index, result in enumerate(ordered_results(work, todo, policy['lanes'])):
        network = result['network']
        total_wait += network.get('wait_seconds', 0)
        for key in counters:
            counters[key].update(network.get(key, {}))
        if 'failure' in result:
            failures.append(result['failure'])
            print(json.dumps({'failed_record': result['failure']}), flush=True)
        else:
            if records and pending_bytes + result['bytes'] > PACKAGE_BYTES:
                checkpoint()
            records.append(result['record'])
            pending_bytes += result['bytes']
        if len(records) >= plan['checkpoint_records']:
            checkpoint()
        if (index + 1) % 25 == 0:
            print(json.dumps({'chunk': args.shard, 'attempted': index + 1,
                'collected': len(all_records) + len(records), 'failed': len(failures),
                'seconds': time.monotonic() - started, 'execution_policy': policy, 'network': stats()}), flush=True)
    checkpoint()
    summary = {'schema': SCHEMA, 'plan_sha256': args.sha256, 'shard': args.shard,
               'assigned_ids': [r['id'] for r in rows], 'collected_ids': [r['id'] for r in all_records],
               'records': all_records, 'packages': packages, 'failures': failures,
               'completed_utc': now(), 'seconds': time.monotonic() - started,
               'execution_policy': policy, 'network': stats()}
    name = prefix + '-summary.json' if not failures else prefix + '-attempt-' + run_id() + '.json'
    path = args.out / name
    save(path, summary)
    store.upload(path)
    print(json.dumps({'finished_chunk': args.shard, 'collected': len(all_records), 'failed': len(failures)}), flush=True)
    if failures:
        raise RuntimeError('Partial collection saved; rerun to retry missing records')


def run_id():
    return os.environ.get('GITHUB_RUN_ID', datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')) + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1')


def aggregate(args, plan):
    control = Store(args.repo, args.tag)
    prior = control.json_asset('summary.json')
    stores, records, packages, missing_chunks = {}, [], [], []
    for shard in range(math.ceil(len(plan['records']) / 512)):
        tag = wave(args.tag, shard)
        if tag not in stores:
            stores[tag] = Store(args.repo, tag)
        store = stores[tag]
        summary = read_summary(store, shard, plan, args.sha256)
        if summary is None:
            missing_chunks.append(shard)
            recovered = store.recover(f'chunk-{shard:03d}', args.out, args.sha256)
            rows = [r for c in recovered for r in c['records']]
            verify_rows(rows, assigned(plan, shard))
            records.extend(rows)
            packages.extend(c['package'] for c in recovered)
        else:
            records.extend(summary['records'])
            packages.extend(summary['packages'])
    verify_rows(records, plan['records'])
    missing = sorted({r['id'] for r in plan['records']} - {r['id'] for r in records})
    complete = not missing and not missing_chunks
    result = {'schema': SCHEMA, 'plan_sha256': args.sha256, 'complete': complete,
              'queued_records': len(plan['records']), 'collected_records': len(records),
              'retained_elsewhere_ids': plan['retained_ids'], 'missing_ids': missing,
              'missing_chunks': missing_chunks, 'packages': packages,
              'stored_bytes': sum(p['bytes'] for p in packages), 'completed_utc': now()}
    if prior is not None:
        if (not complete or prior.get('schema') != SCHEMA or prior.get('complete') is not True
                or prior.get('plan_sha256') != args.sha256
                or any(prior.get(k) != result[k] for k in result if k != 'completed_utc')):
            raise ValueError('Completed inventory differs from verified checkpoints')
        print(json.dumps({'reused_inventory': True, 'collected_records': len(records)}), flush=True)
        return
    path = args.out / ('summary.json' if complete else 'incomplete-' + run_id() + '.json')
    save(path, result)
    control.upload(path)
    print(json.dumps({k:v for k,v in result.items() if k not in ('packages', 'missing_ids', 'retained_elsewhere_ids')}), flush=True)
    if not complete:
        raise RuntimeError('Collection incomplete; retry the unfinished chunks')


def retrieve(args):
    if not re.fullmatch(r'[0-9a-f]{64}', args.sha256):
        raise ValueError('Invalid manifest digest')
    store = Store(args.repo, args.tag)
    asset = store.assets.get('manifest.json')
    if not asset or asset.get('digest') != 'sha256:' + args.sha256 or asset['size'] > MAX_BYTES:
        raise ValueError('Remote manifest identity differs')
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    gh_download(args.repo, asset['id'], args.manifest)
    read_plan(args.manifest, args.sha256)
    print(json.dumps({'manifest_verified': True, 'bytes': asset['size']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('retrieve', 'prepare', 'fetch', 'aggregate'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--shard', type=int, default=0)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--parallel', type=int, default=0)
    parser.add_argument('--rpm', type=int, default=0)
    parser.add_argument('--lanes', type=int, default=1)
    args = parser.parse_args()
    identity(args.repo, args.tag)
    if args.mode == 'retrieve':
        retrieve(args)
        return
    plan = read_plan(args.manifest, args.sha256)
    args.out.mkdir(parents=True, exist_ok=True)
    globals()[args.mode](args, plan)


if __name__ == '__main__':
    main()
