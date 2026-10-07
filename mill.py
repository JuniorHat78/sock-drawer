"""Run a sealed offline toolbox against checked archive checkpoints."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sweep

MAGIC = b'SDRBOX1\n'
AAD = b'sock-drawer/offline-box/v1'
MAX_BOX = 1536 * 1024**2


def public_file(repo, tag, name, destination, optional=False, max_bytes=2 * 1024**3):
    sweep.identity(repo, tag)
    if Path(name).name != name: raise ValueError('Unsafe public asset name')
    url = f'https://github.com/{repo}/releases/download/{quote(tag, safe="")}/{quote(name, safe="")}'
    for attempt in range(6):
        try:
            # Public release downloads need no API token or authenticated API call.
            with urlopen(Request(url, headers={'User-Agent': 'sealed-boxes/1'}), timeout=180) as response:
                sweep.https_url(response.geturl())
                with destination.open('wb') as out:
                    written = 0
                    while block := response.read(1024 * 1024):
                        written += len(block)
                        if written > max_bytes: raise ValueError('Public asset exceeds size budget')
                        out.write(block)
            return True
        except HTTPError as error:
            if optional and error.code == 404: return False
            if error.code not in (429, 500, 502, 503, 504) or attempt == 5: raise
            delay = sweep.retry_seconds(error.headers.get('Retry-After'), attempt)
            time.sleep(max(2 ** (attempt + 1), delay))
        except (URLError, TimeoutError, OSError):
            if attempt == 5: raise
            time.sleep(min(60, 2 ** (attempt + 1)))


class PublicSource:
    def __init__(self, repo, tag, scratch, assets=None):
        sweep.identity(repo, tag)
        self.repo, self.tag, self.scratch = repo, tag, scratch
        self.assets = assets or {}

    def json_asset(self, name):
        import uuid
        self.scratch.mkdir(parents=True, exist_ok=True)
        path = self.scratch / (uuid.uuid4().hex + '.json')
        try:
            if not public_file(self.repo, self.tag, name, path, optional=True, max_bytes=sweep.MAX_BYTES): return None
            if path.stat().st_size > sweep.MAX_BYTES: raise ValueError('Public JSON exceeds budget')
            return json.loads(path.read_text(encoding='utf-8'))
        finally:
            if path.exists(): path.unlink()

    def check_package(self, saved):
        if (saved['tag'] != self.tag or type(saved['id']) is not int or saved['id'] <= 0
                or Path(saved['name']).name != saved['name'] or not re.fullmatch(r'[0-9a-f]{64}', saved['sha256'])
                or not 0 < saved['bytes'] < 2 * 1024**3):
            raise ValueError('Invalid public checkpoint identity')


class OutputStore(sweep.Store):
    def __init__(self, repo, tag, release_id):
        sweep.identity(repo, tag)
        if type(release_id) is not int or release_id <= 0: raise ValueError('Invalid output release ID')
        self.repo, self.tag = repo, tag
        self.release = {'id': release_id,
            'upload_url': f'https://uploads.github.com/repos/{repo}/releases/{release_id}/assets{{?name,label}}'}
        self.refresh()


def key_bytes():
    key = base64.b64decode(os.environ['BOX_KEY'], validate=True)
    if len(key) != 32:
        raise ValueError('Invalid box key length')
    return key


def seal(source, target, key):
    source, target = Path(source), Path(target)
    if source.stat().st_size >= MAX_BOX:
        raise ValueError('Box exceeds size budget')
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(AAD)
    with source.open('rb') as stream, target.open('wb') as out:
        out.write(MAGIC + nonce)
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            out.write(cipher.update(block))
        out.write(cipher.finalize()); out.write(cipher.tag)


def unseal(source, target, key):
    source, target = Path(source), Path(target)
    total = source.stat().st_size
    if not len(MAGIC) + 28 <= total < MAX_BOX + 36:
        raise ValueError('Invalid box size')
    temporary = target.with_name(target.name + '.partial')
    try:
        with source.open('rb') as stream:
            if stream.read(len(MAGIC)) != MAGIC:
                raise ValueError('Invalid box header')
            nonce = stream.read(12)
            stream.seek(-16, 2); tag = stream.read(16)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            cipher.authenticate_additional_data(AAD)
            stream.seek(len(MAGIC) + 12)
            remaining = total - len(MAGIC) - 28
            with temporary.open('wb') as out:
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError('Truncated box')
                    remaining -= len(block); out.write(cipher.update(block))
                out.write(cipher.finalize())
        temporary.replace(target)
    finally:
        if temporary.exists(): temporary.unlink()


def safe_extract(path, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        names = set()
        if sum(m.size for m in members) > 128 * 1024**2 or len(members) > 100:
            raise ValueError('Toolbox exceeds extraction budget')
        for member in members:
            relative = PurePosixPath(member.name)
            target = destination.joinpath(*relative.parts)
            if (not member.isfile() or relative.is_absolute() or '..' in relative.parts
                    or '\\' in member.name or ':' in member.name or member.name in names
                    or not target.resolve().is_relative_to(destination)):
                raise ValueError('Unsafe toolbox member')
            names.add(member.name)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as stream, target.open('wb') as out:
                shutil.copyfileobj(stream, out, 1024 * 1024)
    manifest = json.loads((destination / 'bundle.json').read_text())
    if set(manifest['files']) | {'bundle.json'} != names:
        raise ValueError('Toolbox inventory differs')
    for name, expected in manifest['files'].items():
        if sweep.sha(destination / name) != expected:
            raise ValueError('Toolbox digest differs')
    if manifest['entry'] not in manifest['files'] or manifest['requirements'] not in manifest['files']:
        raise ValueError('Missing toolbox entry/dependencies')
    return manifest


def child_environment():
    return {name: value for name, value in os.environ.items()
            if not (name == 'BOX_KEY' or 'TOKEN' in name.upper() or name.startswith(('GITHUB_', 'ACTIONS_')))}


def download(store, saved, folder):
    name = saved['name']
    if Path(name).name != name:
        raise ValueError('Invalid asset name')
    if not isinstance(store, PublicSource):
        asset = store.assets.get(name)
        if (not asset or asset['id'] != saved['id'] or asset['size'] != saved['bytes']
                or asset.get('digest') != 'sha256:' + saved['sha256']):
            raise ValueError('Asset differs from frozen receipt')
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    public_file(store.repo, store.tag, name, path, max_bytes=saved['bytes'])
    if path.stat().st_size != saved['bytes'] or sweep.sha(path) != saved['sha256']:
        raise ValueError('Downloaded asset digest differs')
    return path


def store_at(repo, tag):
    sweep.identity(repo, tag)
    probe = subprocess.run(['gh', 'api', f'repos/{repo}/releases/tags/{tag}'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if probe.returncode:
        if b'HTTP 404' not in probe.stderr:
            raise RuntimeError('Cannot inspect output release')
        sweep.gh(['release', 'create', tag, '--repo', repo, '--title', tag,
                  '--notes', 'Checked sealed offline outputs.', '--latest=false'])
    return sweep.Store(repo, tag)


def queue_config(args):
    control = PublicSource(args.repo, args.tag, args.out / 'metadata')
    config = control.json_asset('queue.json')
    if not config or config['schema'] != 'box-queue-1' or config['repo'] != args.repo:
        raise ValueError('Unsupported queue identity')
    for phase in ('pilot', 'full'):
        item = config[phase]
        sweep.identity(args.repo, item['source_tag']); sweep.identity(args.repo, item['output_tag'])
        if not re.fullmatch(r'[0-9a-f]{64}', item['plan_sha256']) or not 1 <= item['parallel'] <= 40:
            raise ValueError('Unsupported phase policy')
    return control, config


def emit(**values):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as out:
            for name, value in values.items():
                out.write(name + '=' + json.dumps(value, separators=(',', ':')) + '\n')


def source_identity(rows, saved=False):
    values = [{'id': r['id'], 'attributes': r['attributes'],
               'files': r['source_files'] if saved else r['files']} for r in sorted(rows, key=lambda r: r['id'])]
    return sweep.digest(json.dumps(values, sort_keys=True, separators=(',', ':')).encode())


def chunk_packages(store, task, plan_sha):
    if 'packages' in task:
        return task['packages']
    report = store.json_asset(f"chunk-{task['shard']:03d}-summary.json")
    if report is None: return None
    if (report.get('schema') != sweep.SCHEMA or report['plan_sha256'] != plan_sha
            or report['shard'] != task['shard'] or report['assigned_ids'] != task['expected_ids']
            or report.get('failures') or report['collected_ids'] != [r['id'] for r in report['records']]
            or source_identity(report['records'], saved=True) != task['expected_identity_sha256']):
        raise ValueError('Source chunk differs from frozen task identity')
    ids = []
    for package in report['packages']:
        store.check_package(package); ids.extend(package['ids'])
    if len(ids) != len(set(ids)) or set(ids) != set(task['expected_ids']):
        raise ValueError('Source package coverage differs')
    return report['packages']


def output_identity(config, item, package):
    return {'schema': 'box-output-1', 'bundle_sha256': config['bundle']['sha256'],
            'source_sha256': package['sha256'], 'plan_sha256': item['plan_sha256'], 'source_ids': package['ids']}


def prepare(args):
    control, config = queue_config(args)
    item = config[args.phase]
    if args.phase == 'full':
        ready = control.json_asset('ready.json')
        if not ready or ready.get('bundle_sha256') != config['bundle']['sha256']:
            emit(matrix={'shard': [0]}, count=0, parallel=1)
            print(json.dumps({'enabled': False})); return
    source = sweep.Store(args.repo, item['source_tag'])
    complete = source.json_asset('summary.json')
    if args.phase == 'pilot' and (not complete or complete['complete'] is not True or complete['plan_sha256'] != item['plan_sha256']):
        emit(matrix={'shard': [0]}, count=0, parallel=1)
        print(json.dumps({'source_ready': False})); return
    raw = source.assets['manifest.json']
    path = download(source, {'name': raw['name'], 'id': raw['id'], 'bytes': raw['size'],
                    'sha256': item['plan_sha256']}, args.out)
    plan = sweep.read_plan(path, item['plan_sha256'])
    stores, tasks = {}, []
    for shard in range(math.ceil(len(plan['records']) / 512)):
        tag = sweep.wave(item['source_tag'], shard)
        if tag not in stores:
            stores[tag] = (sweep.Store(args.repo, tag) if args.phase == 'pilot'
                           else PublicSource(args.repo, tag, args.out / 'metadata'))
        if args.phase == 'pilot':
            summary = sweep.read_summary(stores[tag], shard, plan, item['plan_sha256'])
            if summary is None: raise ValueError('Missing checked source chunk')
            tasks.append({'shard': shard, 'packages': summary['packages']})
        else:
            expected = sweep.assigned(plan, shard)
            tasks.append({'shard': shard, 'source_tag': tag, 'expected_ids': [r['id'] for r in expected],
                          'expected_identity_sha256': source_identity(expected)})
    count = len(plan['records'])
    if args.phase == 'pilot' and count != complete['collected_records']:
        raise ValueError('Queue coverage differs from complete source')
    output = store_at(args.repo, item['output_tag'])
    destinations = {}
    for wave in range(math.ceil(len(tasks) / 16)):
        tag = f"{item['output_tag']}-w{wave:02d}"
        destinations[tag] = store_at(args.repo, tag).release['id']
    frozen = {'schema': 'box-tasks-1' if args.phase == 'pilot' else 'box-tasks-2', 'bundle': config['bundle'], 'phase': args.phase,
              'plan_sha256': item['plan_sha256'], 'records': count, 'tasks': tasks}
    if args.phase == 'full': frozen['destinations'] = destinations
    prior = output.json_asset('tasks.json')
    if prior is not None and prior != frozen:
        raise ValueError('Existing tasks belong to another source/toolbox')
    sweep.save(args.out / 'tasks.json', frozen); output.upload(args.out / 'tasks.json')
    output_stores, queued = {}, []
    for task in tasks:
        packages = task.get('packages')
        if packages is None:
            packages = chunk_packages(stores[task['source_tag']], task, item['plan_sha256'])
        if packages is None: continue
        tag = f"{item['output_tag']}-w{task['shard'] // 16:02d}"
        if tag not in output_stores: output_stores[tag] = sweep.Store(args.repo, tag)
        finished = True
        for package in packages:
            prior = output_stores[tag].json_asset(package['name'][:-4] + '-receipt.json')
            if prior is None: finished = False
            else: receipt_ok(output_stores[tag], prior, output_identity(config, item, package))
        if not finished: queued.append(task['shard'])
    capacity = 37 if args.phase == 'full' and complete and complete.get('complete') else item['parallel']
    emit(matrix={'shard': queued or [0]}, count=len(queued), parallel=capacity)
    print(json.dumps({'queued_chunks': len(queued), 'planned_chunks': len(tasks), 'records': count,
                      'parallel': capacity, 'incremental': args.phase == 'full'}))


def receipt_ok(store, prior, expected):
    if any(prior.get(k) != v for k, v in expected.items()):
        raise ValueError('Prior output belongs to another task')
    for saved in prior['outputs']:
        asset = store.assets.get(saved['name'])
        if (not asset or asset['id'] != saved['id'] or asset['size'] != saved['bytes']
                or asset.get('digest') != 'sha256:' + saved['sha256']):
            raise ValueError('Prior output digest differs')
    if prior['failed']:
        raise ValueError('Prior task has preserved unresolved failures')


def sealed_upload(store, raw, sealed, key):
    existing = store.assets.get(sealed.name)
    if existing:
        sweep.gh_download(store.repo, existing['id'], sealed)
        if existing.get('digest') != 'sha256:' + sweep.sha(sealed):
            raise ValueError('Orphan box digest differs')
        restored = sealed.with_suffix('.restored')
        try:
            unseal(sealed, restored, key)
            if sweep.sha(restored) != sweep.sha(raw):
                raise ValueError('Orphan box has different plaintext')
        finally:
            if restored.exists(): restored.unlink()
    else:
        seal(raw, sealed, key)
    return store.upload(sealed)


def carriers(destination, files):
    """Group small compressed parts into bounded transport files without recoding."""
    groups, group, size = [], [], 0
    for saved in files:
        raw = destination / saved['name']
        if Path(saved['name']).name != saved['name'] or sweep.sha(raw) != saved['sha256'] or raw.stat().st_size != saved['bytes']:
            raise ValueError('Output part differs from private receipt')
        if group and size + saved['bytes'] > 1200 * 1024**2:
            groups.append(group); group, size = [], 0
        group.append(saved); size += saved['bytes']
    if group: groups.append(group)
    outputs = []
    for index, group in enumerate(groups):
        path = destination / f'carrier-{index:02d}.tar'
        with tarfile.open(path, 'w:') as archive:
            manifest = json.dumps({'schema': 'box-carrier-1', 'parts': group}, sort_keys=True).encode()
            import io
            header = tarfile.TarInfo('index.json'); header.size = len(manifest)
            archive.addfile(header, io.BytesIO(manifest))
            for saved in group:
                archive.add(destination / saved['name'], arcname=saved['name'], recursive=False)
        outputs.append({'name': path.name, 'bytes': path.stat().st_size, 'sha256': sweep.sha(path)})
    return outputs


def work(args):
    control, config = queue_config(args)
    item = config[args.phase]
    tasks = PublicSource(args.repo, item['output_tag'], args.out / 'metadata').json_asset('tasks.json')
    if (tasks['bundle'] != config['bundle'] or tasks['plan_sha256'] != item['plan_sha256']
            or tasks['phase'] != args.phase):
        raise ValueError('Task set differs from queue')
    assigned = [t for t in tasks['tasks'] if t['shard'] == args.shard]
    if len(assigned) != 1: raise ValueError('Unassigned chunk')
    assigned = assigned[0]
    packages = assigned.get('packages')
    if packages is None:
        packages = chunk_packages(PublicSource(args.repo, assigned['source_tag'], args.out / 'metadata'), assigned, item['plan_sha256'])
    if packages is None: raise ValueError('Assigned source chunk is not ready')
    key = key_bytes()
    parcel = download(control, config['bundle'], args.out / 'parcel')
    unpacked = args.out / 'toolbox.tar.gz'
    unseal(parcel, unpacked, key)
    runtime = args.out / 'toolbox'
    bundle = safe_extract(unpacked, runtime); unpacked.unlink()
    logs = args.out / 'logs'; logs.mkdir()
    with (logs / 'setup.log').open('wb') as out:
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
            '-r', str(runtime / bundle['requirements'])], stdout=out, stderr=subprocess.STDOUT,
            env=child_environment(), timeout=600)
    if result.returncode: raise RuntimeError('Toolbox dependency setup failed')
    tag = f"{item['output_tag']}-w{args.shard // 16:02d}"
    output = (OutputStore(args.repo, tag, tasks['destinations'][tag]) if 'destinations' in tasks
              else sweep.Store(args.repo, tag))
    total = {'records': 0, 'accepted': 0, 'quarantined': 0, 'failed': 0, 'rows': 0, 'entries': 0}
    for package in packages:
        prefix = package['name'][:-4]
        expected = output_identity(config, item, package)
        prior = PublicSource(args.repo, tag, args.out / 'metadata').json_asset(prefix + '-receipt.json')
        if prior is not None:
            receipt_ok(output, prior, expected)
            for k in total: total[k] += prior[k]
            continue
        source = PublicSource(args.repo, package['tag'], args.out / 'metadata')
        path = download(source, package, args.out / 'input')
        ids = args.out / 'ids.json'; sweep.save(ids, package['ids'])
        destination = args.out / prefix
        with (logs / 'run.log').open('wb') as stdout, (logs / 'error.log').open('wb') as stderr:
            result = subprocess.run([sys.executable, '-B', str(runtime / bundle['entry']),
                '--source', str(path.resolve()), '--source-sha', package['sha256'],
                '--plan-sha', item['plan_sha256'], '--ids', str(ids.resolve()),
                '--output', str(destination.resolve()), '--cpus', str(min(4, os.cpu_count() or 1))],
                stdout=stdout, stderr=stderr, env=child_environment(), timeout=18000)
        if result.returncode:
            diagnostic = args.out / (prefix + '-diagnostic.tar.gz')
            with tarfile.open(diagnostic, 'w:gz') as tar:
                for file in logs.iterdir(): tar.add(file, arcname=file.name, recursive=False)
            sealed = diagnostic.with_suffix('.box'); seal(diagnostic, sealed, key)
            output.upload(sealed)
            raise RuntimeError('Offline toolbox failed; sealed diagnostics saved')
        report = json.loads((destination / 'result.json').read_text())
        if (report['records'] != len(package['ids']) or
                report['accepted'] + report['quarantined'] + report['failed'] != report['records']):
            raise ValueError('Toolbox did not account for assigned records')
        saved_parts = []
        transport = carriers(destination, report['files']) if args.phase == 'full' else report['files']
        for index, file in enumerate(transport):
            if Path(file['name']).name != file['name']:
                raise ValueError('Unsafe toolbox output name')
            raw = destination / file['name']
            if sweep.sha(raw) != file['sha256'] or raw.stat().st_size != file['bytes']:
                raise ValueError('Toolbox output differs from its receipt')
            sealed = args.out / f'{prefix}-box-{index:02d}.box'
            saved = sealed_upload(output, raw, sealed, key); saved['plain_sha256'] = file['sha256']
            saved_parts.append(saved); raw.unlink(); sealed.unlink()
        receipt = {**expected, 'outputs': saved_parts,
                   **{k: report[k] for k in ('records', 'accepted', 'quarantined', 'failed')},
                   'rows': report['positions'], 'entries': report['candidates'],
                   'seconds': report['seconds'], 'cpus': report['cpus'],
                   **({'transport': 'box-carrier-1'} if args.phase == 'full' else {})}
        sweep.save(args.out / (prefix + '-receipt.json'), receipt)
        output.upload(args.out / (prefix + '-receipt.json'))
        path.unlink()
        for k in total: total[k] += receipt[k]
        print(json.dumps({'finished_box': prefix, **{k:receipt[k] for k in total},
                          'seconds': receipt['seconds'], 'cpus': receipt['cpus']}), flush=True)
        if receipt['failed']: raise RuntimeError('Unresolved records preserved in sealed outputs')
    print(json.dumps({'finished_chunk': args.shard, **total}), flush=True)


def summary(args):
    control, config = queue_config(args)
    item = config[args.phase]
    root = sweep.Store(args.repo, item['output_tag'])
    tasks = PublicSource(args.repo, item['output_tag'], args.out / 'metadata').json_asset('tasks.json')
    if tasks['bundle'] != config['bundle'] or tasks['plan_sha256'] != item['plan_sha256']:
        raise ValueError('Summary task identity differs')
    stores, source_stores, missing, receipts, ids = {}, {}, [], [], []
    counts = {k: 0 for k in ('records', 'accepted', 'quarantined', 'failed', 'rows', 'entries')}
    for task in tasks['tasks']:
        tag = f"{item['output_tag']}-w{task['shard'] // 16:02d}"
        if tag not in stores: stores[tag] = sweep.Store(args.repo, tag)
        store = stores[tag]
        packages = task.get('packages')
        if packages is None:
            source_tag = task['source_tag']
            if source_tag not in source_stores:
                source_stores[source_tag] = PublicSource(args.repo, source_tag, args.out / 'metadata')
            packages = chunk_packages(source_stores[source_tag], task, item['plan_sha256'])
        if packages is None:
            missing.append(f"chunk-{task['shard']:03d}-source"); continue
        for package in packages:
            name = package['name'][:-4] + '-receipt.json'
            report = PublicSource(args.repo, tag, args.out / 'metadata').json_asset(name)
            if report is None:
                missing.append(name); continue
            expected = output_identity(config, item, package)
            # Preserve failures in the aggregate; no successful-ready claim.
            receipt_ok(store, {**report, 'failed': 0}, expected)
            if report['records'] != len(package['ids']):
                raise ValueError('Output record count differs')
            ids.extend(report['source_ids']); receipts.append(report)
            for k in counts: counts[k] += report[k]
    if len(ids) != len(set(ids)):
        raise ValueError('Output coverage has duplicate records')
    complete = not missing and not counts['failed'] and counts['records'] == tasks['records']
    result = {'schema': 'box-summary-1', 'phase': args.phase, 'bundle_sha256': config['bundle']['sha256'],
              'plan_sha256': item['plan_sha256'], 'complete': complete, **counts,
              'missing': missing, 'receipts': receipts}
    prior = root.json_asset('summary.json')
    if prior is not None and prior != result:
        raise ValueError('Existing summary differs from checked outputs')
    path = args.out / ('summary.json' if complete else 'incomplete-' + sweep.run_id() + '.json')
    sweep.save(path, result); root.upload(path)
    print(json.dumps({k: v for k, v in result.items() if k not in ('receipts', 'missing')}))
    if not complete:
        source_complete = PublicSource(args.repo, item['source_tag'], args.out / 'metadata').json_asset('summary.json')
        if counts['failed'] or args.phase == 'pilot' or (source_complete and source_complete.get('complete')):
            raise RuntimeError('Offline output coverage is incomplete')


def probe_inputs(bundle, args, key):
    attachments = bundle.get('inputs', [])
    if not isinstance(attachments, list) or len(attachments) > 512:
        raise ValueError('Unsupported input count')
    if sum(item['bytes'] for item in attachments) > 16 * 1024**3:
        raise ValueError('Inputs exceed the total size budget')
    input_dir = args.out / 'inputs'
    for index, item in enumerate(attachments):
        if (not re.fullmatch(r'[0-9a-f]{64}', item['plain_sha256'])
                or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])
                or not 0 < item['bytes'] < MAX_BOX + 36):
            raise ValueError('Invalid sealed input identity')
        source = PublicSource(args.repo, item['tag'], args.out / 'metadata')
        packed = download(source, item, args.out / 'attachments')
        input_dir.mkdir(exist_ok=True)
        decoded = input_dir / f'input-{index:03d}.tar'
        unseal(packed, decoded, key)
        if sweep.sha(decoded) != item['plain_sha256']:
            decoded.unlink()
            raise ValueError('Input plaintext differs from its receipt')
        packed.unlink()
    return input_dir if attachments else None


def probe_resume(bundle, args, key):
    item = bundle.get('resume')
    if item is None: return None
    source = PublicSource(args.repo, item['tag'], args.out / 'metadata')
    report = source.json_asset('probe-receipt.json')
    if report is None:
        inventory = sweep.Store(args.repo, item['tag'])
        candidates = sorted((a for a in inventory.assets.values() if re.fullmatch(r'snapshot-[0-9-]+\.json', a['name'])),
                            key=lambda a: a['created_at'])
        report = source.json_asset(candidates[-1]['name']) if candidates else None
    if not report or report.get('bundle_sha256') != item['bundle_sha256'] or len(report['outputs']) != 1:
        raise ValueError('Resume has no matching checked checkpoint')
    saved = report['outputs'][0]
    packed = download(source, saved, args.out / 'resume')
    decoded = args.out / 'resume.tar.gz'; unseal(packed, decoded, key)
    if sweep.sha(decoded) != saved['plain_sha256']:
        decoded.unlink(); raise ValueError('Resume plaintext differs')
    packed.unlink()
    return decoded


def probe_archive(result_dir, archive_path):
    with tarfile.open(archive_path, 'w:gz', compresslevel=1) as archive:
        for path in sorted(result_dir.rglob('*')):
            if path.is_file() and not path.name.endswith(('.partial', '.part')):
                if path.is_symlink() or not path.resolve().is_relative_to(result_dir.resolve()):
                    raise ValueError('Unsafe probe output')
                with path.open('rb') as source:
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(result_dir).as_posix(), fileobj=source)
                    archive.addfile(info, source)


def probe_process(command, runtime, result_dir, store, key, limit, bundle_sha):
    began = time.monotonic(); last_snapshot = began; index = 0
    with (result_dir / 'experiment.log').open('wb') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=child_environment())
        try:
            while process.poll() is None:
                elapsed = time.monotonic() - began
                if elapsed > limit:
                    raise subprocess.TimeoutExpired(command, limit)
                if time.monotonic() - last_snapshot >= 900:
                    prefix = f'snapshot-{sweep.run_id()}-{index:03d}'
                    archive = result_dir.parent / (prefix + '.tar.gz')
                    probe_archive(result_dir, archive)
                    box = result_dir.parent / (prefix + '.box')
                    saved = sealed_upload(store, archive, box, key)
                    saved.update(plain_sha256=sweep.sha(archive), tag=store.tag)
                    report = {'schema': 'box-snapshot-1', 'bundle_sha256': bundle_sha,
                              'seconds': elapsed, 'outputs': [saved]}
                    receipt = result_dir.parent / (prefix + '.json'); sweep.save(receipt, report); store.upload(receipt)
                    archive.unlink(); box.unlink(); receipt.unlink()
                    index += 1; last_snapshot = time.monotonic()
                    print(json.dumps({'sealed_snapshot': index, 'elapsed_seconds': round(elapsed)}), flush=True)
                time.sleep(2)
            return process.returncode == 0
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=20)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=20)


def probe(args):
    """One bounded CPU experiment; its program and diagnostics stay sealed."""
    control = PublicSource(args.repo, args.tag, args.out / 'metadata')
    config = control.json_asset('probe.json')
    if not config or config.get('schema') != 'box-probe-1' or config.get('repo') != args.repo:
        raise ValueError('Unsupported probe identity')
    store = store_at(args.repo, args.tag)
    prior = store.json_asset('probe-receipt.json')
    if prior is not None:
        if prior.get('bundle_sha256') != config['bundle']['sha256']:
            raise ValueError('Prior probe belongs to another toolbox')
        for saved in prior['outputs']:
            asset = store.assets.get(saved['name'])
            if not asset or asset['size'] != saved['bytes'] or asset.get('digest') != 'sha256:' + saved['sha256']:
                raise ValueError('Prior probe output differs')
        if prior['success'] is not True:
            raise RuntimeError('Prior probe has preserved unresolved failures')
        print(json.dumps({'probe_complete': True, 'reused': True})); return
    started = time.perf_counter()
    key = key_bytes()
    parcel = download(control, config['bundle'], args.out / 'parcel')
    plain = args.out / 'toolbox.tar.gz'; unseal(parcel, plain, key)
    runtime = args.out / 'toolbox'; bundle = safe_extract(plain, runtime); plain.unlink()
    result_dir = args.out / 'private'; result_dir.mkdir()
    success = False
    try:
        input_dir = probe_inputs(bundle, args, key)
        resume = probe_resume(bundle, args, key)
        limit = bundle.get('seconds', 1800)
        if type(limit) is not int or not 30 <= limit <= 19800:
            raise ValueError('Unsupported experiment time budget')
        with (result_dir / 'setup.log').open('wb') as log:
            setup = subprocess.run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
                '-r', str(runtime / bundle['requirements'])], stdout=log, stderr=subprocess.STDOUT,
                env=child_environment(), timeout=600)
        if setup.returncode == 0:
            command = [sys.executable, str(runtime / bundle['entry']), '--output', str(result_dir.resolve())]
            if input_dir is not None:
                command.extend(['--inputs', str(input_dir.resolve())])
            if resume is not None:
                command.extend(['--resume', str(resume.resolve())])
            success = probe_process(command, runtime, result_dir, store, key, limit, config['bundle']['sha256'])
    except (subprocess.TimeoutExpired, OSError, ValueError, RuntimeError) as error:
        (result_dir / 'failure.log').write_text(type(error).__name__ + ': ' + str(error), encoding='utf-8')
    archive_path = args.out / 'probe-result.tar.gz'
    probe_archive(result_dir, archive_path)
    sealed = args.out / 'probe-result.box'
    saved = sealed_upload(store, archive_path, sealed, key)
    saved.update(plain_sha256=sweep.sha(archive_path), tag=args.tag)
    receipt = {'schema': 'box-probe-output-1', 'bundle_sha256': config['bundle']['sha256'],
               'success': success, 'outputs': [saved], 'cpus': min(4, os.cpu_count() or 1),
               'seconds': time.perf_counter() - started}
    sweep.save(args.out / 'probe-receipt.json', receipt); store.upload(args.out / 'probe-receipt.json')
    print(json.dumps({'probe_complete': success, 'seconds': receipt['seconds']}), flush=True)
    if not success: raise RuntimeError('Probe has sealed diagnostic failures')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'work', 'summary', 'probe'))
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--phase', choices=('pilot', 'full'), default='pilot')
    parser.add_argument('--shard', type=int, default=0)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); args.out.mkdir(parents=True, exist_ok=True)
    try:
        globals()[args.mode](args)
    except Exception as error:
        # Private toolbox paths, input content and diagnostic text stay sealed.
        print(json.dumps({'operation_failed': True, 'type': type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
