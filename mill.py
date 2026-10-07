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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sweep

MAGIC = b'SDRBOX1\n'
AAD = b'sock-drawer/offline-box/v1'
MAX_BOX = 1536 * 1024**2


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
    asset = store.assets.get(name)
    if (not asset or asset['id'] != saved['id'] or asset['size'] != saved['bytes']
            or asset.get('digest') != 'sha256:' + saved['sha256']):
        raise ValueError('Asset differs from frozen receipt')
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    sweep.gh_download(store.repo, asset['id'], path)
    if sweep.sha(path) != saved['sha256']:
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
    control = sweep.Store(args.repo, args.tag)
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
    if not complete or complete['complete'] is not True or complete['plan_sha256'] != item['plan_sha256']:
        emit(matrix={'shard': [0]}, count=0, parallel=1)
        print(json.dumps({'source_ready': False})); return
    raw = source.assets['manifest.json']
    path = download(source, {'name': raw['name'], 'id': raw['id'], 'bytes': raw['size'],
                    'sha256': item['plan_sha256']}, args.out)
    plan = sweep.read_plan(path, item['plan_sha256'])
    stores, tasks = {}, []
    for shard in range(math.ceil(len(plan['records']) / 512)):
        tag = sweep.wave(item['source_tag'], shard)
        if tag not in stores: stores[tag] = sweep.Store(args.repo, tag)
        summary = sweep.read_summary(stores[tag], shard, plan, item['plan_sha256'])
        if summary is None: raise ValueError('Missing checked source chunk')
        tasks.append({'shard': shard, 'packages': summary['packages']})
    count = sum(len(p['ids']) for t in tasks for p in t['packages'])
    if count != len(plan['records']) or count != complete['collected_records']:
        raise ValueError('Queue coverage differs from complete source')
    output = store_at(args.repo, item['output_tag'])
    frozen = {'schema': 'box-tasks-1', 'bundle': config['bundle'], 'phase': args.phase,
              'plan_sha256': item['plan_sha256'], 'records': count, 'tasks': tasks}
    prior = output.json_asset('tasks.json')
    if prior is not None and prior != frozen:
        raise ValueError('Existing tasks belong to another source/toolbox')
    sweep.save(args.out / 'tasks.json', frozen); output.upload(args.out / 'tasks.json')
    for wave in range(math.ceil(len(tasks) / 16)):
        store_at(args.repo, f"{item['output_tag']}-w{wave:02d}")
    emit(matrix={'shard': [t['shard'] for t in tasks]}, count=len(tasks), parallel=item['parallel'])
    print(json.dumps({'queued_chunks': len(tasks), 'records': count, 'parallel': item['parallel']}))


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


def work(args):
    control, config = queue_config(args)
    item = config[args.phase]
    tasks = sweep.Store(args.repo, item['output_tag']).json_asset('tasks.json')
    if (tasks['bundle'] != config['bundle'] or tasks['plan_sha256'] != item['plan_sha256']
            or tasks['phase'] != args.phase):
        raise ValueError('Task set differs from queue')
    assigned = [t for t in tasks['tasks'] if t['shard'] == args.shard]
    if len(assigned) != 1: raise ValueError('Unassigned chunk')
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
    output = sweep.Store(args.repo, f"{item['output_tag']}-w{args.shard // 16:02d}")
    total = {'records': 0, 'accepted': 0, 'quarantined': 0, 'failed': 0, 'rows': 0, 'entries': 0}
    for package in assigned[0]['packages']:
        prefix = package['name'][:-4]
        expected = {'schema': 'box-output-1', 'bundle_sha256': config['bundle']['sha256'],
                    'source_sha256': package['sha256'], 'plan_sha256': item['plan_sha256'],
                    'source_ids': package['ids']}
        prior = output.json_asset(prefix + '-receipt.json')
        if prior is not None:
            receipt_ok(output, prior, expected)
            for k in total: total[k] += prior[k]
            continue
        source = sweep.Store(args.repo, package['tag'])
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
        for index, file in enumerate(report['files']):
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
                   'seconds': report['seconds'], 'cpus': report['cpus']}
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
    tasks = root.json_asset('tasks.json')
    if tasks['bundle'] != config['bundle'] or tasks['plan_sha256'] != item['plan_sha256']:
        raise ValueError('Summary task identity differs')
    stores, missing, receipts, ids = {}, [], [], []
    counts = {k: 0 for k in ('records', 'accepted', 'quarantined', 'failed', 'rows', 'entries')}
    for task in tasks['tasks']:
        tag = f"{item['output_tag']}-w{task['shard'] // 16:02d}"
        if tag not in stores: stores[tag] = sweep.Store(args.repo, tag)
        store = stores[tag]
        for package in task['packages']:
            name = package['name'][:-4] + '-receipt.json'
            report = store.json_asset(name)
            if report is None:
                missing.append(name); continue
            expected = {'schema': 'box-output-1', 'bundle_sha256': config['bundle']['sha256'],
                        'source_sha256': package['sha256'], 'plan_sha256': item['plan_sha256'],
                        'source_ids': package['ids']}
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
    if not complete: raise RuntimeError('Offline output coverage is incomplete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'work', 'summary'))
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--phase', choices=('pilot', 'full'), required=True)
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
