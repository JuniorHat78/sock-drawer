"""Measure lossless storage choices on an existing public archive sample."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import gzip
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import tarfile
import time

import sweep


def measure(task):
    archive_path, row = task
    with tarfile.open(archive_path, 'r:') as archive:
        found = json.load(archive.extractfile(f"record-{row['id']}/meta.json"))
        if found != row: raise ValueError('Metadata differs from manifest')
        result = []
        for file in row['files']:
            member = archive.getmember(f"record-{row['id']}/{file['name']}")
            if not member.isfile() or member.size != file['gzip_bytes'] or member.size > sweep.MAX_BYTES:
                raise ValueError('Unexpected compressed member')
            packed = archive.extractfile(member).read()
            if sweep.digest(packed) != file['gzip_sha256']: raise ValueError('Compressed member digest differs')
            with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
                raw = stream.read(sweep.MAX_BYTES + 1)
            if len(raw) != file['bytes'] or sweep.digest(raw) != file['sha256']:
                raise ValueError('Original member digest differs')
            record = {'name': file['name'], 'original_bytes': len(raw), 'stored_bytes': len(packed),
                      'original_sha256': file['sha256'], 'codecs': {}}
            for name, compress, decompress in (
                ('gzip9', lambda b: gzip.compress(b, compresslevel=9, mtime=0), gzip.decompress),
                ('xz6', lambda b: lzma.compress(b, preset=6), lzma.decompress),
                ('xz9', lambda b: lzma.compress(b, preset=9), lzma.decompress)):
                start = time.perf_counter(); encoded = compress(raw); seconds = time.perf_counter() - start
                start = time.perf_counter(); decoded = decompress(encoded); decode_seconds = time.perf_counter() - start
                if sweep.digest(decoded) != file['sha256']: raise ValueError('Codec roundtrip differs')
                record['codecs'][name] = {'bytes': len(encoded), 'encode_seconds': seconds,
                                        'decode_seconds': decode_seconds, 'sha256': sweep.digest(encoded)}
                del encoded, decoded
            result.append(record)
    return {'id': row['id'], 'files': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--source-tag', required=True)
    parser.add_argument('--asset', required=True)
    parser.add_argument('--output-tag', required=True)
    parser.add_argument('--limit', type=int, default=32)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.limit <= 32: raise ValueError('Only the small storage probe is enabled')
    args.out.mkdir(parents=True, exist_ok=True)
    source = sweep.Store(args.repo, args.source_tag)
    receipt = source.json_asset(args.asset[:-4] + '-receipt.json')
    if not receipt or receipt['package']['name'] != args.asset: raise ValueError('Missing source receipt')
    source.check_package(receipt['package'])
    saved = receipt['package']
    sweep.identity(args.repo, args.output_tag)
    probe = subprocess.run(['gh', 'api', f'repos/{args.repo}/releases/tags/{args.output_tag}'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if probe.returncode == 0:
        prior = sweep.Store(args.repo, args.output_tag).json_asset('compression.json')
        if prior is not None:
            if (prior['source_sha256'] != saved['sha256'] or prior['roundtrips_checked'] is not True
                    or prior['sample_limit'] != args.limit):
                raise ValueError('Existing storage probe has different inputs')
            print(json.dumps({'reused_storage_probe': True, 'sample_records': prior['sample_records']})); return
    elif b'HTTP 404' not in probe.stderr:
        raise RuntimeError('Cannot check output release')
    path = args.out / args.asset
    sweep.gh_download(args.repo, saved['id'], path)
    if sweep.sha(path) != saved['sha256']: raise ValueError('Archive readback digest differs')
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        if len({m.name for m in members}) != len(members) or any(not m.isfile() for m in members):
            raise ValueError('Duplicate/non-file archive members')
        manifest = json.load(archive.extractfile('manifest.json'))
        if manifest['plan_sha256'] != receipt['plan_sha256'] or manifest['records'] != receipt['records']:
            raise ValueError('Archive manifest differs from checked receipt')
    # Include large records and a uniform sample, without a size-biased total claim.
    rows = manifest['records']; selected = {}
    large = sorted(rows, key=lambda r: sum(f['bytes'] for f in r['files']), reverse=True)
    for row in large[:args.limit // 2]: selected[row['id']] = row
    for index in range(min(len(rows), args.limit)):
        row = rows[index * max(1, len(rows) - 1) // max(1, min(len(rows), args.limit) - 1)]
        if len(selected) < args.limit: selected[row['id']] = row
    cpus = min(4, os.cpu_count() or 1)
    begin = time.perf_counter()
    with ThreadPoolExecutor(max_workers=cpus) as pool:
        results = list(pool.map(measure, [(path, row) for row in selected.values()]))
    totals = {'original_bytes': 0, 'stored_bytes': 0, 'codecs': {n: {'bytes': 0, 'encode_seconds': 0,
                   'decode_seconds': 0} for n in ('gzip9', 'xz6', 'xz9')}}
    for record in results:
        for file in record['files']:
            totals['original_bytes'] += file['original_bytes']; totals['stored_bytes'] += file['stored_bytes']
            for name, value in file['codecs'].items():
                for key in totals['codecs'][name]: totals['codecs'][name][key] += value[key]
    report = {'schema': 'storage-probe-1', 'source_sha256': saved['sha256'],
              'source_plan_sha256': receipt['plan_sha256'], 'sample_records': len(results), 'sample_limit': args.limit,
              'cpus': cpus, 'wall_seconds': time.perf_counter() - begin, 'roundtrips_checked': True,
              'selection': 'large records plus uniform positions; not a corpus-wide savings estimate',
              'totals': totals, 'records': results}
    output = args.out / 'compression.json'; sweep.save(output, report)
    if probe.returncode:
        sweep.gh(['release', 'create', args.output_tag, '--repo', args.repo, '--title', args.output_tag,
                  '--notes', 'Checked small storage probe.', '--latest=false'])
    sweep.Store(args.repo, args.output_tag).upload(output)
    print(json.dumps({k:v for k,v in report.items() if k != 'records'}), flush=True)


if __name__ == '__main__':
    main()
