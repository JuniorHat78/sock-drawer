"""Bounded supervision of one frozen collection and its checked CPU queue."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sweep
import mill


def decision(state, active, raw_done, chunks, ready, cpu_done, failed, previous_failed):
    if raw_done and cpu_done: return 'complete'
    if not raw_done and not active['Sweep']:
        if state.get('source_retries', 0) >= 3: return 'source_needs_attention'
        return 'source'
    if not ready or cpu_done or active['Mill'] or active['Probe']: return 'wait'
    if failed: return 'cpu_needs_attention'
    if chunks > state.get('cpu_last_chunks', 0): return 'cpu'
    if previous_failed:
        if state.get('cpu_retries', 0) >= 3: return 'cpu_needs_attention'
        return 'cpu_retry'
    return 'wait'


def workflow_runs(repo, name):
    values = json.loads(sweep.gh(['api', f'repos/{repo}/actions/workflows/{name.lower()}.yml/runs?per_page=30']))['workflow_runs']
    values = [r for r in values if r.get('head_branch') == 'main']
    active = [r['id'] for r in values if r['status'] != 'completed']
    last = next((r for r in values if r['status'] == 'completed'), None)
    return active, last


def replace_state(repo, tag, path, state):
    sweep.save(path, state)
    sweep.gh(['release', 'upload', tag, str(path), '--repo', repo, '--clobber'])


def dispatch(repo, name, path, inputs):
    sweep.save(path, {'ref': 'main', 'inputs': inputs})
    sweep.gh(['api', '--method', 'POST', f'repos/{repo}/actions/workflows/{name.lower()}.yml/dispatches', '--input', str(path)])


def run(args):
    sweep.identity(args.repo, args.tag)
    source = sweep.Store(args.repo, args.tag)
    config = source.json_asset('care.json')
    if not config or config['schema'] != 'box-care-1' or config['repo'] != args.repo or config['source_tag'] != args.tag:
        raise ValueError('Unsupported supervision identity')
    if not re.fullmatch(r'[0-9a-f]{64}', config['plan_sha256']): raise ValueError('Invalid frozen plan')
    state = source.json_asset('care-state.json') or {'schema': 'box-care-state-1', 'plan_sha256': config['plan_sha256'],
        'cpu_tag': config['cpu_tag'], 'source_retries': 0, 'cpu_retries': 0, 'cpu_last_chunks': 0}
    if state['plan_sha256'] != config['plan_sha256'] or state['cpu_tag'] != config['cpu_tag']:
        raise ValueError('Supervision state belongs to another campaign')
    if state.get('finished'):
        print(json.dumps({'finished': True, 'reason': state['action']})); return
    active, previous = {}, {}
    for name in ('Sweep', 'Mill', 'Probe'): active[name], previous[name] = workflow_runs(args.repo, name)
    public = mill.PublicSource(args.repo, args.tag, args.out / 'metadata')
    raw = public.json_asset('summary.json')
    if raw and raw['plan_sha256'] != config['plan_sha256']: raise ValueError('Source summary has another plan')
    raw_done = bool(raw and raw.get('complete'))
    chunks = 0
    for index in range(config['source_waves']):
        wave = sweep.Store(args.repo, f"{args.tag}-w{index:02d}")
        chunks += sum(bool(re.fullmatch(r'chunk-\d{3}-summary\.json', name)) for name in wave.assets)
    control = mill.PublicSource(args.repo, config['cpu_tag'], args.out / 'metadata')
    queue = control.json_asset('queue.json'); proof = control.json_asset('ready.json')
    ready = bool(queue and proof and proof.get('bundle_sha256') == queue['bundle']['sha256'])
    cpu, failed = None, 0
    if ready:
        item = queue['full']
        if item['source_tag'] != args.tag or item['plan_sha256'] != config['plan_sha256']:
            raise ValueError('CPU queue has another source identity')
        output = sweep.Store(args.repo, item['output_tag'])
        reader = mill.PublicSource(args.repo, item['output_tag'], args.out / 'metadata')
        cpu = reader.json_asset('summary.json')
        incomplete = sorted((a for a in output.assets.values() if re.fullmatch(r'incomplete-[0-9-]+\.json', a['name'])),
                            key=lambda a: a['created_at'], reverse=True)
        snapshot = cpu or (reader.json_asset(incomplete[0]['name']) if incomplete else None)
        if snapshot:
            if snapshot['bundle_sha256'] != queue['bundle']['sha256'] or snapshot['plan_sha256'] != config['plan_sha256']:
                raise ValueError('CPU summary has another recipe')
            failed = snapshot['failed']
            state['cpu_records'] = snapshot['records']
    cpu_done = bool(cpu and cpu.get('complete'))
    previous_failed = bool(previous['Mill'] and previous['Mill']['conclusion'] == 'failure')
    action = decision(state, active, raw_done, chunks, ready, cpu_done, failed, previous_failed)
    state.update(checked_utc=sweep.now(), action=action, active=active, raw_complete=raw_done,
                 completed_source_chunks=chunks, cpu_ready=ready, cpu_complete=cpu_done, cpu_failed=failed)
    inputs = None
    if action == 'source':
        state['source_retries'] += 1
        inputs = {'tag': args.tag, 'sha256': config['plan_sha256'], 'allow_fetch': True,
                  'parallel': '24', 'rpm': '1200', 'lanes': '4'}
    elif action in ('cpu', 'cpu_retry'):
        if action == 'cpu': state['cpu_retries'] = 0
        else: state['cpu_retries'] += 1
        state['cpu_last_chunks'] = chunks
        inputs = {'tag': config['cpu_tag'], 'phase': 'full'}
    elif action in ('complete', 'source_needs_attention', 'cpu_needs_attention'):
        state['finished'] = True
    replace_state(args.repo, args.tag, args.out / 'care-state.json', state)
    if inputs:
        dispatch(args.repo, 'Sweep' if action == 'source' else 'Mill', args.out / 'dispatch.json', inputs)
    if state.get('finished'):
        sweep.gh(['api', '--method', 'PUT', f'repos/{args.repo}/actions/workflows/care.yml/disable'])
    print(json.dumps(state), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True); parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); args.out.mkdir(parents=True, exist_ok=True); run(args)
