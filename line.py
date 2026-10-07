"""Run a bounded list of checked sealed steps, one at a time."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import time

import mill
import sweep


def next_step(steps, receipts, active):
    if active: return 'wait', None
    for index, step in enumerate(steps):
        report = receipts.get(step['tag'])
        if report is None: return 'dispatch', index
        if report.get('bundle_sha256') != step['sha256']: return 'identity_needs_attention', index
        if report.get('success') is not True:
            if step.get('optional') is True: continue
            if (report.get('failure_type') == 'timeout' and report.get('resume_available') is True
                    and index + 1 < len(steps) and steps[index + 1].get('resume_of') == step['tag']):
                continue
            return 'step_needs_attention', index
    return 'complete', None


def retry_dispatch(state, index, step, runs, now):
    """Retry only an intent that provably created no matching workflow run."""
    saved = state.get('requests', {}).get(str(index))
    if not saved or saved['attempts'] >= 3: return False
    requested = dt.datetime.fromisoformat(saved['requested_utc'])
    if (now - requested).total_seconds() < 120: return False
    for run in runs:
        if run['display_title'] == 'Probe ' + step['tag'] and run['head_branch'] == 'main':
            created = dt.datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
            if created >= requested - dt.timedelta(seconds=5): return False
    return True


def run(args):
    source = sweep.Store(args.repo, args.tag)
    config = source.json_asset('line.json')
    if config is None:
        print(json.dumps({'line_ready': False})); return {'finished': True, 'action': 'not_ready'}
    if config.get('schema') != 'box-line-1' or config.get('repo') != args.repo:
        raise ValueError('Unsupported sealed line')
    steps = config['steps']
    if not 1 <= len(steps) <= 20 or len({s['tag'] for s in steps}) != len(steps):
        raise ValueError('Unsupported step count')
    for step in steps:
        sweep.identity(args.repo, step['tag'])
        if len(step['sha256']) != 64 or set(step['sha256']) - set('0123456789abcdef'):
            raise ValueError('Invalid step identity')
        if 'optional' in step and type(step['optional']) is not bool: raise ValueError('Invalid optional step')
        if step.get('resume_of') not in (None, *[s['tag'] for s in steps]): raise ValueError('Unknown resume source')
    identity = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    state = source.json_asset('line-state.json') or {'schema': 'box-line-state-1', 'identity': identity, 'dispatched': []}
    if state['identity'] != identity: raise ValueError('Line configuration changed')
    if state.get('finished'):
        print(json.dumps({'finished': True, 'action': state['action']})); return state
    runs = json.loads(sweep.gh(['api', f'repos/{args.repo}/actions/workflows/probe.yml/runs?per_page=30']))['workflow_runs']
    active = [r['id'] for r in runs if r['head_branch'] == 'main' and r['status'] != 'completed']
    receipts = {}
    for step in steps:
        reader = mill.PublicSource(args.repo, step['tag'], args.out / 'metadata')
        control = reader.json_asset('probe.json')
        if not control or control['bundle']['sha256'] != step['sha256']:
            raise ValueError('Step has no matching frozen program')
        report = reader.json_asset('probe-receipt.json')
        latest_run = next((r for r in runs if r['display_title'] == 'Probe ' + step['tag'] and r['head_branch'] == 'main'), None)
        if (report and report.get('failure_type') == 'timeout') or (report is None and latest_run and latest_run['conclusion'] == 'timed_out'):
            inventory = sweep.Store(args.repo, step['tag'])
            snapshots = sorted((a for a in inventory.assets.values() if a['name'].startswith('snapshot-') and a['name'].endswith('.json')),
                               key=lambda a: a['created_at'])
            saved = reader.json_asset(snapshots[-1]['name']) if snapshots else None
            if saved and saved['bundle_sha256'] == step['sha256']:
                verified = len(saved['outputs']) == 1 and all(inventory.assets.get(o['name'], {}).get('digest') == 'sha256:' + o['sha256']
                               and inventory.assets[o['name']]['size'] == o['bytes'] for o in saved['outputs'])
                if verified:
                    report = report or {'bundle_sha256': step['sha256'], 'success': False, 'failure_type': 'timeout'}
                    report['resume_available'] = True
        if report: receipts[step['tag']] = report
    action, index = next_step(steps, receipts, active)
    if action == 'dispatch' and index in state['dispatched']:
        if not retry_dispatch(state, index, steps[index], runs, dt.datetime.now(dt.timezone.utc)):
            # Preserve unfinished snapshots; do not repeat a failed private program.
            action = 'step_needs_attention'
    state.update(action=action, index=index, active=active, checked_utc=sweep.now())
    inputs = None
    if action == 'dispatch':
        if index not in state['dispatched']: state['dispatched'].append(index)
        requests = state.setdefault('requests', {})
        attempts = requests.get(str(index), {}).get('attempts', 0)
        requests[str(index)] = {'requested_utc': sweep.now(), 'attempts': attempts + 1}
        inputs = {'ref': 'main', 'inputs': {'tag': steps[index]['tag']}}
    state['failed_optional'] = [s['tag'] for s in steps if s.get('optional') and receipts.get(s['tag'], {}).get('success') is False]
    if action in ('complete', 'identity_needs_attention', 'step_needs_attention'):
        state['finished'] = True
    path = args.out / 'line-state.json'; sweep.save(path, state)
    sweep.gh(['release', 'upload', args.tag, str(path), '--repo', args.repo, '--clobber'])
    if inputs:
        path = args.out / 'dispatch.json'; sweep.save(path, inputs)
        sweep.gh(['api', '--method', 'POST', f'repos/{args.repo}/actions/workflows/probe.yml/dispatches', '--input', str(path)])
    if state.get('finished'):
        sweep.gh(['api', '--method', 'PUT', f'repos/{args.repo}/actions/workflows/line.yml/disable'])
    print(json.dumps(state), flush=True)
    return state


def wake(args):
    workflow = json.loads(sweep.gh(['api', f'repos/{args.repo}/actions/workflows/line.yml']))
    if workflow['state'] != 'active':
        print(json.dumps({'controller_wake': False, 'reason': 'disabled'})); return
    path = args.out / 'wake.json'; sweep.save(path, {'ref': 'main'})
    sweep.gh(['api', '--method', 'POST', f'repos/{args.repo}/actions/workflows/line.yml/dispatches', '--input', str(path)])
    print(json.dumps({'controller_wake': True}), flush=True)


def watch(args):
    if not 60 <= args.watch_seconds <= 19500: raise ValueError('Unsupported watch budget')
    deadline = time.monotonic() + args.watch_seconds
    while True:
        state = run(args)
        if state.get('finished'): return
        remaining = deadline - time.monotonic()
        if remaining <= 60:
            # The replacement waits behind this workflow's concurrency group.
            wake(args); return
        time.sleep(min(60, remaining))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True); parser.add_argument('--tag', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--watch-seconds', type=int, default=0)
    parser.add_argument('--wake', action='store_true')
    args = parser.parse_args(); args.out.mkdir(parents=True, exist_ok=True)
    if args.wake: wake(args)
    elif args.watch_seconds: watch(args)
    else: run(args)
