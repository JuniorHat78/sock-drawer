"""Run a bounded list of checked sealed steps, one at a time."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import mill
import sweep


def next_step(steps, receipts, active):
    if active: return 'wait', None
    for index, step in enumerate(steps):
        report = receipts.get(step['tag'])
        if report is None: return 'dispatch', index
        if report.get('bundle_sha256') != step['sha256']: return 'identity_needs_attention', index
        if report.get('success') is not True: return 'step_needs_attention', index
    return 'complete', None


def run(args):
    source = sweep.Store(args.repo, args.tag)
    config = source.json_asset('line.json')
    if config is None:
        print(json.dumps({'line_ready': False})); return
    if config.get('schema') != 'box-line-1' or config.get('repo') != args.repo:
        raise ValueError('Unsupported sealed line')
    steps = config['steps']
    if not 1 <= len(steps) <= 20 or len({s['tag'] for s in steps}) != len(steps):
        raise ValueError('Unsupported step count')
    for step in steps:
        sweep.identity(args.repo, step['tag'])
        if len(step['sha256']) != 64 or set(step['sha256']) - set('0123456789abcdef'):
            raise ValueError('Invalid step identity')
    identity = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    state = source.json_asset('line-state.json') or {'schema': 'box-line-state-1', 'identity': identity, 'dispatched': []}
    if state['identity'] != identity: raise ValueError('Line configuration changed')
    if state.get('finished'):
        print(json.dumps({'finished': True, 'action': state['action']})); return
    runs = json.loads(sweep.gh(['api', f'repos/{args.repo}/actions/workflows/probe.yml/runs?per_page=30']))['workflow_runs']
    active = [r['id'] for r in runs if r['head_branch'] == 'main' and r['status'] != 'completed']
    receipts = {}
    for step in steps:
        reader = mill.PublicSource(args.repo, step['tag'], args.out / 'metadata')
        control = reader.json_asset('probe.json')
        if not control or control['bundle']['sha256'] != step['sha256']:
            raise ValueError('Step has no matching frozen program')
        report = reader.json_asset('probe-receipt.json')
        if report: receipts[step['tag']] = report
    action, index = next_step(steps, receipts, active)
    if action == 'dispatch' and index in state['dispatched']:
        # Preserve unfinished snapshots; do not repeat a failed private program.
        action = 'step_needs_attention'
    state.update(action=action, index=index, active=active, checked_utc=sweep.now())
    inputs = None
    if action == 'dispatch':
        state['dispatched'].append(index)
        inputs = {'ref': 'main', 'inputs': {'tag': steps[index]['tag']}}
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True); parser.add_argument('--tag', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); args.out.mkdir(parents=True, exist_ok=True); run(args)
