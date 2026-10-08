import unittest
import datetime as dt
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
import line


class LineTests(unittest.TestCase):
    def parallel_fixture(self):
        now = dt.datetime(2026, 10, 8, 3, tzinfo=dt.timezone.utc)
        steps = [{'tag': 'a', 'sha256': 'x'}, {'tag': 'b', 'sha256': 'y', 'after': ['a']},
                 {'tag': 'c', 'sha256': 'z'}, {'tag': 'd', 'sha256': 'w'}]
        run = {'id': 10, 'display_title': 'Probe a', 'head_branch': 'main', 'status': 'in_progress',
               'created_at': now.isoformat(), 'updated_at': now.isoformat()}
        return now, steps, run

    def test_parallel_independent_steps_fill_slots_while_dependent_step_waits(self):
        now, steps, run = self.parallel_fixture()
        action, ready, issues, reserved, states = line.parallel_steps(steps, {}, [run], {'dispatched': []}, 3, now)
        self.assertEqual((action, ready, issues, reserved), ('dispatch', [2, 3], [], 0))
        self.assertEqual(states['b'], 'dependency_wait')

    def test_parallel_unconfirmed_intents_reserve_capacity_and_are_not_repeated(self):
        now, steps, run = self.parallel_fixture()
        state = {'dispatched': [2], 'requests': {'2': {'attempts': 1, 'requested_utc': now.isoformat()}}}
        action, ready, _, reserved, _ = line.parallel_steps(steps, {}, [run], state, 2, now)
        self.assertEqual((action, ready, reserved), ('wait', [], 1))

    def test_parallel_failure_blocks_its_dependency_but_runs_independent_work(self):
        now, steps, _ = self.parallel_fixture()
        receipt = {'a': {'bundle_sha256': 'x', 'success': False}}
        action, ready, issues, _, states = line.parallel_steps(steps, receipt, [], {'dispatched': []}, 8, now)
        self.assertEqual((action, ready, issues), ('dispatch', [2, 3], [0]))
        self.assertEqual(states['b'], 'dependency_wait')

    def test_parallel_completed_job_waits_for_visibility_without_redispatch(self):
        now, steps, run = self.parallel_fixture()
        run['status'] = 'completed'
        action, ready, _, _, states = line.parallel_steps(steps, {}, [run], {'dispatched': []}, 3, now)
        self.assertEqual(ready, [2, 3]); self.assertEqual(states['a'], 'receipt_visibility')

    def test_parallel_resume_requires_checked_timeout_and_explicit_dependency(self):
        now, steps, _ = self.parallel_fixture()
        steps[1]['resume_of'] = 'a'
        receipt = {'a': {'bundle_sha256': 'x', 'success': False, 'failure_type': 'timeout', 'resume_available': True}}
        self.assertEqual(line.parallel_steps(steps, receipt, [], {'dispatched': []}, 3, now)[1], [1, 2, 3])
        receipt['a']['resume_available'] = False
        self.assertEqual(line.parallel_steps(steps, receipt, [], {'dispatched': []}, 3, now)[1], [2, 3])

    def test_parallel_optional_failure_cannot_silently_complete_a_blocked_dependent(self):
        now, steps, _ = self.parallel_fixture()
        steps = steps[:2]; steps[0]['optional'] = True
        receipt = {'a': {'bundle_sha256': 'x', 'success': False}}
        self.assertEqual(line.parallel_steps(steps, receipt, [], {'dispatched': []}, 3, now)[0], 'step_needs_attention')

    def test_watch_rolls_over_before_runner_deadline(self):
        args = SimpleNamespace(watch_seconds=180)
        with patch.object(line, 'run', return_value={'finished': False}), patch.object(line, 'wake') as wake:
            with patch.object(line.time, 'monotonic', side_effect=[0, 121]): line.watch(args)
        wake.assert_called_once_with(args)

    def test_watch_stops_when_the_frozen_queue_finishes(self):
        args = SimpleNamespace(watch_seconds=180)
        with patch.object(line, 'run', side_effect=[{'finished': False}, {'finished': True}]), patch.object(line.time, 'sleep') as sleep:
            with patch.object(line.time, 'monotonic', side_effect=[0, 20]): line.watch(args)
        sleep.assert_called_once_with(60)

    def test_watch_retries_transient_errors_but_stops_after_three(self):
        args = SimpleNamespace(watch_seconds=180)
        with patch.object(line, 'run', side_effect=RuntimeError('temporary')), patch.object(line.time, 'sleep') as sleep:
            with patch.object(line.time, 'monotonic', return_value=0):
                with self.assertRaises(RuntimeError): line.watch(args)
        self.assertEqual(sleep.call_count, 2)

    def test_no_parallel_steps(self):
        self.assertEqual(line.next_step([{'tag': 'a', 'sha256': 'x'}], {}, [4]), ('wait', None))

    def test_completed_job_waits_for_its_receipt_without_redispatch(self):
        now = dt.datetime(2026, 10, 8, 1, tzinfo=dt.timezone.utc)
        run = {'status': 'completed', 'updated_at': (now - dt.timedelta(seconds=15)).isoformat()}
        self.assertEqual(line.missing_receipt_action(run, now), 'wait')
        self.assertEqual(line.missing_receipt_action(run, now + dt.timedelta(minutes=11)), 'step_needs_attention')
        run['status'] = 'in_progress'
        self.assertEqual(line.missing_receipt_action(run, now), 'wait')

    def test_public_missing_receipt_is_rechecked_by_verified_asset_id(self):
        report = {'success': True, 'bundle_sha256': 'x'}
        with patch.object(line.mill, 'PublicSource') as reader, patch.object(line.sweep, 'Store') as store:
            reader.json_asset.return_value = None
            store.return_value.json_asset.return_value = report
            self.assertEqual(line.read_receipt('a/b', 'c', reader, {'status': 'completed'}), report)
            store.assert_called_once_with('a/b', 'c')
            store.return_value.json_asset.assert_called_once_with('probe-receipt.json')

    def test_active_job_does_not_poll_authenticated_receipt_metadata(self):
        with patch.object(line.mill, 'PublicSource') as reader, patch.object(line.sweep, 'Store') as store:
            reader.json_asset.return_value = None
            self.assertIsNone(line.read_receipt('a/b', 'c', reader, {'status': 'in_progress'}))
            store.assert_not_called()

    def completed_handoff(self, authenticated_report):
        now = dt.datetime.now(dt.timezone.utc)
        steps = [{'tag': 'q1', 'sha256': 'a' * 64}, {'tag': 'q2', 'sha256': 'b' * 64}]
        config = {'schema': 'box-line-1', 'repo': 'a/b', 'steps': steps}
        completed = {'id': 10, 'display_title': 'Probe q1', 'head_branch': 'main',
                     'status': 'completed', 'conclusion': 'success',
                     'updated_at': (now - dt.timedelta(seconds=15)).isoformat()}
        source = Mock()
        source.json_asset.side_effect = lambda name: config if name == 'line.json' else None
        receipt_store = Mock()
        receipt_store.json_asset.return_value = authenticated_report
        def store(repo, tag): return source if tag == 'line' else receipt_store
        def reader(repo, tag, scratch):
            result = Mock()
            result.json_asset.side_effect = lambda name: {'bundle': {'sha256': next(s['sha256'] for s in steps if s['tag'] == tag)}} if name == 'probe.json' else None
            return result
        def gh(values):
            return json.dumps({'workflow_runs': [completed]}).encode() if values[0] == 'api' and '/runs?' in values[1] else b''
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary, patch.object(line.sweep, 'Store', side_effect=store), patch.object(line.mill, 'PublicSource', side_effect=reader), patch.object(line.sweep, 'gh', side_effect=gh) as request:
            state = line.run(SimpleNamespace(repo='a/b', tag='line', out=Path(temporary)))
        return state, request.call_args_list

    def test_completed_handoff_advances_when_public_receipt_is_stale(self):
        state, requests = self.completed_handoff({'success': True, 'bundle_sha256': 'a' * 64})
        self.assertEqual(state['action'], 'dispatch')
        self.assertEqual(state['index'], 1)
        self.assertFalse(state.get('finished', False))
        self.assertEqual(sum('/dispatches' in str(call) for call in requests), 1)
        self.assertFalse(any('/disable' in str(call) for call in requests))

    def test_completed_handoff_waits_when_both_receipt_reads_are_missing(self):
        state, requests = self.completed_handoff(None)
        self.assertEqual(state['action'], 'wait')
        self.assertEqual(state['reason'], 'receipt_visibility')
        self.assertFalse(state.get('finished', False))
        self.assertFalse(any('/dispatches' in str(call) or '/disable' in str(call) for call in requests))

    def test_successful_steps_are_not_repeated(self):
        steps = [{'tag': 'a', 'sha256': 'x'}, {'tag': 'b', 'sha256': 'y'}]
        receipts = {'a': {'bundle_sha256': 'x', 'success': True}}
        self.assertEqual(line.next_step(steps, receipts, []), ('dispatch', 1))
        receipts['b'] = {'bundle_sha256': 'y', 'success': True}
        self.assertEqual(line.next_step(steps, receipts, []), ('complete', None))

    def test_mismatched_or_failed_program_halts_the_line(self):
        steps = [{'tag': 'a', 'sha256': 'x'}]
        self.assertEqual(line.next_step(steps, {'a': {'bundle_sha256': 'wrong', 'success': True}}, []), ('identity_needs_attention', 0))
        self.assertEqual(line.next_step(steps, {'a': {'bundle_sha256': 'x', 'success': False}}, []), ('step_needs_attention', 0))

    def test_optional_failure_does_not_block_an_independent_step(self):
        steps = [{'tag': 'a', 'sha256': 'x', 'optional': True}, {'tag': 'b', 'sha256': 'y'}]
        self.assertEqual(line.next_step(steps, {'a': {'bundle_sha256': 'x', 'success': False}}, []), ('dispatch', 1))
        self.assertEqual(line.next_step(steps, {'a': {'bundle_sha256': 'wrong', 'success': False}}, []), ('identity_needs_attention', 0))

    def test_timeout_continues_only_to_its_declared_verified_resume(self):
        steps = [{'tag': 'a', 'sha256': 'x'}, {'tag': 'b', 'sha256': 'y', 'resume_of': 'a'}]
        report = {'bundle_sha256': 'x', 'success': False, 'failure_type': 'timeout', 'resume_available': True}
        self.assertEqual(line.next_step(steps, {'a': report}, []), ('dispatch', 1))
        report['resume_available'] = False
        self.assertEqual(line.next_step(steps, {'a': report}, []), ('step_needs_attention', 0))

    def test_dispatch_retries_never_repeat_a_created_job(self):
        now = dt.datetime(2026, 10, 7, 18, tzinfo=dt.timezone.utc)
        state = {'requests': {'1': {'attempts': 1, 'requested_utc': (now - dt.timedelta(minutes=3)).isoformat()}}}
        self.assertTrue(line.retry_dispatch(state, 1, {'tag': 'b'}, [], now))
        runs = [{'display_title': 'Probe b', 'head_branch': 'main', 'created_at': (now - dt.timedelta(minutes=2)).isoformat()}]
        self.assertFalse(line.retry_dispatch(state, 1, {'tag': 'b'}, runs, now))
        state['requests']['1']['attempts'] = 3
        self.assertFalse(line.retry_dispatch(state, 1, {'tag': 'b'}, [], now))

    def test_unconfirmed_dispatch_gets_a_visibility_grace_period(self):
        now = dt.datetime(2026, 10, 7, 18, tzinfo=dt.timezone.utc)
        state = {'requests': {'1': {'attempts': 1, 'requested_utc': (now - dt.timedelta(seconds=60)).isoformat()}}}
        self.assertEqual(line.recovery_action(state, 1, {'tag': 'b'}, [], now), 'wait')
        self.assertEqual(line.recovery_action(state, 1, {'tag': 'b'}, [], now + dt.timedelta(seconds=65)), 'dispatch')


if __name__ == '__main__': unittest.main()
