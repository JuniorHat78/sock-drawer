import unittest
import datetime as dt
from types import SimpleNamespace
from unittest.mock import patch
import line


class LineTests(unittest.TestCase):
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

    def test_no_parallel_steps(self):
        self.assertEqual(line.next_step([{'tag': 'a', 'sha256': 'x'}], {}, [4]), ('wait', None))

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


if __name__ == '__main__': unittest.main()
