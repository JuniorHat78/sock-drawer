import unittest
import line


class LineTests(unittest.TestCase):
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


if __name__ == '__main__': unittest.main()
