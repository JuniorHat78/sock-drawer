import unittest
import care


class Decisions(unittest.TestCase):
    def choose(self, **changes):
        values = dict(state={}, active={'Sweep': [], 'Mill': [], 'Probe': []}, raw_done=False,
                      chunks=5, ready=True, cpu_done=False, failed=0, previous_failed=False)
        values.update(changes)
        return care.decision(**values)

    def test_source_campaigns_do_not_overlap(self):
        self.assertEqual(self.choose(active={'Sweep': [1], 'Mill': [2], 'Probe': []}), 'wait')
        self.assertEqual(self.choose(active={'Sweep': [1], 'Mill': [], 'Probe': []}), 'cpu')

    def test_one_experiment_blocks_new_cpu_batches(self):
        self.assertEqual(self.choose(raw_done=True, active={'Sweep': [], 'Mill': [], 'Probe': [3]}), 'wait')

    def test_unexpected_record_errors_are_not_retried(self):
        self.assertEqual(self.choose(raw_done=True, failed=1, previous_failed=True), 'cpu_needs_attention')

    def test_retries_are_bounded(self):
        self.assertEqual(self.choose(state={'source_retries': 3}), 'source_needs_attention')
        self.assertEqual(self.choose(raw_done=True, chunks=5, state={'cpu_last_chunks': 5, 'cpu_retries': 3}, previous_failed=True), 'cpu_needs_attention')

    def test_no_new_chunks_do_not_repeat_successful_partial_work(self):
        self.assertEqual(self.choose(raw_done=False, active={'Sweep': [1], 'Mill': [], 'Probe': []}, state={'cpu_last_chunks': 5}), 'wait')
        self.assertEqual(self.choose(raw_done=True, state={'cpu_last_chunks': 5}, previous_failed=True), 'cpu_retry')

    def test_proof_is_required_and_completion_stops_work(self):
        self.assertEqual(self.choose(raw_done=True, ready=False), 'wait')
        self.assertEqual(self.choose(raw_done=True, cpu_done=True), 'complete')


if __name__ == '__main__': unittest.main()
