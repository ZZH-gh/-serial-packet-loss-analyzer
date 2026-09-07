from datetime import datetime, timedelta
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from frame_parser import RxChunk
from serial_loss_analyzer import (
    DirectionRead, LoggedChunk, SSCOM_RX_LABEL, SSCOM_TX_LABEL, analyze_cycles,
    match_transactions, read_directional_chunks,
)


class SerialLogTests(unittest.TestCase):
    def test_sscom_native_labels_select_only_rx_and_ignore_timestamp_digits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.TXT"
            path.write_bytes(
                b"[16:10:40.925]" + SSCOM_TX_LABEL + b"FF 01\r\n"
                + b"[16:10:41.255]" + SSCOM_RX_LABEL + b"2E 03 18\r\n"
            )
            result = read_directional_chunks(path)
        self.assertEqual([chunk.data for chunk in result.tx_chunks], [b"\xFF\x01"])
        self.assertEqual([chunk.data for chunk in result.rx_chunks], [b"\x2E\x03\x18"])
        self.assertEqual(result.native_sscom_markers, 2)

    def test_cycle_domain_requires_two_broad_matching_sweeps(self):
        complete = [value for value in range(1, 87) if value not in {12, 24}]
        result = analyze_cycles(complete + [1, 2, 3] + complete)
        self.assertIsNotNone(result)
        model, cycles = result
        self.assertEqual((model.first_sequence, model.last_sequence, model.expected), (1, 86, 86))
        self.assertEqual(model.evidence_cycles, 2)
        self.assertEqual([cycle.missing for cycle in cycles if cycle.included], [2, 2])

    def test_cycle_coverage_threshold_is_configurable(self):
        complete = list(range(1, 11))
        result = analyze_cycles(complete + [1, 2, 3, 4] + complete, min_coverage=0.4)
        self.assertIsNotNone(result)
        _, cycles = result
        self.assertTrue(cycles[1].included)

    def test_manual_cycle_domain_allows_a_single_captured_sweep(self):
        result = analyze_cycles([2, 3, 5, 6], expected_start=1, expected_count=6)
        self.assertIsNotNone(result)
        model, cycles = result
        self.assertEqual((model.first_sequence, model.last_sequence, model.evidence_cycles), (1, 6, 0))
        self.assertEqual(cycles[0].missing_values, (1, 4))

    def test_transaction_pairing_is_separate_from_receive_loss(self):
        now = datetime(1900, 1, 1, 12, 0, 0)
        tx = RxChunk(b"\xFF\x01\x03", now, 1)
        rx = RxChunk(b"\x01\x03\x00", now + timedelta(milliseconds=30), 2)
        read = DirectionRead(
            rx_chunks=[rx], tx_chunks=[tx],
            records=[LoggedChunk("tx", tx), LoggedChunk("rx", rx)],
            direction_markers_found=True,
        )
        result = match_transactions(read)
        self.assertEqual((result.paired, result.unmatched_sent, result.orphan_received, result.key_confirmed), (1, 0, 0, 1))
        self.assertEqual(result.average_latency_ms, 30.0)

    def test_transaction_timeout_does_not_pair_stale_request(self):
        now = datetime(1900, 1, 1, 12, 0, 0)
        tx = RxChunk(b"\x01\x03", now, 1)
        rx = RxChunk(b"\x01\x03\x00", now + timedelta(milliseconds=31), 2)
        read = DirectionRead(rx_chunks=[rx], tx_chunks=[tx], records=[LoggedChunk("tx", tx), LoggedChunk("rx", rx)])
        result = match_transactions(read, timeout_ms=30)
        self.assertEqual((result.paired, result.timed_out_sent, result.orphan_received), (0, 1, 1))


if __name__ == "__main__":
    unittest.main()
