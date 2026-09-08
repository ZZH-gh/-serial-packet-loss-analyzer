from datetime import datetime, timedelta
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from frame_parser import FrameConfig, FrameEvidence, OperationCancelled, RxChunk
from serial_loss_analyzer import (
    DirectionRead, LoggedChunk, SSCOM_RX_LABEL, SSCOM_TX_LABEL, analyze_cycles, analyze_time_windows,
    analyze_log, detect_protocol, match_transactions, read_directional_chunks,
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

    def test_time_windows_locate_missing_sequence_and_long_interval(self):
        now = datetime(1900, 1, 1, 12, 0, 0)
        evidence = [
            FrameEvidence(b"a", first_timestamp=now),
            FrameEvidence(b"b", first_timestamp=now + timedelta(milliseconds=100)),
            FrameEvidence(b"c", first_timestamp=now + timedelta(milliseconds=200)),
            FrameEvidence(b"d", first_timestamp=now + timedelta(milliseconds=1000)),
        ]
        baseline, windows = analyze_time_windows(evidence, [1, 2, 4, 5], 1, 1000, 60)
        self.assertEqual(baseline, 100.0)
        self.assertEqual((windows[0].received, windows[0].missing, windows[0].long_intervals), (4, 1, 1))

    def test_time_windows_allow_hour_long_buckets(self):
        now = datetime(1900, 1, 1, 12, 34, 1)
        evidence = [
            FrameEvidence(b"a", first_timestamp=now),
            FrameEvidence(b"b", first_timestamp=now + timedelta(seconds=1)),
        ]
        _, windows = analyze_time_windows(evidence, [1, 2], 1, 10, 3600)
        self.assertEqual(windows[0].start.strftime("%H:%M:%S"), "12:00:00")

    def test_time_windows_do_not_count_cycle_boundary_as_loss(self):
        now = datetime(1900, 1, 1, 12, 0, 0)
        evidence = [
            FrameEvidence(b"a", first_timestamp=now),
            FrameEvidence(b"b", first_timestamp=now + timedelta(milliseconds=10)),
            FrameEvidence(b"c", first_timestamp=now + timedelta(milliseconds=20)),
        ]
        _, windows = analyze_time_windows(evidence, [9, 10, 1], 1, 1000, 60)
        self.assertEqual(windows[0].missing, 0)

    def test_analyze_log_reuses_rx_only_pipeline_for_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compare.dat"
            path.write_bytes(
                b"[12:00:00.000]" + SSCOM_RX_LABEL + b"AA 55 01\r\n"
                + b"[12:00:00.100]" + SSCOM_RX_LABEL + b"AA 55 03\r\n"
            )
            result = analyze_log(path, FrameConfig(b"\xAA\x55", fixed_length=3), 2, 1, "little", 10)
        self.assertEqual(result.sequences, [1, 3])
        self.assertEqual((result.missing, result.loss_percent), (1, 100 / 3))

    def test_log_read_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cancel.txt"
            path.write_bytes(b"[12:00:00] RX AA 55 01\r\n")
            with self.assertRaises(OperationCancelled):
                read_directional_chunks(path, progress_callback=lambda _current, _total: False)

    def test_protocol_detection_can_be_cancelled(self):
        with self.assertRaises(OperationCancelled):
            detect_protocol(b"\xAA\x55\x01" * 10, progress_callback=lambda _current, _total: False)


if __name__ == "__main__":
    unittest.main()
