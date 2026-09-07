from datetime import datetime, timedelta
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from frame_parser import CrcKind, FrameConfig, FrameProtocol, RxChunk, crc16_modbus, parse_chunks


class FrameParserTests(unittest.TestCase):
    def test_frame_can_span_two_receives(self):
        result = parse_chunks([RxChunk(b"\xAA\x55\x01"), RxChunk(b"\x02\x03")], FrameConfig(b"\xAA\x55", fixed_length=5))
        self.assertEqual(result.frames, [b"\xAA\x55\x01\x02\x03"])
        self.assertFalse(result.events)

    def test_truncated_tail_is_not_a_frame(self):
        result = parse_chunks([RxChunk(b"\xAA\x55\x01")], FrameConfig(b"\xAA\x55", fixed_length=5))
        self.assertEqual(result.frames, [])
        self.assertEqual(result.truncations, 1)

    def test_noise_is_counted_then_valid_frame_recovers(self):
        result = parse_chunks([RxChunk(b"\x00\xAA\x55\x01\x02\x03")], FrameConfig(b"\xAA\x55", fixed_length=5))
        self.assertEqual(result.noise_bytes, 1)
        self.assertEqual(len(result.frames), 1)

    def test_crc_error_does_not_emit_frame_and_recovers(self):
        body = b"\xAA\x55\x01"
        good = body + crc16_modbus(body).to_bytes(2, "little")
        bad = b"\xAA\x55\x00\x00\x00"
        result = parse_chunks([RxChunk(bad + good)], FrameConfig(b"\xAA\x55", fixed_length=5, crc=CrcKind.MODBUS))
        self.assertEqual(result.crc_errors, 1)
        self.assertEqual(result.frames, [good])

    def test_gap_marks_waiting_frame_as_truncated(self):
        now = datetime.now()
        result = parse_chunks(
            [RxChunk(b"\xAA\x55\x01", now), RxChunk(b"\xAA\x55\x02\x03\x04", now + timedelta(milliseconds=50))],
            FrameConfig(b"\xAA\x55", fixed_length=5, max_frame_gap_ms=10),
        )
        self.assertEqual(result.truncations, 1)
        self.assertEqual(len(result.frames), 1)

    def test_modbus_response_can_be_split_across_receives(self):
        body = b"\x2E\x03\x02\x12\x34"
        frame = body + crc16_modbus(body).to_bytes(2, "little")
        result = parse_chunks(
            [RxChunk(frame[:3]), RxChunk(frame[3:])],
            FrameConfig(protocol=FrameProtocol.MODBUS_RTU, crc=CrcKind.MODBUS),
        )
        self.assertEqual(result.frames, [frame])
        self.assertEqual(result.crc_errors, 0)


if __name__ == "__main__":
    unittest.main()
