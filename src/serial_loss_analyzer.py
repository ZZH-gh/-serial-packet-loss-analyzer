#!/usr/bin/env python3
"""Count missing sequence numbers in a serial HEX log.

Designed for logs exported by SSCOM or any terminal that retains the received
HEX bytes.  It deliberately uses only Python's standard library.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


HEX_BYTE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
HEX_BYTE_RAW = re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{2})(?![0-9A-Fa-f])")
RX_MARKER = re.compile(r"\b(?:rx|recv|receive|received)\b|接收|收到|<<|←", re.IGNORECASE)
TX_MARKER = re.compile(r"\b(?:tx|send|sent)\b|发送|发出|>>|→", re.IGNORECASE)
TIMESTAMP_PREFIX = re.compile(r"^\s*(?:(\d{4}[-/]\d{1,2}[-/]\d{1,2})\s+)?(\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*")
TIMESTAMP_PREFIX_RAW = re.compile(rb"^\s*(?:\[(?:(\d{4}[-/]\d{1,2}[-/]\d{1,2})\s+)?(\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\])?\s*")

# SSCOM 5.00a's traditional-Chinese direction glyphs are stored as these
# byte sequences, which are not decodable by normal GBK tables.  Detecting
# them at byte level is therefore more reliable than decoding with replacement.
SSCOM_TX_LABEL = bytes.fromhex("B7 A2 A1 FA A1 F3")
SSCOM_RX_LABEL = bytes.fromhex("CA D5 A1 FB A1 F4")


@dataclass(frozen=True)
class Gap:
    after: int
    first_missing: int
    last_missing: int
    count: int


@dataclass(frozen=True)
class Detection:
    """Best-effort fixed-frame protocol suggestion from a raw HEX stream."""

    header: bytes
    frame_size: int
    seq_offset: int | None
    seq_size: int | None
    endian: str | None
    confidence: float


@dataclass(frozen=True)
class CycleResult:
    index: int
    received: int
    expected: int
    missing: int
    included: bool
    first: int = 0
    last: int = 0
    duplicates: int = 0
    missing_values: tuple[int, ...] = ()


@dataclass(frozen=True)
class CycleModel:
    first_sequence: int
    last_sequence: int
    expected: int
    evidence_cycles: int


@dataclass(frozen=True)
class LoggedChunk:
    direction: str
    chunk: object


@dataclass
class DirectionRead:
    rx_chunks: list = field(default_factory=list)
    tx_chunks: list = field(default_factory=list)
    unknown_chunks: list = field(default_factory=list)
    records: list[LoggedChunk] = field(default_factory=list)
    direction_markers_found: bool = False
    native_sscom_markers: int = 0

    @property
    def direction_confidence(self) -> float:
        known = len(self.rx_chunks) + len(self.tx_chunks)
        total = known + len(self.unknown_chunks)
        return known / total if total else 0.0


@dataclass(frozen=True)
class TransactionSummary:
    sent: int
    received: int
    paired: int
    unmatched_sent: int
    orphan_received: int
    key_confirmed: int
    latency_ms: tuple[float, ...]

    @property
    def average_latency_ms(self) -> float | None:
        return sum(self.latency_ms) / len(self.latency_ms) if self.latency_ms else None


def parse_hex(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if not cleaned or len(cleaned) % 2:
        raise argparse.ArgumentTypeError("hex bytes must contain an even number of digits")
    return bytes.fromhex(cleaned)


def read_bytes(path: Path) -> bytes:
    """Read all payload bytes, never interpreting timestamp digits as HEX."""
    parsed = read_directional_chunks(path)
    return b"".join(record.chunk.data for record in parsed.records)


def _timestamp_and_body(raw_line: bytes) -> tuple[datetime | None, bytes]:
    match = TIMESTAMP_PREFIX_RAW.match(raw_line)
    if not match:
        return None, raw_line
    timestamp = None
    if match.group(2):
        try:
            date = (match.group(1) or b"1900-01-01").decode("ascii").replace("/", "-")
            clock = match.group(2).decode("ascii").replace(",", ".")
            timestamp = datetime.fromisoformat(f"{date} {clock}")
        except ValueError:
            pass
    return timestamp, raw_line[match.end() :]


def _direction_and_payload(body: bytes) -> tuple[str | None, bytes, bool]:
    stripped = body.lstrip()
    if stripped.startswith(SSCOM_TX_LABEL):
        return "tx", stripped[len(SSCOM_TX_LABEL) :], True
    if stripped.startswith(SSCOM_RX_LABEL):
        return "rx", stripped[len(SSCOM_RX_LABEL) :], True
    # Modern terminal exports often use readable ASCII labels.  Latin-1 keeps
    # their bytes losslessly; the Chinese labels above were handled first.
    ascii_prefix = stripped[:32].decode("latin1", errors="ignore")
    is_rx = bool(RX_MARKER.search(ascii_prefix))
    is_tx = bool(TX_MARKER.search(ascii_prefix))
    if is_rx != is_tx:
        return ("rx" if is_rx else "tx"), stripped, False
    return None, stripped, False


def _payload_bytes(body: bytes) -> bytes:
    return bytes(int(token, 16) for token in HEX_BYTE_RAW.findall(body))


def read_directional_chunks(path: Path) -> DirectionRead:
    """Read SSCOM logs while preserving RX/TX evidence and timestamps.

    An unmarked continuation line inherits the immediately preceding direction.
    If the whole file has no direction labels it is deliberately marked
    ``unknown`` rather than silently calling it RX; the compatibility wrapper
    still returns those bytes for plain HEX logs.
    """
    from frame_parser import RxChunk

    result = DirectionRead()
    active_direction: str | None = None
    for line_no, raw_line in enumerate(path.read_bytes().splitlines(), start=1):
        timestamp, body = _timestamp_and_body(raw_line)
        direction, payload_text, native = _direction_and_payload(body)
        if direction:
            result.direction_markers_found = True
            active_direction = direction
            if native:
                result.native_sscom_markers += 1
        elif active_direction:
            direction = active_direction
        payload = _payload_bytes(payload_text)
        if not payload:
            continue
        chunk = RxChunk(payload, timestamp, line_no)
        final_direction = direction or "unknown"
        result.records.append(LoggedChunk(final_direction, chunk))
        if final_direction == "rx":
            result.rx_chunks.append(chunk)
        elif final_direction == "tx":
            result.tx_chunks.append(chunk)
        else:
            result.unknown_chunks.append(chunk)
    return result


def read_receive_chunks(path: Path):
    """Extract RX bytes from common SSCOM-style direction-tagged logs.

    Returns (data, direction_markers_found, rx_line_count).  When no direction
    marker exists the complete HEX stream is returned, so plain HEX exports
    remain usable; callers should display that limitation to the user.
    """
    parsed = read_directional_chunks(path)
    if not parsed.direction_markers_found:
        return parsed.unknown_chunks, False, 0
    return parsed.rx_chunks, True, len(parsed.rx_chunks)


def read_receive_bytes(path: Path) -> tuple[bytes, bool, int]:
    chunks, found_marker, rx_lines = read_receive_chunks(path)
    return b"".join(chunk.data for chunk in chunks), found_marker, rx_lines


def frames(stream: bytes, header: bytes, frame_size: int):
    position = 0
    while position <= len(stream) - frame_size:
        found = stream.find(header, position)
        if found < 0 or found + frame_size > len(stream):
            return
        yield stream[found : found + frame_size]
        position = found + frame_size


def detect_protocol(stream: bytes) -> Detection | None:
    """Suggest a two-byte header, fixed frame size, and sequence field.

    A candidate is useful only when it repeatedly occurs at the same spacing.
    The heuristic intentionally returns None for short/noisy logs instead of
    pretending that a protocol has been identified.
    """
    if len(stream) < 24:
        return None
    positions: dict[bytes, list[int]] = {}
    for index in range(len(stream) - 1):
        positions.setdefault(stream[index : index + 2], []).append(index)

    best: tuple[float, bytes, int] | None = None
    for header, offsets in positions.items():
        if len(offsets) < 4:
            continue
        distances = [right - left for left, right in zip(offsets, offsets[1:])]
        usable = [distance for distance in distances if 4 <= distance <= 1024]
        if len(usable) < 3:
            continue
        mode = max(set(usable), key=usable.count)
        matches = usable.count(mode)
        consistency = matches / len(usable)
        score = matches * consistency
        if best is None or score > best[0]:
            best = (score, header, mode)
    if best is None:
        return None

    score, header, frame_size = best
    captured = list(frames(stream, header, frame_size))
    if len(captured) < 3:
        return None
    best_seq: tuple[float, int, int, str] | None = None
    for size in (1, 2, 4):
        for offset in range(len(header), frame_size - size + 1):
            for endian in ("little", "big"):
                values = [int.from_bytes(frame[offset : offset + size], endian) for frame in captured]
                modulus = 1 << (size * 8)
                advances = [(right - left) % modulus for left, right in zip(values, values[1:])]
                normal = sum(advance == 1 for advance in advances)
                short_gap = sum(2 <= advance <= 32 for advance in advances)
                duplicates = sum(advance == 0 for advance in advances)
                field_score = normal + short_gap * 0.55 - duplicates * 0.25
                if best_seq is None or field_score > best_seq[0]:
                    best_seq = (field_score, offset, size, endian)
    confidence = min(1.0, score / max(3, len(captured) - 1))
    if best_seq is None or best_seq[0] < 2:
        return Detection(header, frame_size, None, None, None, confidence)
    return Detection(header, frame_size, best_seq[1], best_seq[2], best_seq[3], confidence)


def detect_sequence_field(captured: list[bytes]) -> tuple[int, int, str] | None:
    """Suggest a monotonically increasing field from already extracted frames."""
    if len(captured) < 4:
        return None
    best: tuple[float, int, int, str] | None = None
    shortest = min(map(len, captured))
    for size in (1, 2, 4):
        for offset in range(0, shortest - size + 1):
            for endian in ("little", "big"):
                values = [int.from_bytes(frame[offset : offset + size], endian) for frame in captured]
                modulus = 1 << (size * 8)
                advances = [(right - left) % modulus for left, right in zip(values, values[1:])]
                normal = sum(advance == 1 for advance in advances)
                short_gap = sum(2 <= advance <= 32 for advance in advances)
                duplicates = sum(advance == 0 for advance in advances)
                score = normal + short_gap * 0.55 - duplicates * 0.25
                if best is None or score > best[0]:
                    best = (score, offset, size, endian)
    if best is None or best[0] < 2:
        return None
    return best[1], best[2], best[3]


def analyze_cycles(sequences: list[int]) -> tuple[CycleModel, list[CycleResult]] | None:
    """Analyze ascending sweeps without turning partial logs into a tiny cycle.

    A decrease is a *candidate* boundary.  The sequence domain is accepted
    only when at least two broad sweeps independently show the same outer
    range.  This fixes the common failure mode where several short fragments
    make a span of 5 look more frequent than the real 1..86 cycle.
    """
    if len(sequences) < 6:
        return None
    groups: list[list[int]] = [[]]
    for value in sequences:
        if groups[-1] and value < groups[-1][-1]:
            groups.append([])
        groups[-1].append(value)
    groups = [group for group in groups if group]
    if len(groups) < 2:
        return None
    spans = [max(group) - min(group) + 1 for group in groups if len(group) >= 2]
    if len(spans) < 2:
        return None
    largest_span = max(spans)
    # A broad sweep can have internal packet loss, but must cover 80% of the
    # best observed range to become evidence for the theoretical domain.
    broad = [group for group in groups if len(group) >= 2 and max(group) - min(group) + 1 >= largest_span * 0.8]
    if len(broad) < 2:
        return None
    ranges = [(min(group), max(group)) for group in broad]
    range_counts = {candidate: ranges.count(candidate) for candidate in set(ranges)}
    first, last = max(range_counts, key=lambda candidate: (range_counts[candidate], candidate[1] - candidate[0]))
    evidence_cycles = range_counts[(first, last)]
    expected = last - first + 1
    if expected < 2 or evidence_cycles < 2:
        return None
    results: list[CycleResult] = []
    for index, group in enumerate(groups, start=1):
        unique = set(group)
        present = {value for value in unique if first <= value <= last}
        missing_values = tuple(value for value in range(first, last + 1) if value not in present)
        received = len(present)
        results.append(
            CycleResult(
                index, received, expected, len(missing_values), received * 2 >= expected,
                min(group), max(group), len(group) - len(unique), missing_values,
            )
        )
    return CycleModel(first, last, expected, evidence_cycles), results


def detect_modbus_rtu(chunks: list) -> tuple[list[bytes], object] | None:
    """Return verified Modbus RTU frames when CRC establishes the profile."""
    from frame_parser import CrcKind, FrameConfig, FrameProtocol, parse_chunks

    if not chunks:
        return None
    parsed = parse_chunks(chunks, FrameConfig(protocol=FrameProtocol.MODBUS_RTU, crc=CrcKind.MODBUS))
    # Do not label random data as Modbus: at least three CRC-valid frames and
    # at least 80% of logged receive records must be explained.
    if len(parsed.frames) < 3 or len(parsed.frames) < len(chunks) * 0.8:
        return None
    return parsed.frames, parsed


def match_transactions(direction_read: DirectionRead) -> TransactionSummary:
    """Pair each TX with the next RX; never use this for RX loss statistics."""
    waiting = []
    paired = orphan = key_confirmed = 0
    latencies: list[float] = []
    for record in direction_read.records:
        if record.direction == "tx":
            waiting.append(record.chunk)
        elif record.direction == "rx":
            if not waiting:
                orphan += 1
                continue
            tx = waiting.pop(0)
            paired += 1
            # Some devices wrap a Modbus request in a proprietary header.  A
            # matching address/function pair anywhere in TX is evidence, not
            # a prerequisite for the chronological pairing.
            if len(record.chunk.data) >= 2 and record.chunk.data[:2] in (tx.data[index : index + 2] for index in range(max(0, len(tx.data) - 1))):
                key_confirmed += 1
            if tx.timestamp and record.chunk.timestamp:
                elapsed = (record.chunk.timestamp - tx.timestamp).total_seconds() * 1000
                if elapsed >= 0:
                    latencies.append(elapsed)
    return TransactionSummary(
        len(direction_read.tx_chunks), len(direction_read.rx_chunks), paired,
        len(waiting), orphan, key_confirmed, tuple(latencies),
    )


def write_gaps(path: Path, gaps: list[Gap]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["previous_sequence", "first_missing", "last_missing", "missing_count"])
        for gap in gaps:
            writer.writerow([gap.after, gap.first_missing, gap.last_missing, gap.count])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze fixed-size serial frames and report sequence-number gaps."
    )
    parser.add_argument("log", type=Path, help="SSCOM exported text/HEX log")
    parser.add_argument("--header", required=True, type=parse_hex, help="frame header, e.g. AA55")
    parser.add_argument("--frame-size", required=True, type=int, help="complete frame length in bytes")
    parser.add_argument("--seq-offset", required=True, type=int, help="sequence field offset from frame start")
    parser.add_argument("--seq-size", choices=(1, 2, 4), type=int, default=2)
    parser.add_argument("--endian", choices=("little", "big"), default="little")
    parser.add_argument(
        "--max-gap",
        type=int,
        default=1000,
        help="larger jumps are treated as a device restart, not loss (default: 1000)",
    )
    parser.add_argument("--report", type=Path, help="optional CSV output of every missing range")
    args = parser.parse_args()

    if args.frame_size <= len(args.header):
        parser.error("--frame-size must be longer than --header")
    if args.seq_offset < 0 or args.seq_offset + args.seq_size > args.frame_size:
        parser.error("sequence field lies outside the frame")
    if args.max_gap < 1:
        parser.error("--max-gap must be at least 1")

    captured = list(frames(read_bytes(args.log), args.header, args.frame_size))
    sequences = [
        int.from_bytes(frame[args.seq_offset : args.seq_offset + args.seq_size], args.endian)
        for frame in captured
    ]
    if not sequences:
        print("No complete frames found. Check --header and --frame-size.", file=sys.stderr)
        return 2

    modulus = 1 << (8 * args.seq_size)
    gaps: list[Gap] = []
    duplicates = resets = 0
    for previous, current in zip(sequences, sequences[1:]):
        advance = (current - previous) % modulus
        if advance == 0:
            duplicates += 1
        elif advance == 1:
            continue
        elif advance - 1 <= args.max_gap:
            gaps.append(Gap(previous, (previous + 1) % modulus, (current - 1) % modulus, advance - 1))
        else:
            resets += 1

    missing = sum(gap.count for gap in gaps)
    expected = len(sequences) + missing
    loss_rate = 100 * missing / expected if expected else 0.0
    print(f"Captured frames : {len(sequences)}")
    print(f"Missing frames  : {missing}")
    print(f"Loss rate       : {loss_rate:.4f}%")
    print(f"Duplicate seq   : {duplicates}")
    print(f"Restart/outlier : {resets}")
    print(f"Missing ranges  : {len(gaps)}")
    if args.report:
        write_gaps(args.report, gaps)
        print(f"CSV report      : {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
