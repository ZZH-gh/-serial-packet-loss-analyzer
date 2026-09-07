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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


HEX_BYTE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
RX_MARKER = re.compile(r"\b(?:rx|recv|receive|received)\b|接收|收到|<<|←", re.IGNORECASE)
TX_MARKER = re.compile(r"\b(?:tx|send|sent)\b|发送|发出|>>|→", re.IGNORECASE)
TIMESTAMP_PREFIX = re.compile(r"^\s*(?:(\d{4}[-/]\d{1,2}[-/]\d{1,2})\s+)?(\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*")


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


def parse_hex(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if not cleaned or len(cleaned) % 2:
        raise argparse.ArgumentTypeError("hex bytes must contain an even number of digits")
    return bytes.fromhex(cleaned)


def read_bytes(path: Path) -> bytes:
    # SSCOM exports commonly contain spaces/newlines/timestamps.  The frame
    # header below is used to find valid frames in the resulting byte stream.
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    return bytes(int(token.group(), 16) for token in HEX_BYTE.finditer(text))


def read_receive_chunks(path: Path):
    """Extract RX bytes from common SSCOM-style direction-tagged logs.

    Returns (data, direction_markers_found, rx_line_count).  When no direction
    marker exists the complete HEX stream is returned, so plain HEX exports
    remain usable; callers should display that limitation to the user.
    """
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    from frame_parser import RxChunk

    active_rx = False
    found_marker = False
    rx_lines = 0
    chunks = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        is_rx = bool(RX_MARKER.search(line))
        is_tx = bool(TX_MARKER.search(line))
        if is_rx or is_tx:
            found_marker = True
            active_rx = is_rx and not is_tx
        timestamp = None
        payload = line
        match = TIMESTAMP_PREFIX.match(line)
        if match:
            payload = line[match.end():]
            try:
                stamp = f"{match.group(1) or '1900-01-01'} {match.group(2).replace(',', '.')}"
                timestamp = datetime.fromisoformat(stamp.replace('/', '-'))
            except ValueError:
                pass
        tokens = list(HEX_BYTE.finditer(payload))
        if active_rx and tokens:
            chunks.append(RxChunk(bytes(int(token.group(), 16) for token in tokens), timestamp, line_no))
            rx_lines += 1
    if not found_marker:
        return [RxChunk(read_bytes(path))], False, 0
    return chunks, True, rx_lines


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


def analyze_cycles(sequences: list[int]) -> tuple[int, list[CycleResult]] | None:
    """Analyze repeated, ascending sequence-number sweeps.

    A decrease starts a new sweep.  The expected count is inferred from the
    most frequent sweep span (with the largest span used to break ties).  A
    sweep with fewer than half of the expected unique sequence values is
    considered an incomplete acquisition and excluded from the average.
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
    frequencies = {span: spans.count(span) for span in set(spans)}
    expected = max(frequencies, key=lambda span: (frequencies[span], span))
    if expected < 2:
        return None
    results: list[CycleResult] = []
    for index, group in enumerate(groups, start=1):
        received = len(set(group))
        missing = max(0, expected - received)
        results.append(CycleResult(index, received, expected, missing, received * 2 >= expected))
    return expected, results


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
