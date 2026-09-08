#!/usr/bin/env python3
"""Count missing sequence numbers in a serial HEX log.

Designed for logs exported by SSCOM or any terminal that retains the received
HEX bytes.  It deliberately uses only Python's standard library.
"""

from __future__ import annotations

import argparse
import csv
import re
import statistics
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from frame_parser import OperationCancelled


HEX_BYTE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
HEX_BYTE_RAW = re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{2})(?![0-9A-Fa-f])")
RX_MARKER = re.compile(r"\b(?:rx|recv|receive|received)\b|接收|收到|<<|←", re.IGNORECASE)
TX_MARKER = re.compile(r"\b(?:tx|send|sent)\b|发送|发出|>>|→", re.IGNORECASE)
TIMESTAMP_PREFIX = re.compile(r"^\s*(?:(\d{4}[-/]\d{1,2}[-/]\d{1,2})\s+)?(\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*")
TIMESTAMP_PREFIX_RAW = re.compile(rb"^\s*(?:\[(?:(\d{4}[-/]\d{1,2}[-/]\d{1,2})\s+)?(\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\])?\s*")
TABLE_TIMESTAMP_SUFFIX = re.compile(
    r"(?P<date>\d{4}[-/]\d{1,2}[-/]\d{1,2})\s+(?P<time>\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*$"
)

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
    raw_binary_capture: bool = False
    raw_binary_receive: bool = False

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
    timed_out_sent: int
    orphan_received: int
    key_confirmed: int
    latency_ms: tuple[float, ...]
    eligible_sent: int = 0
    eligible_paired: int = 0

    @property
    def eligible_unmatched(self) -> int:
        return self.eligible_sent - self.eligible_paired

    @property
    def response_loss_percent(self) -> float | None:
        if not self.eligible_sent:
            return None
        return 100 * self.eligible_unmatched / self.eligible_sent

    @property
    def average_latency_ms(self) -> float | None:
        return sum(self.latency_ms) / len(self.latency_ms) if self.latency_ms else None


@dataclass(frozen=True)
class TimeWindowResult:
    start: datetime
    received: int
    missing: int
    average_interval_ms: float | None
    max_interval_ms: float | None
    long_intervals: int

    @property
    def loss_percent(self) -> float:
        total = self.received + self.missing
        return 100 * self.missing / total if total else 0.0


@dataclass
class LogAnalysis:
    path: Path
    direction_read: DirectionRead
    parsed: object
    sequences: list[int]
    cycle_model: CycleModel | None
    cycle_results: list[CycleResult]
    gaps: list[Gap]
    duplicates: int
    resets: int
    missing: int
    loss_percent: float

    @property
    def mode(self) -> str:
        return "cycle" if self.cycle_model else "continuous"


@dataclass(frozen=True)
class TimestampTableRow:
    """One complete record in an already-decoded, timestamped table log."""

    line_no: int
    timestamp: datetime
    field_count: int


@dataclass(frozen=True)
class TimestampTableLog:
    """A table log detected without treating its numeric fields as HEX bytes."""

    rows: tuple[TimestampTableRow, ...]
    field_count: int
    invalid_rows: int


@dataclass(frozen=True)
class TimestampGap:
    start: TimestampTableRow
    end: TimestampTableRow
    interval_ms: float
    estimated_missing: int


@dataclass(frozen=True)
class TimestampGapAnalysis:
    """Best-effort timing continuity statistics, deliberately not frame loss."""

    table: TimestampTableLog
    baseline_interval_ms: float | None
    normal_upper_interval_ms: float | None
    threshold_ms: float | None
    gaps: tuple[TimestampGap, ...]
    time_reversals: int

    @property
    def received(self) -> int:
        return len(self.table.rows)

    @property
    def suspected_missing(self) -> int:
        return sum(gap.estimated_missing for gap in self.gaps)

    @property
    def gap_rate_percent(self) -> float:
        total = self.received + self.suspected_missing
        return 100 * self.suspected_missing / total if total else 0.0


def _decode_table_text(raw: bytes) -> str | None:
    """Decode human-readable exports while rejecting raw capture files early."""
    if b"\0" in raw[:4096]:
        return None
    for encoding in ("utf-8-sig", "gb18030", "utf-16"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def detect_timestamp_table(
    path: Path, progress_callback: Callable[[int, int], bool] | None = None,
) -> TimestampTableLog | None:
    """Detect fixed-column rows ending in a full date-and-time timestamp.

    This intentionally requires a strong structural match.  A normal serial
    export with a timestamp prefix or random numbers must remain in the frame
    parser pipeline rather than being misclassified as a table log.
    """
    text = _decode_table_text(path.read_bytes())
    if text is None:
        return None
    lines = text.splitlines()
    rows: list[TimestampTableRow] = []
    nonempty = invalid = 0
    field_counts: dict[int, int] = {}
    for line_no, line in enumerate(lines, start=1):
        if progress_callback and line_no % 128 == 0 and not progress_callback(line_no, max(1, len(lines))):
            raise OperationCancelled()
        if not line.strip():
            continue
        nonempty += 1
        match = TABLE_TIMESTAMP_SUFFIX.search(line)
        if not match:
            invalid += 1
            continue
        try:
            timestamp = datetime.fromisoformat(
                f"{match.group('date').replace('/', '-')} {match.group('time').replace(',', '.')}"
            )
        except ValueError:
            invalid += 1
            continue
        values = line[:match.start()].strip(" \t,;")
        field_count = len([value for value in re.split(r"[\s,;]+", values) if value])
        if field_count < 3:
            invalid += 1
            continue
        rows.append(TimestampTableRow(line_no, timestamp, field_count))
        field_counts[field_count] = field_counts.get(field_count, 0) + 1

    if progress_callback and not progress_callback(len(lines), max(1, len(lines))):
        raise OperationCancelled()
    if len(rows) < 3 or nonempty == 0:
        return None
    field_count, matching_fields = max(field_counts.items(), key=lambda item: item[1])
    # At least 90% of nonblank records must parse and share the same table
    # width.  This leaves a small allowance for headers or damaged lines.
    if len(rows) / nonempty < 0.9 or matching_fields / len(rows) < 0.9:
        return None
    invalid += len(rows) - matching_fields
    stable_rows = tuple(row for row in rows if row.field_count == field_count)
    return TimestampTableLog(stable_rows, field_count, invalid)


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * percentile)]


def analyze_timestamp_gaps(table: TimestampTableLog) -> TimestampGapAnalysis:
    """Estimate time discontinuities without claiming exact protocol loss.

    A robust median is used only as a scale.  The 95th-percentile normal
    interval also contributes to the threshold, which prevents a legitimate
    two-cadence logger from counting its slower cadence as a missing record.
    """
    positive = [
        (right.timestamp - left.timestamp).total_seconds() * 1000
        for left, right in zip(table.rows, table.rows[1:])
        if right.timestamp >= left.timestamp
    ]
    baseline = statistics.median(positive) if positive else None
    # Derive the "normal" upper bound from the central cadence cluster, not
    # from every interval.  Otherwise one genuine long pause in a short file
    # would inflate the 95th percentile enough to hide itself.
    normal_intervals = (
        [interval for interval in positive if baseline * 0.65 <= interval <= baseline * 1.35]
        if baseline and baseline > 0 else []
    )
    normal_upper = _percentile(normal_intervals, 0.95) if normal_intervals else None
    threshold = (
        max(baseline * 1.6, normal_upper * 1.25)
        if baseline and normal_upper and baseline > 0
        else None
    )
    gaps: list[TimestampGap] = []
    reversals = 0
    for left, right in zip(table.rows, table.rows[1:]):
        interval_ms = (right.timestamp - left.timestamp).total_seconds() * 1000
        if interval_ms < 0:
            reversals += 1
            continue
        if threshold is not None and interval_ms > threshold:
            estimated = max(1, int(interval_ms / baseline + 0.5) - 1)
            gaps.append(TimestampGap(left, right, interval_ms, estimated))
    return TimestampGapAnalysis(table, baseline, normal_upper, threshold, tuple(gaps), reversals)


def analyze_timestamp_windows(
    table: TimestampTableLog, analysis: TimestampGapAnalysis, window_seconds: int,
) -> list[TimeWindowResult]:
    """Put rows and timing gaps into the same user-selected time buckets."""
    buckets: dict[datetime, dict] = {}

    def bucket_at(timestamp: datetime) -> dict:
        seconds = timestamp.hour * 3600 + timestamp.minute * 60 + timestamp.second
        bucket_seconds = (seconds // window_seconds) * window_seconds
        start = timestamp.replace(
            hour=bucket_seconds // 3600,
            minute=(bucket_seconds % 3600) // 60,
            second=bucket_seconds % 60,
            microsecond=0,
        )
        return buckets.setdefault(start, {"received": 0, "missing": 0, "intervals": [], "long": 0})

    for row in table.rows:
        bucket_at(row.timestamp)["received"] += 1
    for left, right in zip(table.rows, table.rows[1:]):
        interval_ms = (right.timestamp - left.timestamp).total_seconds() * 1000
        if interval_ms >= 0:
            bucket_at(right.timestamp)["intervals"].append(interval_ms)
    for gap in analysis.gaps:
        bucket = bucket_at(gap.end.timestamp)
        bucket["missing"] += gap.estimated_missing
        bucket["long"] += 1
    return [
        TimeWindowResult(
            start, data["received"], data["missing"],
            statistics.mean(data["intervals"]) if data["intervals"] else None,
            max(data["intervals"]) if data["intervals"] else None,
            data["long"],
        )
        for start, data in sorted(buckets.items())
    ]


def analyze_time_windows(
    evidence: list, sequences: list[int], sequence_size: int, max_sequence_gap: int,
    window_seconds: int = 60,
) -> tuple[float | None, list[TimeWindowResult]]:
    """Group valid RX frames by time and locate sequence gaps / long pauses.

    Only recorded timestamps participate.  Missing sequence numbers are charged
    to the later frame's bucket, making the evidence table and time table agree.
    """
    timestamped = [(item, value) for item, value in zip(evidence, sequences) if item.first_timestamp]
    if len(timestamped) < 2:
        return None, []
    intervals = [
        (right[0].first_timestamp - left[0].first_timestamp).total_seconds() * 1000
        for left, right in zip(timestamped, timestamped[1:])
        if (right[0].first_timestamp - left[0].first_timestamp).total_seconds() >= 0
    ]
    baseline = statistics.median(intervals) if intervals else None
    long_limit = baseline * 3 if baseline and baseline > 0 else None
    buckets: dict[datetime, dict] = {}

    def bucket_at(timestamp: datetime) -> dict:
        # Do not use ``datetime.replace(second=...)`` here: a user may choose
        # 60 seconds or more, and the resulting second field would be invalid.
        # Bucket relative to midnight instead, so every value from 1 to 3600 s
        # has a stable, displayable start time.
        seconds_since_midnight = timestamp.hour * 3600 + timestamp.minute * 60 + timestamp.second
        bucket_seconds = (seconds_since_midnight // window_seconds) * window_seconds
        start = timestamp.replace(
            hour=bucket_seconds // 3600,
            minute=(bucket_seconds % 3600) // 60,
            second=bucket_seconds % 60,
            microsecond=0,
        )
        return buckets.setdefault(start, {"received": 0, "missing": 0, "intervals": [], "long": 0})

    modulus = 1 << (8 * sequence_size)
    previous_item = previous_value = None
    for item, value in timestamped:
        bucket = bucket_at(item.first_timestamp)
        bucket["received"] += 1
        if previous_item is not None:
            interval = (item.first_timestamp - previous_item.first_timestamp).total_seconds() * 1000
            if interval >= 0:
                bucket["intervals"].append(interval)
                if long_limit is not None and interval > long_limit:
                    bucket["long"] += 1
            # A descending value begins a newly captured cycle (or a device
            # restart).  It is never evidence of all the values between the
            # two cycles being lost, so leave that boundary out of the time
            # bucket loss count.  Normal ascending sequence gaps still use
            # modular arithmetic to keep the existing gap definition.
            advance = (value - previous_value) % modulus
            if value >= previous_value and 2 <= advance <= max_sequence_gap + 1:
                bucket["missing"] += advance - 1
        previous_item, previous_value = item, value
    results = [
        TimeWindowResult(
            start, data["received"], data["missing"],
            statistics.mean(data["intervals"]) if data["intervals"] else None,
            max(data["intervals"]) if data["intervals"] else None, data["long"],
        )
        for start, data in sorted(buckets.items())
    ]
    return baseline, results


def analyze_log(
    path: Path, frame_config, sequence_offset: int, sequence_size: int, endian: str,
    max_sequence_gap: int, min_coverage: float = 0.5,
    expected_start: int | None = None, expected_count: int | None = None,
) -> LogAnalysis:
    """Run the same RX-only analysis used by the GUI, for batch comparison."""
    from frame_parser import parse_chunks

    direction_read = read_directional_chunks(path)
    chunks = direction_read.rx_chunks if (direction_read.direction_markers_found or direction_read.raw_binary_receive) else direction_read.unknown_chunks
    parsed = parse_chunks(chunks, frame_config)
    sequences = [int.from_bytes(frame[sequence_offset : sequence_offset + sequence_size], endian) for frame in parsed.frames]
    if not sequences:
        raise ValueError("没有找到完整帧")
    cyclic = analyze_cycles(sequences, min_coverage, expected_start, expected_count)
    if cyclic:
        model, cycles = cyclic
        included = [cycle for cycle in cycles if cycle.included]
        missing = sum(cycle.missing for cycle in included)
        received = sum(cycle.received for cycle in included)
        rate = 100 * missing / (received + missing) if received + missing else 0.0
        return LogAnalysis(path, direction_read, parsed, sequences, model, cycles, [], 0, 0, missing, rate)

    modulus = 1 << (8 * sequence_size)
    gaps: list[Gap] = []
    duplicates = resets = 0
    for previous, current in zip(sequences, sequences[1:]):
        advance = (current - previous) % modulus
        if advance == 0:
            duplicates += 1
        elif advance == 1:
            continue
        elif advance - 1 <= max_sequence_gap:
            gaps.append(Gap(previous, (previous + 1) % modulus, (current - 1) % modulus, advance - 1))
        else:
            resets += 1
    missing = sum(gap.count for gap in gaps)
    rate = 100 * missing / (len(sequences) + missing) if sequences else 0.0
    return LogAnalysis(path, direction_read, parsed, sequences, None, [], gaps, duplicates, resets, missing, rate)


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


def _is_raw_binary_capture(sample: bytes) -> bool:
    """Recognize SSCOM's direct 'receive to file' binary output.

    A text export can contain non-ASCII direction glyphs, so high-bit bytes
    alone are not a safe signal.  NUL/control-heavy content is, and lets raw
    protocol frames bypass the text/HEX tokenizer completely.
    """
    if not sample:
        return False
    nul_ratio = sample.count(0) / len(sample)
    control_ratio = sum(byte < 9 or 14 <= byte < 32 or byte == 127 for byte in sample) / len(sample)
    return nul_ratio >= 0.01 or control_ratio >= 0.10


def read_directional_chunks(
    path: Path, progress_callback: Callable[[int, int], bool] | None = None,
) -> DirectionRead:
    """Read SSCOM logs while preserving RX/TX evidence and timestamps.

    An unmarked continuation line inherits the immediately preceding direction.
    If the whole file has no direction labels it is deliberately marked
    ``unknown`` rather than silently calling it RX; the compatibility wrapper
    still returns those bytes for plain HEX logs.
    """
    from frame_parser import OperationCancelled, RxChunk

    result = DirectionRead()
    total_bytes = path.stat().st_size
    with path.open("rb") as source:
        sample = source.read(min(total_bytes, 65536))
    if _is_raw_binary_capture(sample):
        # SSCOM names its direct receive saves ReceivedTofile-COMx-*.DAT.
        # That filename is sufficient evidence to treat this raw byte stream
        # as RX; other binary DAT files remain explicitly direction-unknown.
        raw_receive = path.name.lower().startswith("receivedtofile")
        direction = "rx" if raw_receive else "unknown"
        raw = bytearray()
        with path.open("rb") as source:
            while block := source.read(65536):
                raw.extend(block)
                if progress_callback and not progress_callback(len(raw), total_bytes):
                    raise OperationCancelled("log read cancelled by user")
        chunk = RxChunk(bytes(raw), None, 1)
        result.records.append(LoggedChunk(direction, chunk))
        if raw_receive:
            result.rx_chunks.append(chunk)
        else:
            result.unknown_chunks.append(chunk)
        result.raw_binary_capture = True
        result.raw_binary_receive = raw_receive
        return result

    active_direction: str | None = None
    consumed = 0
    with path.open("rb") as source:
        for line_no, raw_line in enumerate(source, start=1):
            consumed += len(raw_line)
            if progress_callback and (line_no == 1 or line_no % 200 == 0 or consumed >= total_bytes):
                if not progress_callback(consumed, total_bytes):
                    raise OperationCancelled("log read cancelled by user")
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
    if not (parsed.direction_markers_found or parsed.raw_binary_receive):
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


def detect_protocol(
    stream: bytes, progress_callback: Callable[[int, int], bool] | None = None,
) -> Detection | None:
    """Suggest a two-byte header, fixed frame size, and sequence field.

    A candidate is useful only when it repeatedly occurs at the same spacing.
    The heuristic intentionally returns None for short/noisy logs instead of
    pretending that a protocol has been identified.
    """
    if len(stream) < 24:
        return None
    positions: dict[bytes, list[int]] = {}
    position_total = max(1, len(stream) - 1)
    for index in range(len(stream) - 1):
        if progress_callback and (index == 0 or index % 4096 == 0 or index + 1 == position_total):
            if not progress_callback(index + 1, position_total):
                raise OperationCancelled("protocol detection cancelled by user")
        positions.setdefault(stream[index : index + 2], []).append(index)

    best: tuple[float, bytes, int] | None = None
    candidates = list(positions.items())
    for candidate_index, (header, offsets) in enumerate(candidates, start=1):
        if progress_callback and (candidate_index == 1 or candidate_index % 256 == 0 or candidate_index == len(candidates)):
            if not progress_callback(candidate_index, len(candidates)):
                raise OperationCancelled("protocol detection cancelled by user")
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
                field_score = _credible_sequence_score(values, size)
                if field_score is not None and (best_seq is None or field_score > best_seq[0]):
                    best_seq = (field_score, offset, size, endian)
    confidence = min(1.0, score / max(3, len(captured) - 1))
    if best_seq is None:
        return Detection(header, frame_size, None, None, None, confidence)
    return Detection(header, frame_size, best_seq[1], best_seq[2], best_seq[3], confidence)


def detect_sequence_field(captured: list[bytes]) -> tuple[int, int, str] | None:
    """Suggest a *credible* sequence field from already extracted frames.

    Measurement values often change gradually too. A few adjacent ``+1``
    values are not enough: prefer no result over a fabricated loss rate.
    """
    if len(captured) < 4:
        return None
    best: tuple[float, int, int, str] | None = None
    shortest = min(map(len, captured))
    for size in (1, 2, 4):
        for offset in range(0, shortest - size + 1):
            for endian in ("little", "big"):
                values = [int.from_bytes(frame[offset : offset + size], endian) for frame in captured]
                score = _credible_sequence_score(values, size)
                if score is not None and (best is None or score > best[0]):
                    best = (score, offset, size, endian)
    if best is None:
        return None
    return best[1], best[2], best[3]


def _credible_sequence_score(values: list[int], size: int) -> float | None:
    """Score a field only if it has counter-like adjacent transitions.

    At least 80% of adjacent values must move forward by one or a small gap;
    repeated and backwards values have independent caps. This rejects a slowly
    changing measurement/register value while allowing occasional lost frames
    and normal modulo wraps.
    """
    if len(values) < 4:
        return None
    modulus = 1 << (size * 8)
    advances = [(right - left) % modulus for left, right in zip(values, values[1:])]
    total = len(advances)
    forward = sum(1 <= advance <= 32 for advance in advances)
    normal = sum(advance == 1 for advance in advances)
    repeats = sum(advance == 0 for advance in advances)
    backwards = sum(advance >= modulus - 32 for advance in advances)
    if forward / total < 0.80 or repeats / total > 0.15 or backwards / total > 0.10:
        return None
    if normal < 3:
        return None
    return normal * 2 + (forward - normal)


def analyze_cycles(
    sequences: list[int], min_coverage: float = 0.5,
    expected_start: int | None = None, expected_count: int | None = None,
) -> tuple[CycleModel, list[CycleResult]] | None:
    """Analyze ascending sweeps without turning partial logs into a tiny cycle.

    A decrease is a *candidate* boundary.  The sequence domain is accepted
    only when at least two broad sweeps independently show the same outer
    range.  This fixes the common failure mode where several short fragments
    make a span of 5 look more frequent than the real 1..86 cycle.
    """
    if not 0 < min_coverage <= 1:
        raise ValueError("min_coverage must be in (0, 1]")
    if len(sequences) < 2:
        return None
    groups: list[list[int]] = [[]]
    for value in sequences:
        if groups[-1] and value < groups[-1][-1]:
            groups.append([])
        groups[-1].append(value)
    groups = [group for group in groups if group]
    if expected_count is not None:
        if expected_count < 2 or expected_start is None:
            raise ValueError("manual cycle needs start and count")
        first, last, expected, evidence_cycles = expected_start, expected_start + expected_count - 1, expected_count, 0
    else:
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
                index, received, expected, len(missing_values), received >= expected * min_coverage,
                min(group), max(group), len(group) - len(unique), missing_values,
            )
        )
    return CycleModel(first, last, expected, evidence_cycles), results


def detect_modbus_rtu(
    chunks: list, progress_callback: Callable[[int, int], bool] | None = None,
) -> tuple[list[bytes], object] | None:
    """Return verified Modbus RTU frames when CRC establishes the profile."""
    from frame_parser import CrcKind, FrameConfig, FrameProtocol, parse_chunks

    if not chunks:
        return None
    parsed = parse_chunks(
        chunks, FrameConfig(protocol=FrameProtocol.MODBUS_RTU, crc=CrcKind.MODBUS), progress_callback,
    )
    # Do not label random data as Modbus: at least three CRC-valid frames and
    # at least 80% of logged receive records must be explained.
    if len(parsed.frames) < 3 or len(parsed.frames) < len(chunks) * 0.8:
        return None
    return parsed.frames, parsed


def _modbus_key(data: bytes, is_request: bool) -> tuple[int, int, int | None] | None:
    """Find a Modbus command key plus its expected/actual response size.

    For read-holding/read-input-register commands (03/04), a request's
    register count predicts the response byte-count.  Checking it prevents a
    response for a different read command from satisfying the oldest request.
    """
    candidates: list[tuple[int, int, tuple[int, int, int | None]]] = []
    for index in range(max(0, len(data) - 1)):
        address, function = data[index], data[index + 1] & 0x7F
        if 1 <= address <= 247 and 1 <= function <= 0x7F:
            byte_count = None
            confidence = 1
            if function in (0x03, 0x04):
                if is_request and len(data) >= index + 6:
                    register_count = int.from_bytes(data[index + 4 : index + 6], "big")
                    if 1 <= register_count <= 125:
                        byte_count = register_count * 2
                        confidence = 3
                elif not is_request and len(data) >= index + 3:
                    byte_count = data[index + 2]
                    # A byte-count must be even for a 03/04 register reply.
                    if byte_count and byte_count % 2 == 0:
                        confidence = 3
            candidates.append((confidence, -index, (address, function, byte_count)))
    if not candidates:
        return None
    # Some SSCOM logs add transport bytes before the actual Modbus message.
    # Prefer a complete 03/04 request/reply over an incidental byte pair in
    # that wrapper, then prefer the earliest equally credible candidate.
    return max(candidates)[2]


def match_transactions(direction_read: DirectionRead, timeout_ms: int | None = 1500) -> TransactionSummary:
    """Pair TX requests with later RX replies, preferring the Modbus command key.

    A matching address/function pair is required when both records look like
    Modbus.  This avoids treating an unrelated response as the answer to the
    oldest request when a log contains more than one command type.
    """
    waiting: list[tuple[object, tuple[int, int, int | None] | None]] = []
    paired = orphan = key_confirmed = timed_out = 0
    eligible_sent = eligible_paired = 0
    latencies: list[float] = []
    for record in direction_read.records:
        if record.direction == "tx":
            key = _modbus_key(record.chunk.data, is_request=True)
            waiting.append((record.chunk, key))
            eligible_sent += int(key is not None)
        elif record.direction == "rx":
            while (
                waiting and timeout_ms is not None and waiting[0][0].timestamp and record.chunk.timestamp
                and (record.chunk.timestamp - waiting[0][0].timestamp).total_seconds() * 1000 > timeout_ms
            ):
                waiting.pop(0)
                timed_out += 1
            if not waiting:
                orphan += 1
                continue
            rx_key = _modbus_key(record.chunk.data, is_request=False)
            match_index = next((
                index for index, (_tx, tx_key) in enumerate(waiting)
                if (
                    rx_key is not None and tx_key is not None
                    and tx_key[:2] == rx_key[:2]
                    and (tx_key[2] is None or rx_key[2] is None or tx_key[2] == rx_key[2])
                )
            ), None)
            if match_index is None:
                # Preserve generic chronology pairing for non-Modbus logs, but
                # do not claim it as a command-confirmed response.
                if rx_key is not None and any(tx_key is not None for _tx, tx_key in waiting):
                    orphan += 1
                    continue
                match_index = 0
            tx, tx_key = waiting.pop(match_index)
            paired += 1
            if tx_key is not None and rx_key is not None and tx_key[:2] == rx_key[:2] and (
                tx_key[2] is None or rx_key[2] is None or tx_key[2] == rx_key[2]
            ):
                key_confirmed += 1
                eligible_paired += 1
            if tx.timestamp and record.chunk.timestamp:
                elapsed = (record.chunk.timestamp - tx.timestamp).total_seconds() * 1000
                if elapsed >= 0:
                    latencies.append(elapsed)
    return TransactionSummary(
        len(direction_read.tx_chunks), len(direction_read.rx_chunks), paired,
        len(waiting) + timed_out, timed_out, orphan, key_confirmed, tuple(latencies),
        eligible_sent, eligible_paired,
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
