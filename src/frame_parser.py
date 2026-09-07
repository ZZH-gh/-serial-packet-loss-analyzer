"""Evidence-producing stream parser for UART/serial logs.

Receive chunks are arbitrary driver/log boundaries: a valid frame may span any
number of chunks.  Only a validated complete frame is emitted as a frame.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CrcKind(str, Enum):
    NONE = "none"
    MODBUS = "crc16-modbus"
    CCITT = "crc16-ccitt"


@dataclass(frozen=True)
class FrameConfig:
    header: bytes
    fixed_length: int | None = None
    length_offset: int | None = None
    length_size: int = 1
    length_endian: str = "little"
    length_adjust: int = 0
    crc: CrcKind = CrcKind.NONE
    crc_endian: str = "little"
    max_frame_gap_ms: int | None = None

    def frame_length(self, data: bytes) -> int | None:
        if self.fixed_length is not None:
            return self.fixed_length
        if self.length_offset is None:
            raise ValueError("configure either fixed_length or length_offset")
        end = self.length_offset + self.length_size
        if len(data) < end:
            return None
        return int.from_bytes(data[self.length_offset:end], self.length_endian) + self.length_adjust


@dataclass(frozen=True)
class RxChunk:
    data: bytes
    timestamp: datetime | None = None
    line_no: int = 0


@dataclass(frozen=True)
class ParseEvent:
    kind: str
    received: int = 0
    expected: int | None = None
    detail: str = ""


@dataclass
class ParseResult:
    frames: list[bytes] = field(default_factory=list)
    events: list[ParseEvent] = field(default_factory=list)
    noise_bytes: int = 0

    @property
    def crc_errors(self) -> int:
        return sum(event.kind == "crc_error" for event in self.events)

    @property
    def truncations(self) -> int:
        return sum(event.kind == "truncated" for event in self.events)


def crc16_modbus(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ 0xA001 if value & 1 else value >> 1
    return value & 0xFFFF


def crc16_ccitt(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else (value << 1) & 0xFFFF
    return value


def valid_crc(frame: bytes, config: FrameConfig) -> bool:
    if config.crc is CrcKind.NONE:
        return True
    if len(frame) < 2:
        return False
    expected = int.from_bytes(frame[-2:], config.crc_endian)
    actual = crc16_modbus(frame[:-2]) if config.crc is CrcKind.MODBUS else crc16_ccitt(frame[:-2])
    return actual == expected


def parse_chunks(chunks: list[RxChunk], config: FrameConfig) -> ParseResult:
    if not config.header:
        raise ValueError("header must not be empty")
    result, buffer, pending_at = ParseResult(), bytearray(), None

    def classify_incomplete(reason: str) -> None:
        nonlocal pending_at
        expected = config.frame_length(buffer)
        if buffer.startswith(config.header):
            result.events.append(ParseEvent("truncated", len(buffer), expected, reason))
        buffer.clear()
        pending_at = None

    def consume() -> None:
        nonlocal pending_at
        while buffer:
            start = buffer.find(config.header)
            if start < 0:
                # Preserve a possible partial header at the tail.
                keep = min(len(config.header) - 1, len(buffer))
                dropped = len(buffer) - keep
                if dropped:
                    result.noise_bytes += dropped
                    result.events.append(ParseEvent("noise", dropped, detail="bytes before frame header"))
                    del buffer[:dropped]
                return
            if start:
                result.noise_bytes += start
                result.events.append(ParseEvent("noise", start, detail="bytes before frame header"))
                del buffer[:start]
            expected = config.frame_length(buffer)
            if expected is None:
                return
            if expected < len(config.header) + (2 if config.crc is not CrcKind.NONE else 0):
                result.events.append(ParseEvent("invalid_length", len(buffer), expected))
                del buffer[0]
                continue
            if len(buffer) < expected:
                later = buffer.find(config.header, 1)
                if later > 0:
                    result.events.append(ParseEvent("truncated", later, expected, "next header before expected tail"))
                    del buffer[:later]
                    continue
                return
            frame = bytes(buffer[:expected])
            if valid_crc(frame, config):
                result.frames.append(frame)
                del buffer[:expected]
                pending_at = None
            else:
                result.events.append(ParseEvent("crc_error", expected, expected, "resynchronizing one byte"))
                del buffer[0]

    for chunk in chunks:
        if buffer and pending_at and chunk.timestamp and config.max_frame_gap_ms is not None:
            elapsed = (chunk.timestamp - pending_at).total_seconds() * 1000
            if elapsed > config.max_frame_gap_ms:
                classify_incomplete(f"frame gap {elapsed:.1f} ms exceeds limit")
        buffer.extend(chunk.data)
        pending_at = chunk.timestamp or pending_at
        consume()
    if buffer:
        classify_incomplete("end of log")
    return result
