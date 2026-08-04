"""Dependency-free TCP connection analysis for PCAP and PCAPNG captures."""

from __future__ import annotations

import ipaddress
import os
import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO


class CaptureFormatError(ValueError):
    """Raised when a capture is truncated or uses an unsupported format."""


@dataclass(frozen=True, order=True)
class Endpoint:
    ip: str
    port: int

    def text(self) -> str:
        return f"[{self.ip}]:{self.port}" if ":" in self.ip else f"{self.ip}:{self.port}"


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    captured_len: int
    original_len: int
    linktype: int
    data: bytes


@dataclass(frozen=True)
class TcpPacket:
    timestamp: float
    captured_len: int
    src: Endpoint
    dst: Endpoint
    seq: int
    ack_num: int
    flags: int
    payload_len: int
    ip_version: int

    @property
    def syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def ack(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def rst(self) -> bool:
        return bool(self.flags & 0x04)


@dataclass
class TcpStream:
    stream_id: int
    key: tuple[Endpoint, Endpoint]
    first_src: Endpoint
    first_dst: Endpoint
    start_time: float
    end_time: float
    packet_count: int = 0
    captured_bytes: int = 0
    payload_bytes: int = 0
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    client: Endpoint | None = None
    server: Endpoint | None = None
    syn_seq: int | None = None
    synack_seq: int | None = None
    seen_syn: bool = False
    seen_syn_ack: bool = False
    seen_final_ack: bool = False
    seen_rst: bool = False
    fin_sides: set[Endpoint] = field(default_factory=set)
    syn_count: int = 0
    synack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    def add(self, packet: TcpPacket) -> None:
        self.end_time = packet.timestamp
        self.packet_count += 1
        self.captured_bytes += packet.captured_len
        self.payload_bytes += packet.payload_len
        if packet.ip_version == 4:
            self.ipv4_packets += 1
        else:
            self.ipv6_packets += 1

        if packet.ack:
            self.ack_count += 1
        if packet.flags & 0x08:
            self.psh_count += 1
        if packet.fin:
            self.fin_count += 1
            self.fin_sides.add(packet.src)
        if packet.rst:
            self.rst_count += 1
            self.seen_rst = True

        if packet.syn and not packet.ack:
            self.syn_count += 1
            if not self.seen_syn:
                self.client = packet.src
                self.server = packet.dst
                self.syn_seq = packet.seq
                self.seen_syn = True

        if packet.syn and packet.ack:
            self.synack_count += 1
            if self.client is None:
                self.client = packet.dst
                self.server = packet.src
            if packet.src == self.server and packet.dst == self.client:
                if self.syn_seq is None or packet.ack_num == (self.syn_seq + 1) & 0xFFFFFFFF:
                    self.seen_syn_ack = True
                    if self.synack_seq is None:
                        self.synack_seq = packet.seq

        if (
            packet.ack
            and not packet.syn
            and self.seen_syn
            and self.seen_syn_ack
            and self.client is not None
            and packet.src == self.client
            and packet.dst == self.server
            and (
                self.synack_seq is None
                or packet.ack_num == (self.synack_seq + 1) & 0xFFFFFFFF
            )
        ):
            self.seen_final_ack = True

    @property
    def handshake_complete(self) -> bool:
        return self.seen_syn and self.seen_syn_ack and self.seen_final_ack

    @property
    def bidirectional_fin(self) -> bool:
        return len(self.fin_sides) >= 2

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def close_type(self) -> str:
        if self.bidirectional_fin:
            return "bidirectional_fin"
        if self.seen_rst:
            return "rst"
        if self.fin_sides:
            return "one_sided_fin"
        return "not_observed"

    @property
    def status(self) -> str:
        if self.handshake_complete and self.bidirectional_fin:
            return "complete_handshake_and_bidirectional_fin"
        if self.handshake_complete and self.seen_rst:
            return "complete_handshake_and_rst"
        if self.handshake_complete and self.fin_sides:
            return "complete_handshake_and_one_sided_fin"
        if self.handshake_complete:
            return "complete_handshake_without_observed_close"
        if not self.seen_syn:
            return "midstream_without_syn"
        if not self.seen_syn_ack:
            return "incomplete_handshake_missing_syn_ack"
        return "incomplete_handshake_missing_final_ack"

    def public_dict(self) -> dict[str, Any]:
        client = self.client or self.first_src
        server = self.server or self.first_dst
        return {
            "stream_id": self.stream_id,
            "client": client.text(),
            "server": server.text(),
            "client_ip": client.ip,
            "client_port": client.port,
            "server_ip": server.ip,
            "server_port": server.port,
            "packets": self.packet_count,
            "captured_bytes": self.captured_bytes,
            "payload_bytes": self.payload_bytes,
            "duration_seconds": round(self.duration, 6),
            "start_timestamp": self.start_time,
            "end_timestamp": self.end_time,
            "handshake_complete": self.handshake_complete,
            "seen_syn": self.seen_syn,
            "seen_syn_ack": self.seen_syn_ack,
            "seen_final_ack": self.seen_final_ack,
            "close_type": self.close_type,
            "bidirectional_fin": self.bidirectional_fin,
            "seen_rst": self.seen_rst,
            "status": self.status,
            "flags": {
                "syn": self.syn_count,
                "syn_ack": self.synack_count,
                "ack": self.ack_count,
                "fin": self.fin_count,
                "rst": self.rst_count,
                "psh": self.psh_count,
            },
            "ip_versions": {
                "ipv4_packets": self.ipv4_packets,
                "ipv6_packets": self.ipv6_packets,
            },
        }


@dataclass(frozen=True)
class InterfaceInfo:
    linktype: int
    ts_resolution: float = 1e-6
    ts_offset: float = 0.0


def _read_exact(fp: BinaryIO, length: int) -> bytes:
    data = fp.read(length)
    if len(data) != length:
        raise CaptureFormatError("Capture is truncated or incomplete")
    return data


def _iter_pcap(fp: BinaryIO, magic: bytes) -> Iterator[PacketRecord]:
    variants = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    if magic not in variants:
        raise CaptureFormatError("Unsupported PCAP byte order or magic")
    endian, divisor = variants[magic]
    _, _, _, _, _, linktype = struct.unpack(endian + "HHIIII", _read_exact(fp, 20))

    while True:
        header = fp.read(16)
        if not header:
            return
        if len(header) != 16:
            raise CaptureFormatError("Truncated PCAP packet header")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", header)
        if incl_len > 1_073_741_824:
            raise CaptureFormatError("Unreasonably large PCAP packet")
        yield PacketRecord(
            timestamp=ts_sec + ts_frac / divisor,
            captured_len=incl_len,
            original_len=orig_len,
            linktype=linktype,
            data=_read_exact(fp, incl_len),
        )


def _parse_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        if offset + length > len(data):
            break
        options.setdefault(code, []).append(data[offset : offset + length])
        offset += (length + 3) & ~3
    return options


def _iter_pcapng(fp: BinaryIO, first_four: bytes) -> Iterator[PacketRecord]:
    current_endian: str | None = None
    interfaces: list[InterfaceInfo] = []
    block_type_raw = first_four

    while True:
        block_len_raw = _read_exact(fp, 4)
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            bom = _read_exact(fp, 4)
            if bom == b"\x4d\x3c\x2b\x1a":
                current_endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                current_endian = ">"
            else:
                raise CaptureFormatError("Invalid PCAPNG byte-order magic")
            block_len = struct.unpack(current_endian + "I", block_len_raw)[0]
            if block_len < 28 or block_len % 4:
                raise CaptureFormatError("Invalid PCAPNG section length")
            _read_exact(fp, block_len - 16)
            trailer = _read_exact(fp, 4)
            if struct.unpack(current_endian + "I", trailer)[0] != block_len:
                raise CaptureFormatError("PCAPNG block length mismatch")
            interfaces = []
        else:
            if current_endian is None:
                raise CaptureFormatError("PCAPNG section header is missing")
            block_type = struct.unpack(current_endian + "I", block_type_raw)[0]
            block_len = struct.unpack(current_endian + "I", block_len_raw)[0]
            if block_len < 12 or block_len % 4 or block_len > 1_073_741_824:
                raise CaptureFormatError("Invalid PCAPNG block length")
            body = _read_exact(fp, block_len - 12)
            trailer = _read_exact(fp, 4)
            if struct.unpack(current_endian + "I", trailer)[0] != block_len:
                raise CaptureFormatError("PCAPNG block length mismatch")

            if block_type == 1 and len(body) >= 8:
                linktype = struct.unpack_from(current_endian + "H", body, 0)[0]
                options = _parse_options(body[8:], current_endian)
                resolution = 1e-6
                if 9 in options and options[9] and options[9][0]:
                    value = options[9][0][0]
                    resolution = (
                        2.0 ** -(value & 0x7F) if value & 0x80 else 10.0**-value
                    )
                ts_offset = 0.0
                if 14 in options and options[14] and len(options[14][0]) >= 8:
                    ts_offset = float(
                        struct.unpack(current_endian + "q", options[14][0][:8])[0]
                    )
                interfaces.append(InterfaceInfo(linktype, resolution, ts_offset))
            elif block_type == 6 and len(body) >= 20:
                interface_id, ts_high, ts_low, caplen, origlen = struct.unpack_from(
                    current_endian + "IIIII", body, 0
                )
                if interface_id < len(interfaces) and 20 + caplen <= len(body):
                    interface = interfaces[interface_id]
                    ticks = (ts_high << 32) | ts_low
                    yield PacketRecord(
                        timestamp=interface.ts_offset + ticks * interface.ts_resolution,
                        captured_len=caplen,
                        original_len=origlen,
                        linktype=interface.linktype,
                        data=body[20 : 20 + caplen],
                    )
            elif block_type == 3 and len(body) >= 4 and interfaces:
                origlen = struct.unpack_from(current_endian + "I", body, 0)[0]
                caplen = min(origlen, len(body) - 4)
                yield PacketRecord(
                    timestamp=0.0,
                    captured_len=caplen,
                    original_len=origlen,
                    linktype=interfaces[0].linktype,
                    data=body[4 : 4 + caplen],
                )
            elif block_type == 2 and len(body) >= 20:
                interface_id = struct.unpack_from(current_endian + "H", body, 0)[0]
                ts_high, ts_low, caplen, origlen = struct.unpack_from(
                    current_endian + "IIII", body, 4
                )
                if interface_id < len(interfaces) and 20 + caplen <= len(body):
                    interface = interfaces[interface_id]
                    ticks = (ts_high << 32) | ts_low
                    yield PacketRecord(
                        timestamp=interface.ts_offset + ticks * interface.ts_resolution,
                        captured_len=caplen,
                        original_len=origlen,
                        linktype=interface.linktype,
                        data=body[20 : 20 + caplen],
                    )

        block_type_raw = fp.read(4)
        if not block_type_raw:
            return
        if len(block_type_raw) != 4:
            raise CaptureFormatError("Truncated PCAPNG trailer")


def iter_capture(path: str | os.PathLike[str]) -> Iterator[PacketRecord]:
    with open(path, "rb") as fp:
        magic = fp.read(4)
        if len(magic) < 4:
            raise CaptureFormatError("Capture is empty or too short")
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(fp, magic)
        else:
            yield from _iter_pcap(fp, magic)


def _extract_network_payload(data: bytes, linktype: int) -> tuple[int | None, bytes]:
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None, b""
        protocol = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        while protocol in (0x8100, 0x88A8, 0x9100):
            if len(data) < offset + 4:
                return None, b""
            protocol = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        return protocol, data[offset:]
    if linktype == 113:  # Linux cooked v1
        return (struct.unpack_from("!H", data, 14)[0], data[16:]) if len(data) >= 16 else (None, b"")
    if linktype == 276:  # Linux cooked v2
        return (struct.unpack_from("!H", data, 0)[0], data[20:]) if len(data) >= 20 else (None, b"")
    if linktype in (0, 108):  # BSD NULL / LOOP
        payload = data[4:] if len(data) >= 4 else b""
        version = payload[0] >> 4 if payload else 0
        return (0x0800 if version == 4 else 0x86DD if version == 6 else None), payload
    if linktype in (12, 101):  # Raw IP
        version = data[0] >> 4 if data else 0
        return (0x0800 if version == 4 else 0x86DD if version == 6 else None), data
    if linktype == 228:
        return 0x0800, data
    if linktype == 229:
        return 0x86DD, data
    return None, b""


def _decode_ipv4(payload: bytes) -> tuple[str, str, bytes, int] | None:
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    header_len = (payload[0] & 0x0F) * 4
    if header_len < 20 or len(payload) < header_len:
        return None
    total_len = struct.unpack_from("!H", payload, 2)[0]
    if total_len < header_len or struct.unpack_from("!H", payload, 6)[0] & 0x1FFF:
        return None
    return (
        str(ipaddress.ip_address(payload[12:16])),
        str(ipaddress.ip_address(payload[16:20])),
        payload[header_len : min(len(payload), total_len)],
        payload[9],
    )


def _decode_ipv6(payload: bytes) -> tuple[str, str, bytes, int] | None:
    if len(payload) < 40 or payload[0] >> 4 != 6:
        return None
    payload_len = struct.unpack_from("!H", payload, 4)[0]
    next_header = payload[6]
    end = len(payload) if payload_len == 0 else min(len(payload), 40 + payload_len)
    offset = 40
    for _ in range(16):
        if next_header in (0, 43, 60):
            if offset + 2 > end:
                return None
            new_next = payload[offset]
            header_len = (payload[offset + 1] + 1) * 8
            if header_len < 8 or offset + header_len > end:
                return None
        elif next_header == 44:
            if offset + 8 > end:
                return None
            new_next = payload[offset]
            if (struct.unpack_from("!H", payload, offset + 2)[0] >> 3) & 0x1FFF:
                return None
            header_len = 8
        elif next_header == 51:
            if offset + 2 > end:
                return None
            new_next = payload[offset]
            header_len = (payload[offset + 1] + 2) * 4
            if header_len < 8 or offset + header_len > end:
                return None
        else:
            break
        next_header = new_next
        offset += header_len
    return (
        str(ipaddress.ip_address(payload[8:24])),
        str(ipaddress.ip_address(payload[24:40])),
        payload[offset:end],
        next_header,
    )


def decode_tcp(packet: PacketRecord) -> TcpPacket | None:
    protocol, network = _extract_network_payload(packet.data, packet.linktype)
    if protocol == 0x0800:
        decoded = _decode_ipv4(network)
        ip_version = 4
    elif protocol == 0x86DD:
        decoded = _decode_ipv6(network)
        ip_version = 6
    else:
        return None
    if decoded is None:
        return None
    src_ip, dst_ip, transport, next_header = decoded
    if next_header != 6 or len(transport) < 20:
        return None
    src_port, dst_port, seq, ack_num = struct.unpack_from("!HHII", transport, 0)
    data_offset = (transport[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(transport):
        return None
    return TcpPacket(
        timestamp=packet.timestamp,
        captured_len=packet.captured_len,
        src=Endpoint(src_ip, src_port),
        dst=Endpoint(dst_ip, dst_port),
        seq=seq,
        ack_num=ack_num,
        flags=transport[13],
        payload_len=len(transport) - data_offset,
        ip_version=ip_version,
    )


def _canonical_key(src: Endpoint, dst: Endpoint) -> tuple[Endpoint, Endpoint]:
    first, second = sorted((src, dst))
    return first, second


def _should_start_new_stream(current: TcpStream, packet: TcpPacket) -> bool:
    if not (packet.syn and not packet.ack):
        return False
    if (
        current.seen_syn
        and current.client == packet.src
        and current.server == packet.dst
        and current.syn_seq == packet.seq
        and not current.handshake_complete
    ):
        return False
    if current.seen_syn:
        return True
    return current.packet_count > 0


def analyze_capture(path: str | os.PathLike[str], *, filename: str | None = None) -> dict[str, Any]:
    """Analyze one capture and return TCP stream and packet statistics."""
    streams: list[TcpStream] = []
    active: dict[tuple[Endpoint, Endpoint], TcpStream] = {}
    total_packets = 0
    tcp_packets = 0
    non_tcp_packets = 0
    linktypes: set[int] = set()
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    for raw_packet in iter_capture(path):
        total_packets += 1
        linktypes.add(raw_packet.linktype)
        first_timestamp = (
            raw_packet.timestamp
            if first_timestamp is None
            else min(first_timestamp, raw_packet.timestamp)
        )
        last_timestamp = (
            raw_packet.timestamp
            if last_timestamp is None
            else max(last_timestamp, raw_packet.timestamp)
        )
        packet = decode_tcp(raw_packet)
        if packet is None:
            non_tcp_packets += 1
            continue
        tcp_packets += 1
        key = _canonical_key(packet.src, packet.dst)
        current = active.get(key)
        if current is None or _should_start_new_stream(current, packet):
            current = TcpStream(
                stream_id=len(streams),
                key=key,
                first_src=packet.src,
                first_dst=packet.dst,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
            )
            streams.append(current)
            active[key] = current
        current.add(packet)

    file_path = Path(path)
    with file_path.open("rb") as capture_file:
        capture_format = (
            "pcapng" if capture_file.read(4) == b"\x0a\x0d\x0d\x0a" else "pcap"
        )
    stream_rows = [stream.public_dict() for stream in streams]
    return {
        "file": {
            "name": filename or file_path.name,
            "size_bytes": file_path.stat().st_size,
            "format": capture_format,
        },
        "summary": {
            "tcp_streams": len(streams),
            "complete_handshakes": sum(stream.handshake_complete for stream in streams),
            "incomplete_or_midstream": sum(not stream.handshake_complete for stream in streams),
            "midstream_without_syn": sum(not stream.seen_syn for stream in streams),
            "bidirectional_fin_streams": sum(stream.bidirectional_fin for stream in streams),
            "reset_streams": sum(stream.seen_rst for stream in streams),
            "streams_with_payload": sum(stream.payload_bytes > 0 for stream in streams),
            "total_packets": total_packets,
            "tcp_packets": tcp_packets,
            "non_tcp_packets": non_tcp_packets,
            "capture_duration_seconds": round(
                max(0.0, (last_timestamp or 0.0) - (first_timestamp or 0.0)), 6
            ),
            "linktypes": sorted(linktypes),
        },
        "streams": stream_rows,
    }


_TOTAL_FIELDS = (
    "complete_handshakes",
    "incomplete_or_midstream",
    "midstream_without_syn",
    "bidirectional_fin_streams",
    "reset_streams",
    "streams_with_payload",
    "total_packets",
    "tcp_packets",
    "non_tcp_packets",
    "capture_duration_seconds",
)


def analyze_sample_pcaps(samples: Sequence[Any]) -> dict[str, Any]:
    """Analyze every sample PCAP without making analysis failure fatal to a run."""
    cache: dict[Path, tuple[dict[str, Any] | None, str | None]] = {}
    pcaps: list[dict[str, Any]] = []
    totals: dict[str, int | float] = {field: 0 for field in _TOTAL_FIELDS}
    analyzed_pcaps = 0
    failed_pcaps = 0
    tcp_connections = 0
    multi_connection_pcaps = 0

    for sample in samples:
        path = Path(sample.pcap_path).resolve()
        if path not in cache:
            try:
                cache[path] = (analyze_capture(path), None)
            except (OSError, ValueError, struct.error) as exc:
                cache[path] = (None, (str(exc).strip() or exc.__class__.__name__)[:500])
        result, error = cache[path]
        record: dict[str, Any] = {
            "sample_name": sample.name,
            "expected": sample.expected,
            "source": sample.source,
            "analysis_ok": error is None,
            "error": error,
        }
        if result is None:
            failed_pcaps += 1
        else:
            analyzed_pcaps += 1
            record.update(result)
            summary = result["summary"]
            connections = int(summary["tcp_streams"])
            tcp_connections += connections
            multi_connection_pcaps += connections > 1
            for field in _TOTAL_FIELDS:
                totals[field] += summary[field]
        pcaps.append(record)

    return {
        "version": 1,
        "summary": {
            "pcap_count": len(samples),
            "analyzed_pcaps": analyzed_pcaps,
            "failed_pcaps": failed_pcaps,
            "tcp_connections": tcp_connections,
            "multi_connection_pcaps": multi_connection_pcaps,
            **{
                key: round(value, 6) if key == "capture_duration_seconds" else value
                for key, value in totals.items()
            },
        },
        "pcaps": pcaps,
    }


def matrix_tcp_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Return the compact subset included in one sample-matrix row."""
    if not record.get("analysis_ok"):
        return {
            "analysis_ok": False,
            "connection_count": None,
            "error": record.get("error") or "PCAP analysis failed",
        }
    summary = record["summary"]
    return {
        "analysis_ok": True,
        "connection_count": summary["tcp_streams"],
        "complete_handshakes": summary["complete_handshakes"],
        "incomplete_or_midstream": summary["incomplete_or_midstream"],
        "bidirectional_fin_streams": summary["bidirectional_fin_streams"],
        "reset_streams": summary["reset_streams"],
        "tcp_packets": summary["tcp_packets"],
        "capture_duration_seconds": summary["capture_duration_seconds"],
    }
