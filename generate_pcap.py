"""根据完整 HTTP 报文构造可复现的 TCP PCAP。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address
from math import isfinite
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


_TCP_SEQUENCE_MODULUS = 2**32
_HEADER_BODY_SEPARATOR_RE = re.compile(r"(?:\r\n|\r|\n)(?:\r\n|\r|\n)")
_CONTENT_LENGTH_HEADER_RE = re.compile(
    r"^[ \t]*content-length[ \t]*:",
    flags=re.IGNORECASE | re.MULTILINE,
)
_CONTENT_LENGTH_RE = re.compile(
    r"^(?P<prefix>[ \t]*content-length[ \t]*:[ \t]*)"
    r"(?P<value>[0-9]+)(?P<suffix>[ \t]*)$",
    flags=re.IGNORECASE | re.MULTILINE,
)
_TRANSFER_ENCODING_RE = re.compile(
    r"^[ \t]*transfer-encoding[ \t]*:",
    flags=re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class PcapConfig:
    """生成 TCP 流时使用的网络参数和序列化配置。"""

    # 使用文档保留地址模拟外部客户端，与默认 EXTERNAL_NET/HOME_NET 方向一致。
    client_ip: str = "198.51.100.10"
    server_ip: str = "192.168.10.20"
    client_mac: str = "00:11:22:33:44:55"
    server_mac: str = "66:77:88:99:aa:bb"
    client_port: int = 49152
    server_port: int = 80
    client_initial_seq: int = 1000
    server_initial_seq: int = 9000
    timestamp: float = 1_700_000_000.0
    timestamp_step: float = 0.001
    mss: int = 1460

    def __post_init__(self) -> None:
        for name in ("client_ip", "server_ip"):
            value = getattr(self, name)
            try:
                IPv4Address(value)
            except ValueError as exc:
                raise ValueError(f"{name} 必须是有效的 IPv4 地址") from exc
        if self.client_ip == self.server_ip:
            raise ValueError("client_ip 和 server_ip 不能相同")

        for name in ("client_port", "server_port"):
            value = getattr(self, name)
            if not 1 <= value <= 65535:
                raise ValueError(f"{name} 必须在 1 到 65535 之间")

        for name in ("client_initial_seq", "server_initial_seq"):
            value = getattr(self, name)
            if not 0 <= value < _TCP_SEQUENCE_MODULUS:
                raise ValueError(f"{name} 必须是无符号 32 位整数")

        if self.mss <= 0:
            raise ValueError("mss 必须大于 0")
        if not isfinite(self.timestamp):
            raise ValueError("timestamp 必须是有限数值")
        if not isfinite(self.timestamp_step) or self.timestamp_step <= 0:
            raise ValueError("timestamp_step 必须是大于 0 的有限数值")


def _sync_content_length(header: str, body: bytes) -> str:
    """让文本模式的 Content-Length 与最终 body 一致。"""
    content_length_headers = list(_CONTENT_LENGTH_HEADER_RE.finditer(header))
    if _TRANSFER_ENCODING_RE.search(header):
        raise ValueError(
            "文本输入不支持 Transfer-Encoding，请使用 bytes/Base64 原文输入"
        )
    if len(content_length_headers) > 1:
        raise ValueError(
            "文本输入包含多个 Content-Length，请使用 bytes/Base64 原文输入"
        )
    if not content_length_headers:
        return header

    matches = list(_CONTENT_LENGTH_RE.finditer(header))
    if len(matches) != 1:
        raise ValueError("Content-Length 必须是非负十进制整数")

    match = matches[0]
    return (
        header[: match.start("value")]
        + str(len(body))
        + header[match.end("value") :]
    )


def http_text_to_bytes(message: str) -> bytes:
    """把粘贴的 HTTP 文本转换为结构完整的 UTF-8 HTTP 报文。"""
    if not message:
        return b""

    separator = _HEADER_BODY_SEPARATOR_RE.search(message)
    if separator:
        header = message[: separator.start()]
        body_bytes = message[separator.end() :].encode("utf-8")
    else:
        header, body_bytes = message, b""

    header = header.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    header = _sync_content_length(header, body_bytes)
    header_bytes = header.replace("\n", "\r\n").encode("utf-8")
    return header_bytes + b"\r\n\r\n" + body_bytes


def _to_bytes(message: str | bytes) -> bytes:
    """bytes 原样返回；文本输入按 HTTP 语义规范化。"""
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return http_text_to_bytes(message)
    raise TypeError("HTTP 报文必须是 str 或 bytes")


def _advance(sequence: int, amount: int) -> int:
    return (sequence + amount) % _TCP_SEQUENCE_MODULUS


def _segments(payload: bytes, mss: int) -> list[bytes]:
    return [payload[offset : offset + mss] for offset in range(0, len(payload), mss)]


def generate_pcap(
    output_file: str,
    request: str | bytes,
    response: str | bytes,
    *,
    config: PcapConfig | None = None,
) -> Path:
    """生成可复现的 HTTP-over-TCP 流量包。

    ``request`` 和 ``response`` 必须是完整 HTTP 报文。bytes 输入会原样写入
    TCP payload；str 输入会把 header 统一为 CRLF、补齐缺失的头体分隔符，保留
    body 内容，并同步唯一的 Content-Length。分块编码、重复 Content-Length 或
    需要逐字节保真时应传入 bytes。
    """
    flow = config or PcapConfig()
    request_bytes = _to_bytes(request)
    response_bytes = _to_bytes(response)
    packets = []

    def add_packet(
        *,
        from_client: bool,
        flags: str,
        seq: int,
        ack: int = 0,
        payload: bytes = b"",
    ) -> None:
        if from_client:
            ethernet = Ether(src=flow.client_mac, dst=flow.server_mac)
            internet = IP(src=flow.client_ip, dst=flow.server_ip)
            source_port, destination_port = flow.client_port, flow.server_port
        else:
            ethernet = Ether(src=flow.server_mac, dst=flow.client_mac)
            internet = IP(src=flow.server_ip, dst=flow.client_ip)
            source_port, destination_port = flow.server_port, flow.client_port

        packet = ethernet / internet / TCP(
            sport=source_port,
            dport=destination_port,
            flags=flags,
            seq=seq,
            ack=ack,
            window=64240,
        )
        if payload:
            packet /= Raw(load=payload)

        packet[IP].id = len(packets) + 1
        packet.time = flow.timestamp + len(packets) * flow.timestamp_step
        packets.append(packet)

    client_seq = flow.client_initial_seq
    server_seq = flow.server_initial_seq

    # TCP 三次握手。
    add_packet(from_client=True, flags="S", seq=client_seq)
    add_packet(
        from_client=False,
        flags="SA",
        seq=server_seq,
        ack=_advance(client_seq, 1),
    )
    client_seq = _advance(client_seq, 1)
    server_seq = _advance(server_seq, 1)
    add_packet(from_client=True, flags="A", seq=client_seq, ack=server_seq)

    request_segments = _segments(request_bytes, flow.mss)
    for index, segment in enumerate(request_segments):
        flags = "PA" if index == len(request_segments) - 1 else "A"
        add_packet(
            from_client=True,
            flags=flags,
            seq=client_seq,
            ack=server_seq,
            payload=segment,
        )
        client_seq = _advance(client_seq, len(segment))

    if request_segments:
        add_packet(
            from_client=False,
            flags="A",
            seq=server_seq,
            ack=client_seq,
        )

    response_segments = _segments(response_bytes, flow.mss)
    for index, segment in enumerate(response_segments):
        flags = "PA" if index == len(response_segments) - 1 else "A"
        add_packet(
            from_client=False,
            flags=flags,
            seq=server_seq,
            ack=client_seq,
            payload=segment,
        )
        server_seq = _advance(server_seq, len(segment))

    if response_segments:
        add_packet(
            from_client=True,
            flags="A",
            seq=client_seq,
            ack=server_seq,
        )

    # 使用四个 TCP 包完整关闭连接。
    add_packet(
        from_client=True,
        flags="FA",
        seq=client_seq,
        ack=server_seq,
    )
    client_seq = _advance(client_seq, 1)
    add_packet(
        from_client=False,
        flags="A",
        seq=server_seq,
        ack=client_seq,
    )
    add_packet(
        from_client=False,
        flags="FA",
        seq=server_seq,
        ack=client_seq,
    )
    server_seq = _advance(server_seq, 1)
    add_packet(
        from_client=True,
        flags="A",
        seq=client_seq,
        ack=server_seq,
    )

    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path
