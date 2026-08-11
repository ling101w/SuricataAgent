from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

from generate_pcap import generate_pcap
from pcap_tcp_analysis import CaptureFormatError, analyze_capture


CLIENT = "198.51.100.10"
SERVER = "192.168.10.20"
CLIENT_PORT = 49152
SERVER_PORT = 80


def _tcp_packet(
    *,
    from_client: bool,
    flags: str,
    seq: int,
    ack: int = 0,
    payload: bytes = b"",
):
    src, dst = (CLIENT, SERVER) if from_client else (SERVER, CLIENT)
    sport, dport = (
        (CLIENT_PORT, SERVER_PORT)
        if from_client
        else (SERVER_PORT, CLIENT_PORT)
    )
    packet = Ether() / IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        seq=seq,
        ack=ack,
    )
    if payload:
        packet /= Raw(payload)
    return packet


def _write_packets(path: Path, packets: list[object]) -> None:
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index * 0.001
    wrpcap(str(path), packets)


def test_complete_connection_is_counted_with_handshake_and_fin(tmp_path: Path) -> None:
    pcap = tmp_path / "complete.pcap"
    generate_pcap(
        str(pcap),
        b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )

    result = analyze_capture(pcap)

    assert result["summary"]["tcp_streams"] == 1
    assert result["summary"]["complete_handshakes"] == 1
    assert result["summary"]["bidirectional_fin_streams"] == 1
    assert result["summary"]["streams_with_payload"] == 1
    assert result["streams"][0]["status"] == (
        "complete_handshake_and_bidirectional_fin"
    )


def test_fresh_syn_reusing_four_tuple_starts_another_connection(tmp_path: Path) -> None:
    pcap = tmp_path / "tuple-reuse.pcap"
    _write_packets(
        pcap,
        [
            _tcp_packet(from_client=True, flags="S", seq=100),
            _tcp_packet(from_client=False, flags="SA", seq=200, ack=101),
            _tcp_packet(from_client=True, flags="A", seq=101, ack=201),
            _tcp_packet(from_client=True, flags="S", seq=900),
        ],
    )

    result = analyze_capture(pcap)

    assert result["summary"]["tcp_streams"] == 2
    assert result["summary"]["complete_handshakes"] == 1


def test_retransmitted_syn_stays_in_the_same_connection(tmp_path: Path) -> None:
    pcap = tmp_path / "syn-retransmission.pcap"
    _write_packets(
        pcap,
        [
            _tcp_packet(from_client=True, flags="S", seq=100),
            _tcp_packet(from_client=True, flags="S", seq=100),
            _tcp_packet(from_client=False, flags="SA", seq=200, ack=101),
            _tcp_packet(from_client=True, flags="A", seq=101, ack=201),
        ],
    )

    result = analyze_capture(pcap)

    assert result["summary"]["tcp_streams"] == 1
    assert result["summary"]["complete_handshakes"] == 1
    assert result["streams"][0]["flags"]["syn"] == 2


def test_midstream_capture_counts_one_incomplete_connection(tmp_path: Path) -> None:
    pcap = tmp_path / "midstream.pcap"
    _write_packets(
        pcap,
        [
            _tcp_packet(
                from_client=True,
                flags="PA",
                seq=101,
                ack=201,
                payload=b"GET / HTTP/1.1\r\n\r\n",
            ),
            _tcp_packet(from_client=False, flags="A", seq=201, ack=119),
        ],
    )

    result = analyze_capture(pcap)

    assert result["summary"]["tcp_streams"] == 1
    assert result["summary"]["midstream_without_syn"] == 1
    assert result["summary"]["incomplete_or_midstream"] == 1


def test_non_tcp_packets_and_malformed_capture_are_reported(tmp_path: Path) -> None:
    udp_pcap = tmp_path / "udp.pcap"
    packet = Ether() / IP(src=CLIENT, dst=SERVER) / UDP(sport=50000, dport=53) / Raw(b"dns")
    _write_packets(udp_pcap, [packet])

    result = analyze_capture(udp_pcap)

    assert result["summary"]["tcp_streams"] == 0
    assert result["summary"]["tcp_packets"] == 0
    assert result["summary"]["non_tcp_packets"] == 1

    malformed = tmp_path / "broken.pcap"
    malformed.write_bytes(b"pcap")
    with pytest.raises(CaptureFormatError):
        analyze_capture(malformed)
