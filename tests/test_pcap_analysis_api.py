from __future__ import annotations

import base64
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import rdpcap, wrpcap

from generate_pcap import PcapConfig, generate_pcap
from web_app import app


def _two_connection_capture(tmp_path: Path) -> Path:
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"
    combined = tmp_path / "two-connections.pcap"
    request = b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    generate_pcap(str(first), request, response)
    generate_pcap(
        str(second),
        request,
        response,
        config=PcapConfig(client_initial_seq=50_000, server_initial_seq=90_000),
    )
    packets = list(rdpcap(str(first))) + list(rdpcap(str(second)))
    wrpcap(str(combined), packets)
    return combined


def test_uploaded_pcap_returns_tcp_connection_count(tmp_path: Path) -> None:
    capture = _two_connection_capture(tmp_path)
    client = TestClient(app)

    response = client.post(
        "/api/pcap/analyze",
        json={
            "filename": capture.name,
            "content_base64": base64.b64encode(capture.read_bytes()).decode("ascii"),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["connection_count"] == 2
    assert result["summary"]["tcp_streams"] == 2
    assert result["summary"]["complete_handshakes"] == 2
    assert result["file"]["name"] == "two-connections.pcap"
    assert len(result["streams"]) == 2


def test_uploaded_pcap_rejects_invalid_capture_and_base64() -> None:
    client = TestClient(app)

    malformed = client.post(
        "/api/pcap/analyze",
        json={
            "filename": "broken.pcap",
            "content_base64": base64.b64encode(b"pcap").decode("ascii"),
        },
    )
    invalid_base64 = client.post(
        "/api/pcap/analyze",
        json={"filename": "broken.pcap", "content_base64": "not-base64!"},
    )

    assert malformed.status_code == 422
    assert malformed.json()["detail"]["code"] == "INVALID_CAPTURE"
    assert invalid_base64.status_code == 422
    assert "Base64" in invalid_base64.json()["detail"]
