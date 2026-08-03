from __future__ import annotations

import pytest

from poc_http_extractor import PocHttpExtractionError, extract_http_request


def test_extracts_requests_json_without_executing_source() -> None:
    source = '''
import requests

target = "http://victim.local:8080"
payload = {"cmd": "id;cat /etc/passwd"}
raise RuntimeError("must never execute")
requests.post(f"{target}/api/run", json=payload, headers={"X-Test": "poc"})
'''

    result = extract_http_request(source)

    assert result.accepted is True
    assert result.selected.method == "POST"
    assert result.selected.path == "/api/run"
    assert b"Host: victim.local:8080" in result.selected.raw_request
    assert b'Content-Type: application/json' in result.selected.raw_request
    assert b'{"cmd":"id;cat /etc/passwd"}' in result.selected.raw_request


def test_extracts_framework_target_and_form_body() -> None:
    source = '''
from pocsuite3.api import requests

class Demo:
    def _verify(self):
        path = "/cgi-bin/export"
        data = {"pdfUrl": "file:///etc/passwd"}
        return requests.post(self.url + path, data=data)
'''

    result = extract_http_request(source)

    assert result.selected.path == "/cgi-bin/export"
    assert result.selected.host == "target.local"
    assert b"pdfUrl=file%3A%2F%2F%2Fetc%2Fpasswd" in result.selected.body
    assert "self.url" in result.selected.unresolved
    assert result.accepted is True


def test_prefers_exploit_request_in_multi_step_poc() -> None:
    source = '''
import requests

session = requests.Session()
session.post("http://target.local/login", data={"username": "admin", "password": "admin"})
session.get("http://target.local/cgi-bin/.%2e/.%2e/.%2e/etc/passwd")
'''

    result = extract_http_request(source)

    assert len(result.candidates) == 2
    assert result.selected.method == "GET"
    assert ".%2e" in result.selected.path
    assert result.warnings


def test_extracts_urllib_request_object() -> None:
    source = '''
from urllib.request import Request, urlopen

req = Request(
    "http://target.local/xml",
    data=b"<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    headers={"Content-Type": "application/xml"},
    method="POST",
)
urlopen(req)
'''

    result = extract_http_request(source)

    assert result.selected.client == "urllib.request"
    assert result.selected.path == "/xml"
    assert b"<!ENTITY xxe" in result.selected.body


def test_extracts_raw_socket_http() -> None:
    source = '''
import socket

s = socket.socket()
raw = b"GET /download?file=../etc/passwd HTTP/1.1\\r\\nHost: target.local\\r\\n\\r\\n"
s.sendall(raw)
'''

    result = extract_http_request(source)

    assert result.selected.client == "socket"
    assert result.selected.path == "/download?file=../etc/passwd"
    assert result.selected.confidence == 0.99


def test_rejects_code_without_materializable_http_request() -> None:
    with pytest.raises(PocHttpExtractionError) as error:
        extract_http_request("print('not an HTTP PoC')")

    assert error.value.code == "POC_HTTP_NO_REQUEST"
