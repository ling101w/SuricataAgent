from __future__ import annotations

import json
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qs
from xml.etree import ElementTree

import pytest

import traffic_cases
from rule_compiler import SemanticRequestChange, SemanticTestcase
from traffic_cases import (
    TrafficDerivation,
    TrafficSampleList,
    build_traffic_matrix,
    materialize_semantic_testcases,
    derive_http_cases,
    derive_http_cases_with_diagnostics,
    parse_http_request,
)


_RESPONSE = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"


def _request(
    body: bytes,
    *headers: str,
    include_length: bool = True,
) -> bytes:
    lines = [b"POST /api/read HTTP/1.1", b"Host: example.invalid"]
    lines.extend(header.encode("latin-1") for header in headers)
    if include_length:
        lines.append(f"Content-Length: {len(body)}".encode("ascii"))
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _cases(derivation: TrafficDerivation):
    return {
        name: (expected, raw_request, mss)
        for name, expected, _reason, raw_request, _response, mss in derivation.cases
    }


def _assert_content_length(raw_request: bytes) -> None:
    parsed = parse_http_request(raw_request)
    lengths = [
        value
        for name, value in parsed.headers
        if name.casefold() == "content-length"
    ]
    assert lengths == [str(len(parsed.body))]


def _multipart_fields(raw_request: bytes) -> dict[str, str]:
    parsed = parse_http_request(raw_request)
    content_type = next(
        value
        for name, value in parsed.headers
        if name.casefold() == "content-type"
    )
    envelope = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
            "latin-1"
        )
        + parsed.body
    )
    message = BytesParser(policy=policy.HTTP).parsebytes(envelope)
    assert message.is_multipart()
    fields: dict[str, str] = {}
    for part in message.iter_parts():
        assert isinstance(part, Message)
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or part.get_filename() is not None:
            continue
        payload = part.get_payload(decode=True)
        assert payload is not None
        fields[name] = payload.decode(part.get_content_charset() or "utf-8")
    return fields


def test_json_mutations_keep_positive_semantics_and_change_negative_field() -> None:
    document = {"mode": "raw", "path": "../../etc/passwd"}
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    derivation = derive_http_cases_with_diagnostics(
        _request(body, "Content-Type: application/json; charset=utf-8"),
        _RESPONSE,
    )
    cases = _cases(derivation)

    assert derivation.skips == ()
    positive = cases["positive-body-json-value-encoded"][1]
    negative = cases["negative-body-json-benign-value"][1]
    assert json.loads(parse_http_request(positive).body) == document
    assert json.loads(parse_http_request(negative).body)["path"] == (
        "documents/report.pdf"
    )
    for name, (_expected, raw_request, _mss) in cases.items():
        if "body-json" in name:
            _assert_content_length(raw_request)


def test_form_mutations_keep_positive_semantics_and_change_negative_field() -> None:
    body = b"mode=raw&path=../../etc/passwd"
    derivation = derive_http_cases_with_diagnostics(
        _request(body, "Content-Type: application/x-www-form-urlencoded"),
        _RESPONSE,
    )
    cases = _cases(derivation)

    assert derivation.skips == ()
    positive = parse_qs(
        parse_http_request(cases["positive-body-form-url-encoded"][1]).body.decode()
    )
    negative = parse_qs(
        parse_http_request(cases["negative-body-form-benign-value"][1]).body.decode()
    )
    assert positive["path"] == ["../../etc/passwd"]
    assert negative["path"] == ["documents/report.pdf"]
    for name, (_expected, raw_request, _mss) in cases.items():
        if "body-form" in name:
            _assert_content_length(raw_request)


def test_multipart_mutations_keep_positive_semantics_and_change_negative_field() -> None:
    boundary = "----traffic-contract"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="mode"\r\n\r\n'
        "raw\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="path"\r\n\r\n'
        "../../etc/passwd\r\n"
        f"--{boundary}--\r\n"
    ).encode("ascii")
    derivation = derive_http_cases_with_diagnostics(
        _request(body, f"Content-Type: multipart/form-data; boundary={boundary}"),
        _RESPONSE,
    )
    cases = _cases(derivation)

    assert derivation.skips == ()
    positive = _multipart_fields(
        cases["positive-body-multipart-boundary-changed"][1]
    )
    negative = _multipart_fields(
        cases["negative-body-multipart-benign-value"][1]
    )
    assert positive["path"] == "../../etc/passwd"
    assert negative["path"] == "documents/report.pdf"
    for name, (_expected, raw_request, _mss) in cases.items():
        if "body-multipart" in name:
            _assert_content_length(raw_request)


def test_xml_mutations_keep_positive_semantics_and_change_negative_field() -> None:
    body = b'<request mode="raw"><path>../../etc/passwd</path></request>'
    derivation = derive_http_cases_with_diagnostics(
        _request(body, "Content-Type: application/xml; charset=utf-8"),
        _RESPONSE,
    )
    cases = _cases(derivation)

    assert derivation.skips == ()
    positive_body = parse_http_request(
        cases["positive-body-xml-character-reference"][1]
    ).body
    negative_body = parse_http_request(
        cases["negative-body-xml-benign-value"][1]
    ).body
    assert ElementTree.fromstring(positive_body).findtext("path") == "../../etc/passwd"
    assert ElementTree.fromstring(negative_body).findtext("path") == (
        "documents/report.pdf"
    )
    for name, (_expected, raw_request, _mss) in cases.items():
        if "body-xml" in name:
            _assert_content_length(raw_request)


@pytest.mark.parametrize(
    ("raw_request", "expected_code"),
    [
        pytest.param(
            _request(
                b"1\r\nx\r\n0\r\n\r\n",
                "Content-Type: application/json",
                "Transfer-Encoding: chunked",
                include_length=False,
            ),
            "TRANSFER_ENCODING_UNSUPPORTED",
            id="chunked",
        ),
        pytest.param(
            _request(
                b"compressed",
                "Content-Type: application/json",
                "Content-Encoding: gzip",
            ),
            "CONTENT_ENCODING_UNSUPPORTED",
            id="gzip",
        ),
        pytest.param(
            _request(
                b'{}',
                "Content-Type: application/json",
                "Content-Type: text/plain",
            ),
            "DUPLICATE_CONTENT_TYPE",
            id="duplicate-content-type",
        ),
        pytest.param(
            _request(
                b"<!DOCTYPE request><request><path>../../etc/passwd</path></request>",
                "Content-Type: application/xml",
            ),
            "XML_DTD_UNSUPPORTED",
            id="xml-dtd",
        ),
        pytest.param(
            _request(
                b'<!DOCTYPE request [<!ENTITY x "value">]>'
                b"<request><path>../../etc/passwd</path></request>",
                "Content-Type: application/xml",
            ),
            "XML_ENTITY_UNSUPPORTED",
            id="xml-entity",
        ),
    ],
)
def test_protocol_and_xml_safety_skips_are_explicit(
    raw_request: bytes,
    expected_code: str,
) -> None:
    derivation = derive_http_cases_with_diagnostics(raw_request, _RESPONSE)

    assert [skip.code for skip in derivation.skips] == [expected_code]


@pytest.mark.parametrize(
    ("content_type", "body", "expected_code"),
    [
        ("application/json", b'{"path":', "JSON_PARSE_FAILED"),
        (
            "application/x-www-form-urlencoded",
            b"path=%ZZ",
            "FORM_PARSE_FAILED",
        ),
        (
            "multipart/form-data",
            b"not-a-multipart-body",
            "MULTIPART_BOUNDARY_MISSING",
        ),
        ("application/xml", b"<request>", "XML_PARSE_FAILED"),
    ],
)
def test_declared_format_failure_reports_only_its_own_parser(
    content_type: str,
    body: bytes,
    expected_code: str,
) -> None:
    derivation = derive_http_cases_with_diagnostics(
        _request(body, f"Content-Type: {content_type}"),
        _RESPONSE,
    )

    assert [skip.code for skip in derivation.skips] == [expected_code]


@pytest.mark.parametrize(
    ("raw_response", "expected_code"),
    [
        pytest.param(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 11\r\n\r\nhello world",
            "RESPONSE_EVIDENCE_UNRECOGNIZED",
            id="unrecognized-evidence",
        ),
        pytest.param(
            b"not an http response",
            "RESPONSE_PARSE_FAILED",
            id="malformed-response",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: 4\r\n\r\ngzip",
            "RESPONSE_CONTENT_ENCODING_UNSUPPORTED",
            id="compressed-response",
        ),
        pytest.param(
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Type: text/plain\r\nContent-Length: 5\r\n\r\nerror",
            "RESPONSE_STATUS_UNSUPPORTED",
            id="non-success-response",
        ),
        pytest.param(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            "Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
            "RESPONSE_TRANSFER_ENCODING_UNSUPPORTED",
            id="chunked-text-response",
        ),
    ],
)
def test_response_mutation_failures_are_structured(
    raw_response: str | bytes,
    expected_code: str,
) -> None:
    request = b"GET /download?path=../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"
    derivation = derive_http_cases_with_diagnostics(request, raw_response)

    assert [skip.code for skip in derivation.skips] == [expected_code]


def test_legacy_list_and_matrix_diagnostics_remain_compatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(
        b"compressed",
        "Content-Type: application/json",
        "Content-Encoding: gzip",
    )
    legacy_cases = derive_http_cases(request, _RESPONSE)
    assert type(legacy_cases) is list
    assert legacy_cases

    def fake_generate_pcap(
        output_file: str,
        _request_bytes: bytes,
        _response_bytes: bytes,
        *,
        config: object,
    ) -> Path:
        del config
        return Path(output_file)

    monkeypatch.setattr(traffic_cases, "generate_pcap", fake_generate_pcap)
    samples = build_traffic_matrix(Path(__file__).parent, request, _RESPONSE)

    assert isinstance(samples, TrafficSampleList)
    assert isinstance(samples, list)
    assert [skip.code for skip in samples.skips] == [
        "CONTENT_ENCODING_UNSUPPORTED"
    ]
    assert samples.skips == samples.mutation_skips


def test_matrix_assigns_request_response_and_transaction_oracles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = b"GET /download?path=../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"
    body = (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}".encode("ascii")
        + b"\r\n\r\n"
        + body
    )

    def fake_generate_pcap(
        output_file: str,
        _request_bytes: bytes,
        _response_bytes: bytes,
        *,
        config: object,
    ) -> Path:
        del config
        return Path(output_file)

    monkeypatch.setattr(traffic_cases, "generate_pcap", fake_generate_pcap)
    samples = build_traffic_matrix(tmp_path, request, response)
    targets = {sample.name: sample.validates for sample in samples}

    assert targets["positive-url-encoded"] == "request_detection"
    assert targets["positive-response-passwd-root-only"] == "response_detection"
    assert targets["negative-response-passwd-error-page"] == "response_detection"
    assert (
        targets["negative-transaction-different-endpoint-same-response"]
        == "transaction_specificity"
    )


def test_body_attack_gets_different_endpoint_same_response_hard_negative() -> None:
    request = _request(
        b'{"cmd":"whoami","id":"123"}',
        "Content-Type: application/json",
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        b"Content-Length: 11\r\n\r\nuid=0(root)"
    )

    derivation = derive_http_cases_with_diagnostics(request, response)
    transaction = next(
        case
        for case in derivation.cases
        if case[0] == "negative-transaction-different-endpoint-same-response"
    )

    assert transaction[1] == "no_alert"
    assert transaction[4] == response
    parsed = parse_http_request(transaction[3])
    assert parsed.target == "/not-vulnerable"
    assert parsed.body == b'{"cmd":"whoami","id":"123"}'


def test_uploaded_negative_pcap_is_copied_into_reproducible_sample_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(
        b'{"path":"../../etc/passwd"}',
        "Content-Type: application/json",
    )
    uploaded = tmp_path / "external-negative.pcap"
    uploaded.write_bytes(b"negative-pcap")

    def fake_generate_pcap(
        output_file: str,
        _request_bytes: bytes,
        _response_bytes: bytes,
        *,
        config: object,
    ) -> Path:
        del config
        path = Path(output_file)
        path.write_bytes(b"generated-pcap")
        return path

    monkeypatch.setattr(traffic_cases, "generate_pcap", fake_generate_pcap)
    sample_dir = tmp_path / "samples"
    samples = build_traffic_matrix(
        sample_dir,
        request,
        _RESPONSE,
        uploaded_negative_pcaps=(uploaded,),
    )

    copied = next(sample for sample in samples if sample.source == "uploaded")
    assert copied.pcap_path.parent == sample_dir.resolve()
    assert copied.pcap_path.name == "negative-uploaded-1.pcap"
    assert copied.pcap_path.read_bytes() == b"negative-pcap"


def test_semantic_query_testcases_become_real_positive_and_negative_pcaps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated: list[tuple[Path, bytes, bytes]] = []

    def fake_generate_pcap(
        output_file: str,
        request_bytes: bytes,
        response_bytes: bytes,
        *,
        config: object,
    ) -> Path:
        del config
        path = Path(output_file)
        path.write_bytes(b"pcap")
        generated.append((path, request_bytes, response_bytes))
        return path

    monkeypatch.setattr(traffic_cases, "generate_pcap", fake_generate_pcap)
    samples = materialize_semantic_testcases(
        tmp_path,
        b"GET /view?file=file:///etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        (
            SemanticTestcase(
                "alert",
                (SemanticRequestChange("query", "file", "file:///etc/shadow"),),
                "同类敏感文件读取",
            ),
            SemanticTestcase(
                "no_alert",
                (SemanticRequestChange("query", "file", "https://example.com/a.pdf"),),
                "正常远程 PDF",
            ),
        ),
    )

    assert [sample.expected for sample in samples] == ["alert", "no_alert"]
    assert all(sample.source == "semantic" for sample in samples)
    assert b"file%3A%2F%2F%2Fetc%2Fshadow" in generated[0][1]
    assert b"https%3A%2F%2Fexample.com%2Fa.pdf" in generated[1][1]
    assert generated[0][2].endswith(b"OK")
    assert generated[1][2].endswith(b"OK")


def test_semantic_testcase_cannot_add_unknown_field_without_neutralizing_attack(
    tmp_path: Path,
) -> None:
    samples = materialize_semantic_testcases(
        tmp_path,
        b"GET /view?file=file:///etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
        (
            SemanticTestcase(
                "no_alert",
                (SemanticRequestChange("query", "otherParam", "file:///etc/shadow"),),
                "未知字段",
            ),
        ),
    )

    assert not samples
    assert samples.mutation_skips[0].code == "SEMANTIC_ATTACK_FIELD_NOT_NEUTRALIZED"


def test_semantic_negative_can_move_attack_value_to_unrelated_query_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_requests: list[bytes] = []

    def fake_generate_pcap(
        output_file: str,
        request_bytes: bytes,
        _response_bytes: bytes,
        *,
        config: object,
    ) -> Path:
        del config
        path = Path(output_file)
        path.write_bytes(b"pcap")
        generated_requests.append(request_bytes)
        return path

    monkeypatch.setattr(traffic_cases, "generate_pcap", fake_generate_pcap)
    samples = materialize_semantic_testcases(
        tmp_path,
        b"GET /view?file=file:///etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
        (
            SemanticTestcase(
                "no_alert",
                (
                    SemanticRequestChange("query", "file", "report.pdf"),
                    SemanticRequestChange(
                        "query", "otherParam", "file:///etc/passwd"
                    ),
                ),
                "攻击字符串位于无关字段",
            ),
        ),
    )

    assert len(samples) == 1
    request_line = generated_requests[0].split(b"\r\n", 1)[0]
    assert b"file=report.pdf" in request_line
    assert b"otherParam=file%3A%2F%2F%2Fetc%2Fpasswd" in request_line
