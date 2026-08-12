import json
from urllib.parse import parse_qs

from rule_knowledge import contains_exploit_marker
from traffic_cases import derive_http_cases, parse_http_request, parse_http_response


_RESPONSE = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"


def _request(content_type: str | None, body: bytes) -> bytes:
    headers = [
        b"POST /api/read HTTP/1.1",
        b"Host: example.invalid",
    ]
    if content_type:
        headers.append(f"Content-Type: {content_type}".encode("ascii"))
    headers.append(f"Content-Length: {len(body)}".encode("ascii"))
    return b"\r\n".join(headers) + b"\r\n\r\n" + body


def _case_map(request: bytes):
    return {
        name: (expected, raw_request, mss)
        for name, expected, _reason, raw_request, _response, mss in derive_http_cases(
            request,
            _RESPONSE,
        )
    }


def _assert_content_length(raw_request: bytes) -> None:
    parsed = parse_http_request(raw_request)
    lengths = [
        value
        for name, value in parsed.headers
        if name.lower() == "content-length"
    ]
    assert lengths == [str(len(parsed.body))]


def _assert_response_content_length(raw_response: bytes) -> None:
    parsed = parse_http_response(raw_response)
    lengths = [
        value
        for name, value in parsed.headers
        if name.lower() == "content-length"
    ]
    assert lengths == [str(len(parsed.body))]


def test_json_body_variants_preserve_semantics_and_create_close_negatives() -> None:
    original_document = {"mode": "raw", "path": "../../etc/passwd"}
    body = b'{"mode":"raw","path":"../../etc/passwd"}'
    cases = _case_map(_request("application/json; charset=utf-8", body))

    expected_names = {
        "positive-body-segmented",
        "positive-body-json-whitespace-changed",
        "positive-body-json-key-order-changed",
        "positive-body-json-value-encoded",
        "positive-body-json-extra-field",
        "negative-body-json-benign-value",
        "negative-body-json-value-in-other-field",
        "negative-body-json-different-endpoint",
    }
    assert expected_names <= cases.keys()

    for name in {
        "positive-body-json-whitespace-changed",
        "positive-body-json-key-order-changed",
        "positive-body-json-value-encoded",
    }:
        expected, raw_request, _mss = cases[name]
        assert expected == "alert"
        assert json.loads(parse_http_request(raw_request).body) == original_document
        _assert_content_length(raw_request)

    encoded_body = parse_http_request(
        cases["positive-body-json-value-encoded"][1]
    ).body
    assert b"\\u002e" in encoded_body

    benign_request = cases["negative-body-json-benign-value"][1]
    benign_document = json.loads(parse_http_request(benign_request).body)
    assert benign_document["path"] == "documents/report.pdf"
    assert not contains_exploit_marker(benign_document["path"])
    _assert_content_length(benign_request)

    moved_request = cases["negative-body-json-value-in-other-field"][1]
    moved_document = json.loads(parse_http_request(moved_request).body)
    assert moved_document["path"] == "documents/report.pdf"
    assert "../../etc/passwd" in moved_document.values()
    _assert_content_length(moved_request)

    assert cases["positive-body-segmented"][2] <= 16


def test_form_body_variants_preserve_decoded_values_and_update_length() -> None:
    body = b"mode=raw&path=../../etc/passwd"
    cases = _case_map(_request("application/x-www-form-urlencoded", body))

    expected_names = {
        "positive-body-form-extra-parameter",
        "positive-body-form-parameter-order-changed",
        "positive-body-form-url-encoded",
        "negative-body-form-benign-value",
        "negative-body-form-value-in-other-parameter",
        "negative-body-form-different-endpoint",
    }
    assert expected_names <= cases.keys()

    for name in {
        "positive-body-form-parameter-order-changed",
        "positive-body-form-url-encoded",
    }:
        raw_request = cases[name][1]
        parsed_form = parse_qs(
            parse_http_request(raw_request).body.decode("utf-8"),
            keep_blank_values=True,
        )
        assert parsed_form["mode"] == ["raw"]
        assert parsed_form["path"] == ["../../etc/passwd"]
        _assert_content_length(raw_request)

    encoded_body = parse_http_request(
        cases["positive-body-form-url-encoded"][1]
    ).body
    assert b"%2F" in encoded_body

    benign_request = cases["negative-body-form-benign-value"][1]
    benign_form = parse_qs(parse_http_request(benign_request).body.decode("utf-8"))
    assert benign_form["path"] == ["documents/report.pdf"]
    _assert_content_length(benign_request)

    moved_request = cases["negative-body-form-value-in-other-parameter"][1]
    moved_form = parse_qs(parse_http_request(moved_request).body.decode("utf-8"))
    assert moved_form["path"] == ["documents/report.pdf"]
    assert moved_form["description"] == ["../../etc/passwd"]
    _assert_content_length(moved_request)


def test_text_body_uses_conservative_marker_and_line_ending_variants() -> None:
    body = b"path=../../etc/passwd\r\nmode=read"
    cases = _case_map(_request("text/plain; charset=utf-8", body))

    assert "positive-body-text-line-endings-changed" in cases
    assert "negative-body-text-marker-removed" in cases
    assert "negative-body-text-different-endpoint" in cases

    newline_request = cases["positive-body-text-line-endings-changed"][1]
    newline_body = parse_http_request(newline_request).body
    assert b"\r\n" not in newline_body
    assert b"../../etc/passwd" in newline_body
    _assert_content_length(newline_request)

    benign_request = cases["negative-body-text-marker-removed"][1]
    benign_body = parse_http_request(benign_request).body.decode("utf-8")
    assert not contains_exploit_marker(benign_body)
    _assert_content_length(benign_request)


def test_ambiguous_transfer_encoding_body_is_not_rewritten() -> None:
    request = (
        b"POST /api/read HTTP/1.1\r\n"
        b"Host: example.invalid\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"2a\r\n{\"path\":\"../../etc/passwd\"}\r\n0\r\n\r\n"
    )
    cases = _case_map(request)

    assert "positive-body-segmented" in cases
    assert not any("body-json" in name for name in cases)
    assert all(
        b"Content-Length:" not in raw_request
        for _expected, raw_request, _mss in cases.values()
    )


def test_fallback_negative_is_added_when_no_semantic_negative_can_be_derived() -> None:
    request = b"GET /health HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    cases = {
        name: (expected, raw_request, mss)
        for name, expected, _reason, raw_request, _response, mss in derive_http_cases(
            request,
            b"",
        )
    }

    expected, raw_request, _mss = cases["negative-different-endpoint-fallback"]
    assert expected == "no_alert"
    parsed = parse_http_request(raw_request)
    assert parsed.method == "GET"
    assert parsed.target == "/not-vulnerable"
    assert parsed.headers == parse_http_request(request).headers


def test_compressed_body_is_not_treated_as_plain_json() -> None:
    compressed_body = b"not-really-gzip-{\"path\":\"../../etc/passwd\"}"
    request = (
        b"POST /api/read HTTP/1.1\r\n"
        b"Host: example.invalid\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Encoding: gzip\r\n"
        + f"Content-Length: {len(compressed_body)}".encode("ascii")
        + b"\r\n\r\n"
        + compressed_body
    )
    cases = _case_map(request)

    assert "positive-body-segmented" in cases
    assert not any("body-json" in name for name in cases)
    assert not any("body-text" in name for name in cases)


def test_passwd_response_variants_cover_stable_evidence_and_decoys() -> None:
    request = (
        b"GET /download?path=../../etc/passwd HTTP/1.1\r\n"
        b"Host: example.invalid\r\n\r\n"
    )
    body = (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}".encode("ascii")
        + b"\r\n\r\n"
        + body
    )
    cases = {
        name: (expected, raw_response, mss)
        for name, expected, _reason, _request, raw_response, mss in derive_http_cases(
            request,
            response,
        )
    }

    positive_names = {
        "positive-response-passwd-root-only",
        "positive-response-passwd-shell-changed",
        "positive-response-passwd-lines-reordered",
        "positive-response-passwd-unrelated-account-added",
        "positive-response-passwd-segmented",
    }
    negative_names = {
        "negative-response-passwd-error-page",
        "negative-response-passwd-fragment-decoy",
        "negative-response-passwd-documentation-decoy",
    }
    assert positive_names | negative_names <= cases.keys()

    root_only = parse_http_response(
        cases["positive-response-passwd-root-only"][1]
    ).body
    assert root_only.splitlines() == [b"root:x:0:0:root:/root:/bin/bash"]

    shell_changed = parse_http_response(
        cases["positive-response-passwd-shell-changed"][1]
    ).body
    assert shell_changed.splitlines() == [b"root:x:0:0:root:/root:/bin/sh"]

    reordered = parse_http_response(
        cases["positive-response-passwd-lines-reordered"][1]
    ).body
    assert reordered.splitlines()[0].startswith(b"www-data:")
    assert any(line.startswith(b"root:x:0:0:") for line in reordered.splitlines())

    added = parse_http_response(
        cases["positive-response-passwd-unrelated-account-added"][1]
    ).body
    assert b"trafficcase:x:65530:65530:" in added
    assert cases["positive-response-passwd-segmented"][2] == 17

    error = parse_http_response(cases["negative-response-passwd-error-page"][1])
    assert error.status_code == 404
    fragment = parse_http_response(
        cases["negative-response-passwd-fragment-decoy"][1]
    ).body
    documentation = parse_http_response(
        cases["negative-response-passwd-documentation-decoy"][1]
    ).body
    assert b"root" in fragment and b":" not in fragment
    assert b"root:x:0:0" in documentation
    assert not any(
        line.startswith(b"root:") and len(line.split(b":")) == 7
        for line in documentation.splitlines()
    )

    for name in positive_names | negative_names:
        expected, raw_response, _mss = cases[name]
        assert expected == ("alert" if name.startswith("positive-") else "no_alert")
        _assert_response_content_length(raw_response)
    assert len({cases[name][1] for name in positive_names}) >= 4


def test_passwd_response_accepts_pdf_type_and_bare_samesite_cookie_attribute() -> None:
    request = (
        b"GET /viewPDF?pdfUrl=file:///etc/passwd HTTP/1.1\r\n"
        b"Host: example.invalid\r\n\r\n"
    )
    body = (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
    )
    response = (
        b"HTTP/1.1 200\r\n"
        b"Content-Type: application/pdf;charset=UTF-8\r\n"
        b"Set-Cookie: JSESSIONID=test; Path=/; HttpOnly=true\r\n"
        b"SameSite=Lax\r\n"
        + f"Content-Length: {len(body)}".encode("ascii")
        + b"\r\n\r\n"
        + body
    )

    parsed = parse_http_response(response)
    set_cookie = next(
        value for name, value in parsed.headers if name.casefold() == "set-cookie"
    )
    assert set_cookie.endswith("; SameSite=Lax")

    names = {
        name
        for name, _expected, _reason, _request, _response, _mss in derive_http_cases(
            request,
            response,
        )
    }
    assert "positive-response-passwd-root-only" in names
    assert "negative-response-passwd-documentation-decoy" in names
