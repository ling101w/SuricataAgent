"""Deterministically extract HTTP evidence from Python PoC source code.

The extractor only parses Python syntax. It never imports or executes submitted PoC
code, opens sockets, or contacts a target.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import quote, quote_plus, urlencode, urlsplit


ADAPTER_VERSION = "python-poc-http-v1"
MIN_CONFIDENCE = 0.65
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
HTTP_CALLS = {method.casefold() for method in HTTP_METHODS}
KNOWN_HTTP_NAMES = {
    "requests",
    "httpx",
    "urllib",
    "session",
    "client",
    "http",
    "api",
}
EXPLOIT_MARKERS = (
    "../",
    ".%2e",
    "file://",
    "${",
    "#{",
    "{{",
    "<!entity",
    "union select",
    "sleep(",
    "cmd=",
    "command",
    "exec",
    "jndi:",
    "ognl",
    "xxe",
)


class PocHttpExtractionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class _Value:
    value: Any
    unresolved: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _Client:
    kind: str


@dataclass(frozen=True, slots=True)
class _Connection:
    target: _Value


@dataclass(frozen=True, slots=True)
class _UrllibRequest:
    method: str
    url: _Value
    headers: _Value
    body: _Value
    line: int


@dataclass(frozen=True, slots=True)
class HttpRequestCandidate:
    method: str
    url: str
    path: str
    host: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    raw_request: bytes
    client: str
    source_line: int
    source_end_line: int
    unresolved: tuple[str, ...]
    confidence: float
    score: float

    def public_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "path": self.path,
            "host": self.host,
            "headers": dict(self.headers),
            "body_bytes": len(self.body),
            "body_preview": self.body.decode("utf-8", errors="backslashreplace")[:4_000],
            "raw_request": self.raw_request.decode(
                "utf-8", errors="backslashreplace"
            ),
            "client": self.client,
            "source_line": self.source_line,
            "source_end_line": self.source_end_line,
            "unresolved": list(self.unresolved),
            "confidence": self.confidence,
            "score": self.score,
        }


@dataclass(frozen=True, slots=True)
class PocExtractionResult:
    source_sha256: str
    filename: str
    candidates: tuple[HttpRequestCandidate, ...]
    selected_index: int
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def selected(self) -> HttpRequestCandidate:
        return self.candidates[self.selected_index]

    @property
    def accepted(self) -> bool:
        return self.selected.confidence >= MIN_CONFIDENCE

    def public_dict(self) -> dict[str, Any]:
        return {
            "adapter": ADAPTER_VERSION,
            "source_sha256": self.source_sha256,
            "filename": self.filename,
            "candidate_count": len(self.candidates),
            "selected_index": self.selected_index,
            "accepted": self.accepted,
            "minimum_confidence": MIN_CONFIDENCE,
            "warnings": list(self.warnings),
            "selected": self.selected.public_dict(),
            "candidates": [item.public_dict() for item in self.candidates],
        }


def _value(value: Any, *parts: _Value) -> _Value:
    unresolved: set[str] = set()
    for part in parts:
        unresolved.update(part.unresolved)
    return _Value(value, frozenset(unresolved))


def _placeholder(name: str) -> _Value:
    return _Value("{" + name + "}", frozenset({name}))


def _string(value: _Value) -> str:
    if isinstance(value.value, bytes):
        return value.value.decode("utf-8", errors="backslashreplace")
    if value.value is None:
        return ""
    return str(value.value)


def _bytes(value: _Value) -> bytes:
    if isinstance(value.value, bytes):
        return value.value
    return _string(value).encode("utf-8")


def _qualname(node: ast.AST, imports: Mapping[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _qualname(node.value, imports)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _target_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _target_key(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _url_target(url: str) -> tuple[str, str]:
    value = url.strip() or "/"
    if value.startswith(("http://", "https://")):
        parsed = urlsplit(value)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host = parsed.netloc
        if not host or "{" in host or "}" in host:
            port = parsed.port if parsed.hostname and "{" not in parsed.hostname else None
            host = "target.local" + (f":{port}" if port else "")
        return host, path
    if value.startswith("/"):
        return "target.local", value
    placeholder_end = value.rfind("}")
    slash = value.find("/", placeholder_end + 1 if placeholder_end >= 0 else 0)
    path = value[slash:] if slash >= 0 else "/"
    return "target.local", path


def _compile_raw_request(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
) -> tuple[str, str, tuple[tuple[str, str], ...], bytes]:
    host, path = _url_target(url)
    normalized: dict[str, str] = {}
    for key, item in headers.items():
        if key.casefold() in {"host", "content-length"}:
            continue
        normalized[str(key)] = str(item)
    ordered = [("Host", host), *normalized.items()]
    if body:
        ordered.append(("Content-Length", str(len(body))))
    head = f"{method} {path} HTTP/1.1\r\n".encode("ascii", errors="replace")
    head += b"".join(
        f"{key}: {item}\r\n".encode("utf-8", errors="backslashreplace")
        for key, item in ordered
    )
    return host, path, tuple(ordered), head + b"\r\n" + body


def _multipart(data: Any, files: Any) -> tuple[bytes, str]:
    boundary = "----SuricataAgentBoundary"
    chunks: list[bytes] = []

    def add_field(name: str, content: Any) -> None:
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                str(content).encode("utf-8", errors="backslashreplace"),
                b"\r\n",
            ]
        )

    if isinstance(data, Mapping):
        for key, content in data.items():
            add_field(str(key), content)
    if isinstance(files, Mapping):
        for key, spec in files.items():
            filename = "upload.bin"
            content: Any = spec
            content_type = "application/octet-stream"
            if isinstance(spec, (tuple, list)):
                if spec:
                    filename = str(spec[0])
                if len(spec) > 1:
                    content = spec[1]
                if len(spec) > 2:
                    content_type = str(spec[2])
            payload = content if isinstance(content, bytes) else str(content).encode()
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    (
                        f'Content-Disposition: form-data; name="{key}"; '
                        f'filename="{filename}"\r\n'
                    ).encode(),
                    f"Content-Type: {content_type}\r\n\r\n".encode(),
                    payload,
                    b"\r\n",
                ]
            )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


class _Extractor:
    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.imports: dict[str, str] = {}
        self.attributes: dict[str, _Value] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.candidates: list[HttpRequestCandidate] = []

    def extract(self) -> list[HttpRequestCandidate]:
        self._process_block(self.tree.body, {})
        unique: dict[tuple[int, bytes], HttpRequestCandidate] = {}
        for item in self.candidates:
            unique[(item.source_line, item.raw_request)] = item
        return list(unique.values())

    def _process_block(self, statements: Sequence[ast.stmt], env: dict[str, _Value]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                self._import(statement)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[statement.name] = statement
                local = dict(env)
                for argument in statement.args.args:
                    local[argument.arg] = _placeholder(argument.arg)
                self._process_block(statement.body, local)
            elif isinstance(statement, ast.ClassDef):
                self._process_block(statement.body, dict(env))
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                node = statement.value
                if node is None:
                    continue
                value = self._eval(node, env)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    key = _target_key(target)
                    if key:
                        env[key] = value
                        if key.startswith("self."):
                            self.attributes[key] = value
                self._detect_call(node, env)
            elif isinstance(statement, ast.AugAssign):
                key = _target_key(statement.target)
                if key and isinstance(statement.op, ast.Add):
                    left = env.get(key, self.attributes.get(key, _placeholder(key)))
                    right = self._eval(statement.value, env)
                    env[key] = self._add(left, right)
            elif isinstance(statement, ast.Expr):
                self._detect_call(statement.value, env)
            elif isinstance(statement, ast.Return) and statement.value is not None:
                self._detect_call(statement.value, env)
            elif isinstance(statement, ast.If):
                self._process_block(statement.body, dict(env))
                self._process_block(statement.orelse, dict(env))
            elif isinstance(statement, (ast.For, ast.While, ast.With, ast.Try)):
                for block in (
                    getattr(statement, "body", []),
                    getattr(statement, "orelse", []),
                    getattr(statement, "finalbody", []),
                ):
                    self._process_block(block, dict(env))
                for handler in getattr(statement, "handlers", []):
                    self._process_block(handler.body, dict(env))

    def _import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for item in node.names:
                self.imports[item.asname or item.name.split(".")[0]] = item.name
            return
        module = node.module or ""
        for item in node.names:
            self.imports[item.asname or item.name] = f"{module}.{item.name}".strip(".")

    def _lookup(self, key: str, env: Mapping[str, _Value]) -> _Value:
        return env.get(key, self.attributes.get(key, _placeholder(key)))

    def _eval(self, node: ast.AST, env: dict[str, _Value], depth: int = 0) -> _Value:
        if depth > 8:
            return _placeholder("expression-depth")
        if isinstance(node, ast.Constant):
            return _Value(node.value)
        if isinstance(node, ast.Name):
            return self._lookup(node.id, env)
        if isinstance(node, ast.Attribute):
            key = _target_key(node) or _qualname(node, self.imports)
            return self._lookup(key, env)
        if isinstance(node, ast.JoinedStr):
            parts: list[_Value] = []
            for item in node.values:
                if isinstance(item, ast.Constant):
                    parts.append(_Value(str(item.value)))
                elif isinstance(item, ast.FormattedValue):
                    parts.append(self._eval(item.value, env, depth + 1))
            return _value("".join(_string(item) for item in parts), *parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._add(
                self._eval(node.left, env, depth + 1),
                self._eval(node.right, env, depth + 1),
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            parts = [self._eval(item, env, depth + 1) for item in node.elts]
            return _value([item.value for item in parts], *parts)
        if isinstance(node, ast.Dict):
            keys = [self._eval(item, env, depth + 1) for item in node.keys]
            values = [self._eval(item, env, depth + 1) for item in node.values]
            result = {
                _string(key): value.value for key, value in zip(keys, values, strict=True)
            }
            return _value(result, *keys, *values)
        if isinstance(node, ast.Subscript):
            container = self._eval(node.value, env, depth + 1)
            key = self._eval(node.slice, env, depth + 1)
            try:
                return _value(container.value[key.value], container, key)
            except (KeyError, IndexError, TypeError):
                return _placeholder(f"{_target_key(node.value) or 'value'}[{_string(key)}]")
        if isinstance(node, ast.IfExp):
            return self._eval(node.body, env, depth + 1)
        if isinstance(node, ast.Call):
            return self._eval_call(node, env, depth + 1)
        return _placeholder(node.__class__.__name__)

    @staticmethod
    def _add(left: _Value, right: _Value) -> _Value:
        try:
            result = left.value + right.value
        except (TypeError, ValueError):
            result = _string(left) + _string(right)
        return _value(result, left, right)

    def _eval_call(self, call: ast.Call, env: dict[str, _Value], depth: int) -> _Value:
        name = _qualname(call.func, self.imports)
        short = name.split(".")[-1]
        args = [self._eval(item, env, depth + 1) for item in call.args]
        kwargs = {
            item.arg: self._eval(item.value, env, depth + 1)
            for item in call.keywords
            if item.arg
        }
        if short in {"Session", "Client", "AsyncClient"}:
            return _Value(_Client(name))
        if short in {"HTTPConnection", "HTTPSConnection"}:
            return _Value(_Connection(args[0] if args else _placeholder("host")))
        if short == "Request" and ("urllib" in name.casefold() or name == "Request"):
            url = args[0] if args else kwargs.get("url", _placeholder("url"))
            body = kwargs.get("data", args[1] if len(args) > 1 else _Value(b""))
            headers = kwargs.get("headers", _Value({}))
            method = _string(kwargs.get("method", _Value("POST" if _bytes(body) else "GET")))
            return _Value(
                _UrllibRequest(method.upper(), url, headers, body, call.lineno),
                frozenset().union(url.unresolved, headers.unresolved, body.unresolved),
            )
        if short in {"str", "repr"}:
            return _value(_string(args[0]) if args else "", *args)
        if short == "bytes":
            return _value(_bytes(args[0]) if args else b"", *args)
        if short in {"dumps", "loads"} and "json" in name.casefold() and args:
            if short == "dumps":
                return _value(
                    json.dumps(args[0].value, ensure_ascii=False, separators=(",", ":")),
                    args[0],
                )
        if short in {"quote", "quote_plus"} and args:
            encoder = quote_plus if short == "quote_plus" else quote
            return _value(encoder(_string(args[0])), args[0])
        if short == "urlencode" and args:
            try:
                return _value(urlencode(args[0].value, doseq=True), args[0])
            except (TypeError, ValueError):
                return _placeholder("urlencoded-data")
        if short in {"b64encode", "urlsafe_b64encode"} and args:
            encoder = base64.urlsafe_b64encode if short.startswith("urlsafe") else base64.b64encode
            return _value(encoder(_bytes(args[0])), args[0])
        if short == "encode" and isinstance(call.func, ast.Attribute):
            owner = self._eval(call.func.value, env, depth + 1)
            return _value(_string(owner).encode(), owner)
        if short == "decode" and isinstance(call.func, ast.Attribute):
            owner = self._eval(call.func.value, env, depth + 1)
            return _value(_bytes(owner).decode("utf-8", errors="backslashreplace"), owner)
        if short == "replace" and isinstance(call.func, ast.Attribute) and len(args) >= 2:
            owner = self._eval(call.func.value, env, depth + 1)
            return _value(_string(owner).replace(_string(args[0]), _string(args[1])), owner, *args)
        if short == "format" and isinstance(call.func, ast.Attribute):
            owner = self._eval(call.func.value, env, depth + 1)
            try:
                rendered = _string(owner).format(
                    *[_string(item) for item in args],
                    **{key: _string(item) for key, item in kwargs.items()},
                )
                return _value(rendered, owner, *args, *kwargs.values())
            except (KeyError, IndexError, ValueError):
                return _value(_string(owner), owner, *args, *kwargs.values())
        function = self.functions.get(short)
        if function is not None and depth < 5:
            local = dict(env)
            for argument, item in zip(function.args.args, args, strict=False):
                local[argument.arg] = item
            for statement in function.body:
                if isinstance(statement, ast.Assign):
                    item = self._eval(statement.value, local, depth + 1)
                    for target in statement.targets:
                        key = _target_key(target)
                        if key:
                            local[key] = item
                elif isinstance(statement, ast.Return) and statement.value is not None:
                    return self._eval(statement.value, local, depth + 1)
        return _placeholder(f"{short}()")

    def _detect_call(self, node: ast.AST, env: dict[str, _Value]) -> None:
        if not isinstance(node, ast.Call):
            return
        name = _qualname(node.func, self.imports)
        short = name.split(".")[-1].casefold()
        owner_value = None
        if isinstance(node.func, ast.Attribute):
            owner_value = self._eval(node.func.value, env)

        if short in HTTP_CALLS and self._known_http_owner(name, owner_value):
            url_node = node.args[0] if node.args else _keyword(node, "url")
            if url_node is not None:
                self._append_http_call(short.upper(), url_node, node, env, name)
            return
        if short == "request" and self._known_http_owner(name, owner_value):
            method_node = node.args[0] if node.args else _keyword(node, "method")
            url_node = node.args[1] if len(node.args) > 1 else _keyword(node, "url")
            if method_node is not None and url_node is not None:
                method = _string(self._eval(method_node, env)).upper()
                self._append_http_call(method, url_node, node, env, name)
            return
        if short == "request" and isinstance(owner_value, _Value) and isinstance(
            owner_value.value, _Connection
        ):
            if len(node.args) >= 2:
                method = _string(self._eval(node.args[0], env)).upper()
                path = self._eval(node.args[1], env)
                target = owner_value.value.target
                url = _value(f"http://{_string(target)}{_string(path)}", target, path)
                self._append_http_call(method, None, node, env, name, url_override=url, body_position=2)
            return
        if short == "urlopen":
            request_node = node.args[0] if node.args else _keyword(node, "url")
            if request_node is not None:
                request = self._eval(request_node, env)
                if isinstance(request.value, _UrllibRequest):
                    marker = request.value
                    self._append_candidate(
                        marker.method,
                        marker.url,
                        marker.headers,
                        marker.body,
                        "urllib.request",
                        node,
                    )
            return
        if short in {"send", "sendall"} and node.args:
            raw = self._eval(node.args[0], env)
            self._append_raw_socket(_bytes(raw), raw.unresolved, node)

    @staticmethod
    def _known_http_owner(name: str, owner: _Value | None) -> bool:
        if owner is not None and isinstance(owner.value, _Client):
            return True
        lowered = name.casefold()
        return any(item in lowered.split(".") for item in KNOWN_HTTP_NAMES)

    def _append_http_call(
        self,
        method: str,
        url_node: ast.AST | None,
        call: ast.Call,
        env: dict[str, _Value],
        client: str,
        *,
        url_override: _Value | None = None,
        body_position: int | None = None,
    ) -> None:
        url = url_override or self._eval(url_node, env)  # type: ignore[arg-type]
        params_node = _keyword(call, "params")
        if params_node is not None:
            params = self._eval(params_node, env)
            try:
                query = urlencode(params.value, doseq=True)
            except (TypeError, ValueError):
                query = _string(params)
            separator = "&" if "?" in _string(url) else "?"
            url = _value(_string(url) + separator + query, url, params)

        headers = self._eval(_keyword(call, "headers"), env) if _keyword(call, "headers") else _Value({})
        header_map = {
            str(key): str(item)
            for key, item in (headers.value.items() if isinstance(headers.value, Mapping) else [])
        }
        body = _Value(b"")
        json_node = _keyword(call, "json")
        data_node = _keyword(call, "data") or _keyword(call, "content")
        files_node = _keyword(call, "files")
        if json_node is not None:
            source = self._eval(json_node, env)
            body = _value(
                json.dumps(source.value, ensure_ascii=False, separators=(",", ":")).encode(),
                source,
            )
            header_map.setdefault("Content-Type", "application/json")
        elif files_node is not None:
            data = self._eval(data_node, env) if data_node is not None else _Value({})
            files = self._eval(files_node, env)
            payload, content_type = _multipart(data.value, files.value)
            body = _value(payload, data, files)
            header_map.setdefault("Content-Type", content_type)
        elif data_node is not None:
            source = self._eval(data_node, env)
            if isinstance(source.value, Mapping):
                body = _value(urlencode(source.value, doseq=True).encode(), source)
                header_map.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                body = _value(_bytes(source), source)
        elif body_position is not None and len(call.args) > body_position:
            body = self._eval(call.args[body_position], env)
        cookies_node = _keyword(call, "cookies")
        if cookies_node is not None:
            cookies = self._eval(cookies_node, env)
            if isinstance(cookies.value, Mapping):
                header_map.setdefault(
                    "Cookie", "; ".join(f"{key}={item}" for key, item in cookies.value.items())
                )
            headers = _value(header_map, headers, cookies)
        else:
            headers = _value(header_map, headers)
        self._append_candidate(method, url, headers, body, client, call)

    def _append_candidate(
        self,
        method: str,
        url: _Value,
        headers: _Value,
        body: _Value,
        client: str,
        node: ast.AST,
    ) -> None:
        method = method.upper()
        if method not in HTTP_METHODS:
            return
        header_map = headers.value if isinstance(headers.value, Mapping) else {}
        host, path, compiled_headers, raw = _compile_raw_request(
            method,
            _string(url),
            {str(key): str(item) for key, item in header_map.items()},
            _bytes(body),
        )
        unresolved = sorted(url.unresolved | headers.unresolved | body.unresolved)
        confidence = 1.0
        if path == "/":
            confidence -= 0.35
        critical = [
            item
            for item in unresolved
            if "url" in item.casefold()
            or "path" in item.casefold()
            or "payload" in item.casefold()
            or "data" in item.casefold()
            or "body" in item.casefold()
        ]
        confidence -= min(0.36, 0.12 * len(critical))
        if body.unresolved and _bytes(body).startswith(b"{"):
            confidence -= 0.08
        confidence = round(max(0.0, confidence), 2)
        corpus = (path + "\n" + _bytes(body).decode("utf-8", errors="ignore")).casefold()
        exploit_score = sum(marker in corpus for marker in EXPLOIT_MARKERS)
        score = (
            confidence * 10
            + (2 if method in {"POST", "PUT", "PATCH", "DELETE"} else 1)
            + (2 if body.value else 0)
            + min(exploit_score * 3, 9)
            + min(getattr(node, "lineno", 0) / 10_000, 0.5)
        )
        self.candidates.append(
            HttpRequestCandidate(
                method=method,
                url=_string(url),
                path=path,
                host=host,
                headers=compiled_headers,
                body=_bytes(body),
                raw_request=raw,
                client=client,
                source_line=getattr(node, "lineno", 0),
                source_end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                unresolved=tuple(unresolved),
                confidence=confidence,
                score=round(score, 3),
            )
        )

    def _append_raw_socket(
        self,
        raw: bytes,
        unresolved: frozenset[str],
        node: ast.AST,
    ) -> None:
        normalized = raw.replace(b"\r\n", b"\n")
        head, separator, body = normalized.partition(b"\n\n")
        lines = head.splitlines()
        if not lines:
            return
        first = lines[0].decode("ascii", errors="ignore").split()
        if len(first) < 2 or first[0].upper() not in HTTP_METHODS:
            return
        headers: dict[str, str] = {}
        for line in lines[1:]:
            key, colon, item = line.partition(b":")
            if colon:
                headers[key.decode(errors="ignore").strip()] = item.decode(
                    "utf-8", errors="backslashreplace"
                ).strip()
        host = headers.get("Host", "target.local")
        path = first[1]
        compiled = raw if b"\r\n" in raw else raw.replace(b"\n", b"\r\n")
        score = 12 + sum(marker in compiled.decode(errors="ignore").casefold() for marker in EXPLOIT_MARKERS) * 3
        self.candidates.append(
            HttpRequestCandidate(
                method=first[0].upper(),
                url=path,
                path=path,
                host=host,
                headers=tuple(headers.items()),
                body=body if separator else b"",
                raw_request=compiled,
                client="socket",
                source_line=getattr(node, "lineno", 0),
                source_end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                unresolved=tuple(sorted(unresolved)),
                confidence=0.99 if not unresolved else 0.85,
                score=float(score),
            )
        )


def extract_http_request(
    source: str | bytes,
    *,
    filename: str = "poc.py",
) -> PocExtractionResult:
    """Parse a Python PoC and select the strongest materializable HTTP request."""
    source_bytes = source if isinstance(source, bytes) else source.encode("utf-8")
    if len(source_bytes) > 1024 * 1024:
        raise PocHttpExtractionError("POC_SOURCE_TOO_LARGE", "Python PoC 不能超过 1 MiB")
    try:
        text = source_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PocHttpExtractionError(
            "POC_SOURCE_ENCODING_ERROR", "Python PoC 必须是 UTF-8 文本"
        ) from exc
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        location = f"第 {exc.lineno} 行" if exc.lineno else ""
        raise PocHttpExtractionError(
            "POC_SYNTAX_ERROR", f"Python PoC 无法解析{location}：{exc.msg}"
        ) from exc
    candidates = _Extractor(tree).extract()
    if not candidates:
        raise PocHttpExtractionError(
            "POC_HTTP_NO_REQUEST",
            "没有找到可静态解析的 HTTP 请求；PoC 不会被执行",
        )
    selected_index = max(
        range(len(candidates)),
        key=lambda index: (candidates[index].score, candidates[index].source_line),
    )
    selected = candidates[selected_index]
    warnings: list[str] = []
    if len(candidates) > 1:
        warnings.append(f"检测到 {len(candidates)} 个请求，已选择评分最高的漏洞触发候选")
    if selected.unresolved:
        warnings.append("请求仍包含静态分析无法解析的变量：" + "、".join(selected.unresolved))
    if selected.confidence < MIN_CONFIDENCE:
        warnings.append("提取置信度不足，必须人工补全 Raw HTTP 后才能进入验证")
    return PocExtractionResult(
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        filename=filename,
        candidates=tuple(candidates),
        selected_index=selected_index,
        warnings=tuple(warnings),
    )


__all__ = [
    "ADAPTER_VERSION",
    "MIN_CONFIDENCE",
    "HttpRequestCandidate",
    "PocExtractionResult",
    "PocHttpExtractionError",
    "extract_http_request",
]
