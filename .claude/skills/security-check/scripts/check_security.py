#!/usr/bin/env python3
"""
security-check: HTML/JS 파일을 4가지 관점으로 점검한다.
1. 하드코딩된 비밀번호/API 키
2. escape 없이 innerHTML에 넣는 사용자 입력 (XSS)
3. console.log 등에서 민감 정보 노출
4. http:// 로 시작하는 외부 요청 (평문 통신)

stdlib(re)만 사용하며, 결과를 JSON으로 stdout에 출력한다.
정규식 기반 휴리스틱 검사이므로 완벽하지 않다 - 특히 여러 줄에 걸친
표현식이나 동적으로 조립되는 문자열은 놓칠 수 있다.

사용법:
    python check_security.py file1.html [file2.js ...]
"""

import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. 하드코딩된 비밀번호 / API 키
# ---------------------------------------------------------------------------

# 변수/키 이름에 민감한 단어가 "포함"되어 있으면 매치되도록 substring 방식으로 작성한다.
# (예: CORRECT_PASSWORD, userApiKey 처럼 snake_case/camelCase에 섞여 있어도 잡아야 하므로
#  \b 단어 경계 대신 이름 전체를 느슨하게 매치한다.)
SENSITIVE_NAME_ASSIGN_RE = re.compile(
    r"""
    ([A-Za-z_$][A-Za-z0-9_$]*
        (?:pass(?:word)?|pwd|secret|api[_]?key|apikey|
           access[_]?token|auth[_]?token|private[_]?key|client[_]?secret)
     [A-Za-z0-9_$]*)
    \s*[:=]\s*
    ["'`]([^"'`\n]{4,})["'`]
    """,
    re.IGNORECASE | re.VERBOSE,
)

PLACEHOLDER_VALUE_RE = re.compile(
    r"""(?ix)
    ^(
        your.*|my.*|enter.*|insert.*|type.*|change\s*me.*|
        example.*|sample.*|placeholder.*|dummy.*|test.*|demo.*|
        x{3,}|\*{3,}|todo.*|fixme.*|<.*>|\{\{.*\}\}|\$\{.*\}|
        process\.env.*|null|undefined|none
    )$
    """
)

KNOWN_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub Token"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI/Anthropic 형식 Secret Key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack Token"),
]

# ---------------------------------------------------------------------------
# 2. innerHTML XSS
# ---------------------------------------------------------------------------

INNERHTML_ASSIGN_RE = re.compile(r"\.innerHTML\s*(\+?=)\s*([^;]+);", re.DOTALL)
PURE_STATIC_STRING_RE = re.compile(r"""^(["'`])(?:(?!\1).)*\1$""", re.DOTALL)
ESCAPE_HINT_RE = re.compile(
    r"(?i)\b(sanitize|escapeHtml|escape_html|DOMPurify|textContent|encodeHTML)\b"
)

# ---------------------------------------------------------------------------
# 3. console.log 민감 정보 노출
# ---------------------------------------------------------------------------

CONSOLE_CALL_RE = re.compile(
    r"console\.(log|debug|info|warn|error)\s*\(([^)]*)\)", re.DOTALL
)
SENSITIVE_TOKEN_RE = re.compile(
    r"(?i)[\w.\[\]'\"]*"
    r"(?:password|pwd|secret|token|api[_]?key|apikey|ssn|creditcard|card[_]?number|auth)"
    r"[\w.\[\]'\"]*"
)
BARE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.\[\]'\"]*$")

# ---------------------------------------------------------------------------
# 4. http:// 외부 요청
# ---------------------------------------------------------------------------

HTTP_URL_RE = re.compile(
    r"""(?i)["'`\(]\s*(http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'`\s\)]+)"""
)


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def check_hardcoded_secrets(text: str, issues: list) -> None:
    for match in SENSITIVE_NAME_ASSIGN_RE.finditer(text):
        name, value = match.group(1), match.group(2)
        if PLACEHOLDER_VALUE_RE.match(value.strip()):
            continue
        line = line_of(text, match.start())
        issues.append(
            {
                "severity": "critical",
                "check": "hardcoded-secret",
                "line": line,
                "message": f'{line}행: "{name}"에 비밀번호/키로 보이는 값이 코드에 그대로 박혀 있습니다 ("{value[:24]}{"..." if len(value) > 24 else ""}").',
                "suggestion": "비밀값은 코드에 직접 쓰지 말고, 서버 환경변수나 별도의 비밀 관리 저장소에서 불러오도록 바꾸세요. 이미 커밋했다면 값을 즉시 교체(rotate)하세요.",
            }
        )

    for pattern, label in KNOWN_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line = line_of(text, match.start())
            issues.append(
                {
                    "severity": "critical",
                    "check": "hardcoded-secret",
                    "line": line,
                    "message": f"{line}행: {label}로 보이는 문자열이 코드에 그대로 노출되어 있습니다.",
                    "suggestion": "즉시 해당 키를 폐기하고 재발급하세요. 코드에서 제거하고 환경변수 등 안전한 곳에 보관하세요.",
                }
            )


def check_innerhtml_xss(text: str, issues: list) -> None:
    for match in INNERHTML_ASSIGN_RE.finditer(text):
        rhs = match.group(2).strip()
        line = line_of(text, match.start())

        if PURE_STATIC_STRING_RE.match(rhs):
            continue  # 고정 문자열만 대입 - 사용자 입력이 섞여 있지 않음

        if ESCAPE_HINT_RE.search(rhs):
            continue  # sanitize/escape 처리가 보임 - 이미 이스케이프 중

        issues.append(
            {
                "severity": "critical",
                "check": "innerhtml-xss",
                "line": line,
                "message": f'{line}행: innerHTML에 "{rhs[:60]}{"..." if len(rhs) > 60 else ""}" 를 이스케이프 없이 그대로 넣고 있습니다.',
                "suggestion": "innerHTML 대신 textContent를 쓰거나, 꼭 HTML이 필요하다면 DOMPurify 같은 라이브러리로 이스케이프한 뒤 넣으세요.",
            }
        )


def check_console_log_leak(text: str, issues: list) -> None:
    for match in CONSOLE_CALL_RE.finditer(text):
        args = match.group(2)
        line = line_of(text, match.start())

        token_match = SENSITIVE_TOKEN_RE.search(args)
        if not token_match:
            continue

        stripped_args = args.strip()
        is_direct_dump = bool(BARE_IDENTIFIER_RE.match(stripped_args)) and bool(
            SENSITIVE_TOKEN_RE.search(stripped_args)
        )

        if is_direct_dump:
            issues.append(
                {
                    "severity": "critical",
                    "check": "console-log-leak",
                    "line": line,
                    "message": f'{line}행: console.log가 민감한 값으로 보이는 변수("{stripped_args}")를 그대로 출력하고 있습니다.',
                    "suggestion": "디버그용 로그에서 비밀번호/토큰 등 민감한 값을 출력하지 마세요. 배포 전 해당 로그를 삭제하거나 마스킹 처리하세요.",
                }
            )
        else:
            issues.append(
                {
                    "severity": "warning",
                    "check": "console-log-leak",
                    "line": line,
                    "message": f'{line}행: console.log 인자에 "{token_match.group(0)[:40]}" 처럼 민감해 보이는 이름이 포함되어 있습니다. 실제로 값이 찍히는지 확인이 필요합니다.',
                    "suggestion": "단순 안내 메시지라면 문제 없지만, 실제 비밀번호/토큰 값이 함께 출력되는지 확인하고 그렇다면 로그를 제거하세요.",
                }
            )


def check_http_external_request(text: str, issues: list) -> None:
    seen_at_line = set()
    for match in HTTP_URL_RE.finditer(text):
        url = match.group(1)
        line = line_of(text, match.start())
        key = (line, url)
        if key in seen_at_line:
            continue
        seen_at_line.add(key)
        issues.append(
            {
                "severity": "warning",
                "check": "http-external-request",
                "line": line,
                "message": f'{line}행: 암호화되지 않은 "http://" 주소로 외부 요청/리소스를 가리키고 있습니다 ({url[:60]}{"..." if len(url) > 60 else ""}).',
                "suggestion": "가능하면 https://로 바꾸세요. http://는 중간자 공격(MITM)에 노출되어 통신 내용이 도청·변조될 수 있습니다.",
            }
        )


def check_file(path: Path) -> dict:
    raw_bytes = path.read_bytes()
    text = raw_bytes.decode("utf-8", errors="replace")

    issues = []
    check_hardcoded_secrets(text, issues)
    check_innerhtml_xss(text, issues)
    check_console_log_leak(text, issues)
    check_http_external_request(text, issues)

    order = {"critical": 0, "warning": 1, "suggestion": 2}
    issues.sort(key=lambda i: (order[i["severity"]], i["line"] or 0))

    summary = {"critical": 0, "warning": 0, "suggestion": 0}
    for issue in issues:
        summary[issue["severity"]] += 1

    return {"file": str(path), "summary": summary, "issues": issues}


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print("사용법: python check_security.py file1.html [file2.js ...]", file=sys.stderr)
        sys.exit(1)

    results = [check_file(Path(p)) for p in sys.argv[1:]]
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
