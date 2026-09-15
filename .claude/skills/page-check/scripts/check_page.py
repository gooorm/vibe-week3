#!/usr/bin/env python3
"""
page-check: HTML 페이지를 5가지 관점(title, 내부 링크, 이미지 alt, 뷰포트, 인코딩)으로 점검한다.
stdlib(html.parser)만 사용하며, 결과를 JSON으로 stdout에 출력한다.

사용법:
    python check_page.py file1.html [file2.html ...]
"""

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

HANGUL_RE = re.compile(r"[가-힣]")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "tel:", "javascript:", "//")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_text = None
        self._in_title = False
        self.has_viewport_meta = False
        self.charset_meta_pos = None  # (line, col) of first charset-declaring meta
        self.imgs = []  # list of dict(line, col, attrs)
        self.links = []  # list of dict(line, col, href)
        self.ids = set()  # every id/name attribute seen, for anchor checks
        self.meta_count_before_charset = 0
        self._meta_seen = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        line, col = self.getpos()

        if "id" in attrs_dict and attrs_dict["id"]:
            self.ids.add(attrs_dict["id"])
        if tag == "a" and "name" in attrs_dict and attrs_dict["name"]:
            self.ids.add(attrs_dict["name"])

        if tag == "title":
            self._in_title = True
            self.title_text = ""

        if tag == "img":
            self.imgs.append({"line": line, "col": col, "attrs": attrs_dict})

        if tag == "a" and attrs_dict.get("href"):
            self.links.append({"line": line, "col": col, "href": attrs_dict["href"]})

        if tag == "meta":
            self._meta_seen += 1
            name = (attrs_dict.get("name") or "").lower()
            if name == "viewport":
                self.has_viewport_meta = True

            has_charset_attr = "charset" in attrs_dict
            http_equiv = (attrs_dict.get("http-equiv") or "").lower()
            content = (attrs_dict.get("content") or "").lower()
            declares_charset = has_charset_attr or (
                http_equiv == "content-type" and "charset=" in content
            )
            if declares_charset and self.charset_meta_pos is None:
                self.charset_meta_pos = (line, col)
                self.meta_count_before_charset = self._meta_seen - 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title_text = (self.title_text or "") + data


def check_title(parser, issues):
    text = (parser.title_text or "").strip()
    if parser.title_text is None:
        issues.append(
            {
                "severity": "critical",
                "check": "title",
                "line": None,
                "message": "<title> 태그가 없습니다.",
                "suggestion": "브라우저 탭/북마크/검색 결과에 표시될 <title>을 <head> 안에 추가하세요.",
            }
        )
    elif not text:
        issues.append(
            {
                "severity": "critical",
                "check": "title",
                "line": None,
                "message": "<title> 태그는 있지만 내용이 비어 있습니다.",
                "suggestion": "페이지를 설명하는 실제 제목 텍스트를 채워 넣으세요.",
            }
        )


def check_viewport(parser, issues):
    if not parser.has_viewport_meta:
        issues.append(
            {
                "severity": "warning",
                "check": "viewport",
                "line": None,
                "message": '모바일 뷰포트 메타 태그(<meta name="viewport" ...>)가 없습니다.',
                "suggestion": '<meta name="viewport" content="width=device-width, initial-scale=1"> 를 <head>에 추가하세요.',
            }
        )


def check_img_alt(parser, issues):
    for img in parser.imgs:
        attrs = img["attrs"]
        if "alt" not in attrs:
            issues.append(
                {
                    "severity": "warning",
                    "check": "img-alt",
                    "line": img["line"],
                    "message": f"{img['line']}행의 <img> 태그에 alt 속성이 없습니다 (src=\"{attrs.get('src', '')}\").",
                    "suggestion": "스크린 리더 사용자와 SEO를 위해 이미지를 설명하는 alt 텍스트를 추가하세요. 장식용 이미지라면 alt=\"\"로 명시하세요.",
                }
            )
        elif attrs.get("alt", "").strip() == "":
            issues.append(
                {
                    "severity": "suggestion",
                    "check": "img-alt",
                    "line": img["line"],
                    "message": f"{img['line']}행의 <img>가 alt=\"\" (빈 값)입니다.",
                    "suggestion": "장식용 이미지가 의도한 것이 맞는지 확인하고, 의미 있는 이미지라면 설명 텍스트를 채워주세요.",
                }
            )


def check_encoding(parser, raw_bytes, text, issues):
    has_hangul = bool(HANGUL_RE.search(text))

    try:
        raw_bytes.decode("utf-8")
        is_valid_utf8 = True
    except UnicodeDecodeError:
        is_valid_utf8 = False

    if not is_valid_utf8:
        issues.append(
            {
                "severity": "critical",
                "check": "encoding",
                "line": None,
                "message": "파일이 유효한 UTF-8로 인코딩되어 있지 않습니다.",
                "suggestion": "에디터에서 파일을 UTF-8로 다시 저장하세요. 한글이 깨져 보일 수 있습니다.",
            }
        )
        return

    if parser.charset_meta_pos is None:
        issues.append(
            {
                "severity": "critical" if has_hangul else "suggestion",
                "check": "encoding",
                "line": None,
                "message": '문자 인코딩을 선언하는 <meta charset="UTF-8">이 없습니다.'
                + (" (한글 콘텐츠가 있어 브라우저/OS에 따라 글자가 깨질 수 있습니다)" if has_hangul else ""),
                "suggestion": '<head> 맨 앞부분에 <meta charset="UTF-8">을 추가하세요.',
            }
        )
    else:
        line, _ = parser.charset_meta_pos
        # HTML5 spec: charset meta should appear within the first 1024 bytes,
        # and before any other meta with textual content.
        if parser.meta_count_before_charset > 0:
            issues.append(
                {
                    "severity": "suggestion",
                    "check": "encoding",
                    "line": line,
                    "message": f'<meta charset="UTF-8">가 있지만 다른 <meta> 태그보다 뒤({line}행)에 있습니다.',
                    "suggestion": "인코딩이 확실히 먼저 적용되도록 charset 메타 태그를 <head>의 가장 첫 줄로 옮기세요.",
                }
            )


def resolve_target(href, base_dir):
    """href에서 프래그먼트를 분리하고, 파일 경로가 있으면 절대경로로 변환한다."""
    path_part, _, fragment = href.partition("#")
    if not path_part:
        return None, fragment or None
    target = (base_dir / path_part).resolve()
    return target, (fragment or None)


def check_internal_links(parser, base_dir, issues):
    for link in parser.links:
        href = link["href"].strip()
        if not href or href.startswith(EXTERNAL_SCHEMES):
            continue

        if href.startswith("#"):
            fragment = href[1:]
            if fragment and fragment not in parser.ids:
                issues.append(
                    {
                        "severity": "critical",
                        "check": "broken-link",
                        "line": link["line"],
                        "message": f"{link['line']}행의 링크 \"{href}\"가 가리키는 id=\"{fragment}\" 요소를 페이지 안에서 찾을 수 없습니다.",
                        "suggestion": "대상 id 오타를 확인하거나, 해당 id를 가진 요소를 추가하세요.",
                    }
                )
            continue

        target, fragment = resolve_target(href, base_dir)
        if target is None:
            continue

        if not target.exists():
            issues.append(
                {
                    "severity": "critical",
                    "check": "broken-link",
                    "line": link["line"],
                    "message": f"{link['line']}행의 링크 \"{href}\"가 가리키는 파일을 찾을 수 없습니다.",
                    "suggestion": "파일 경로/이름의 오타를 확인하거나 누락된 파일을 추가하세요.",
                }
            )
            continue

        if fragment and target.suffix.lower() in (".html", ".htm"):
            try:
                target_text = target.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            target_parser = PageParser()
            target_parser.feed(target_text)
            if fragment not in target_parser.ids:
                issues.append(
                    {
                        "severity": "warning",
                        "check": "broken-link",
                        "line": link["line"],
                        "message": f"{link['line']}행의 링크 \"{href}\"는 파일은 존재하지만 id=\"{fragment}\"를 대상 페이지에서 찾을 수 없습니다.",
                        "suggestion": "앵커 id 오타를 확인하세요.",
                    }
                )


def check_file(path: Path):
    raw_bytes = path.read_bytes()
    text = raw_bytes.decode("utf-8", errors="replace")

    parser = PageParser()
    parser.feed(text)

    issues = []
    check_title(parser, issues)
    check_internal_links(parser, path.parent, issues)
    check_img_alt(parser, issues)
    check_viewport(parser, issues)
    check_encoding(parser, raw_bytes, text, issues)

    order = {"critical": 0, "warning": 1, "suggestion": 2}
    issues.sort(key=lambda i: (order[i["severity"]], i["line"] or 0))

    summary = {"critical": 0, "warning": 0, "suggestion": 0}
    for issue in issues:
        summary[issue["severity"]] += 1

    return {"file": str(path), "summary": summary, "issues": issues}


def main():
    # Windows 콘솔의 기본 코드페이지(cp949 등)에서 한글 출력이 깨지는 것을 방지한다.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print("사용법: python check_page.py file1.html [file2.html ...]", file=sys.stderr)
        sys.exit(1)

    results = [check_file(Path(p)) for p in sys.argv[1:]]
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
