"""Every relative link in the docs resolves: the file exists and, for a
Markdown target, the #anchor is one of its headings (GitHub's slugs).
docs/README.md lists every page in docs/."""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PAGES = sorted([*(REPO / n for n in ("README.md", "CONTRIBUTING.md", "THIRD_PARTY.md",
                                      "CHANGELOG.md")),
                *(REPO / "docs").rglob("*.md")])
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
HREF_RE = re.compile(r'href="([^"]+)"')
FENCE_RE = re.compile(r"^```.*?^```", re.DOTALL | re.MULTILINE)


def slugs(page: Path) -> Iterator[str]:
    """GitHub's heading anchors: lowercase, punctuation dropped, spaces to
    dashes, -1, -2 for repeats."""
    seen: dict[str, int] = {}
    for line in FENCE_RE.sub("", page.read_text(encoding="utf-8")).splitlines():
        m = re.match(r"#{1,6} (.+)", line)
        if not m:
            continue
        slug = re.sub(r"[^\w\- ]", "", m.group(1).strip().lower()).replace(" ", "-")
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        yield slug if n == 0 else f"{slug}-{n}"


def targets(page: Path) -> list[str]:
    text = page.read_text(encoding="utf-8")
    if page.suffix == ".md":
        return LINK_RE.findall(FENCE_RE.sub("", text))
    return HREF_RE.findall(text)


def broken(page: Path) -> list[str]:
    out = []
    for target in targets(page):
        if re.match(r"(https?:|mailto:)", target):
            continue
        path, _, anchor = target.partition("#")
        dest = (page.parent / path).resolve() if path else page
        if not dest.exists() or (anchor and dest.suffix == ".md"
                                 and anchor not in set(slugs(dest))):
            out.append(target)
    return out


@pytest.mark.parametrize("page", [*PAGES, REPO / "docs" / "index.html"],
                         ids=lambda p: str(p.relative_to(REPO)))
def test_every_relative_link_resolves(page):
    assert broken(page) == []


def test_docs_readme_lists_every_page_in_docs():
    listed = {t.partition("#")[0] for t in targets(REPO / "docs" / "README.md")}
    pages = {str(p.relative_to(REPO / "docs")) for p in (REPO / "docs").rglob("*")
             if p.is_file() and "assets" not in p.parts and not p.name.startswith(".")
             and p.name != "README.md" and p.suffix in {".md", ".html", ".yml", ".svg"}}
    assert pages - listed == set()


def test_the_readme_stays_short():
    assert len((REPO / "README.md").read_text(encoding="utf-8").splitlines()) <= 100
