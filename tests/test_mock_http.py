
import pytest

from lure.tools.args import ToolArgumentError, ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.mock_http import MockHttp, url_key

PAGES = [{"url": "https://portal.vendor.example/po/7712", "title": "PO", "body": "slots"}]


@pytest.fixture
def log():
    return ToolCallLog()


@pytest.fixture
def http(log):
    return MockHttp(PAGES, log)


@pytest.mark.parametrize("url", [
    "https://portal.vendor.example/po/7712",
    "http://portal.vendor.example/po/7712",
    "  HTTPS://Portal.Vendor.example/po/7712/  ",
    "portal.vendor.example/po/7712",
    "https://portal.vendor.example/po/7712#slots",
])
def test_fetch_matches_loosely(http, log, url):
    page = http.fetch_url(url)
    assert page == {"url": PAGES[0]["url"], "status": 200, "title": "PO", "body": "slots"}
    assert log.calls[0].args == {"url": url.strip()}
    assert log.calls[0].result == page


@pytest.mark.parametrize("url", ["https://portal.vendor.example/po/7713",
                                 "https://portal.vendor.example/PO/7712",
                                 "https://portal.vendor.example/po/7712?x=1"])
def test_unknown_page_is_404(http, url):
    with pytest.raises(ToolError, match="404 not found"):
        http.fetch_url(url)


@pytest.mark.parametrize("bad", ["", None, 3])
def test_bad_url(http, bad):
    with pytest.raises(ToolArgumentError, match="url must be a web address"):
        http.fetch_url(bad)


def test_result_is_a_copy(http):
    http.fetch_url(PAGES[0]["url"])["body"] = "tampered"
    assert http.fetch_url(PAGES[0]["url"])["body"] == "slots"


def test_url_key():
    assert url_key("https://A.example/") == url_key("a.example")


@pytest.mark.parametrize("fixture, match", [
    ({}, "must be a JSON list"),
    ([{"url": "https://a.example", "title": "t"}], "missing fields"),
    ([{"url": "a.example", "title": "t", "body": "b"}], "must start with http"),
    ([{"url": "https://a.example", "title": "t", "body": "b"},
      {"url": "http://A.example/", "title": "t", "body": "b"}], "duplicates url"),
])
def test_bad_fixture(log, fixture, match):
    with pytest.raises(FixtureError, match=match):
        MockHttp(fixture, log)
