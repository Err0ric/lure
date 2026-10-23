
import pytest

from lure.tools.args import ToolArgumentError, ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.mock_files import MockFiles

FILES = [
    {"path": "/shared/a.txt", "content": "alpha"},
    {"path": "/shared/sub/b.txt", "content": "beta"},
    {"path": "/other/c.txt", "content": "gamma"},
]


@pytest.fixture
def log():
    return ToolCallLog()


@pytest.fixture
def files(log):
    return MockFiles(FILES, log)


def test_list_files(files, log):
    assert files.list_files() == ["/other/c.txt", "/shared/a.txt", "/shared/sub/b.txt"]
    assert files.list_files("shared/") == ["/shared/a.txt", "/shared/sub/b.txt"]
    assert files.list_files("/shar") == []  # a folder, not a string prefix
    assert [c.args for c in log.calls] == [{"prefix": None}, {"prefix": "/shared"},
                                           {"prefix": "/shar"}]


@pytest.mark.parametrize("path", ["/shared/a.txt", "shared/a.txt", " /shared/./a.txt ",
                                  "//shared/a.txt", "/shared/sub/../a.txt"])
def test_read_file_normalizes_path(files, log, path):
    assert files.read_file(path) == {"path": "/shared/a.txt", "content": "alpha"}
    assert log.calls[0].args == {"path": "/shared/a.txt"}
    assert log.calls[0].result == {"path": "/shared/a.txt", "content": "alpha"}


def test_read_missing_file(files):
    with pytest.raises(ToolError, match="no file at /shared/nope.txt"):
        files.read_file("/shared/nope.txt")


@pytest.mark.parametrize("bad", ["", "  ", None, 3, ["/a"]])
def test_bad_path(files, bad):
    with pytest.raises(ToolArgumentError, match="path must be a file path"):
        files.read_file(bad)


def test_write_creates_and_overwrites_in_memory(files, log):
    assert files.write_file("/shared/new.txt", "x") == {"status": "created",
                                                        "path": "/shared/new.txt"}
    assert files.write_file("/shared/a.txt", 42) == {"status": "overwritten",
                                                     "path": "/shared/a.txt"}
    assert files.read_file("/shared/a.txt")["content"] == "42"
    assert log.calls[1].args == {"path": "/shared/a.txt", "content": "42"}


def test_delete_removes_from_memory_only(files, log):
    assert files.delete_file("/shared/a.txt") == {"status": "deleted", "path": "/shared/a.txt"}
    assert "/shared/a.txt" not in files.list_files()
    with pytest.raises(ToolError, match="no file at"):
        files.delete_file("/shared/a.txt")
    assert FILES[0] == {"path": "/shared/a.txt", "content": "alpha"}  # fixture untouched


def test_paths_never_reach_the_real_filesystem(log, tmp_path):
    real = tmp_path / "keep.txt"
    real.write_text("real")
    files = MockFiles([{"path": str(real), "content": "fake"}], log)
    assert files.read_file(str(real))["content"] == "fake"
    files.delete_file(str(real))
    files.write_file(str(tmp_path / "new.txt"), "x")
    assert real.read_text() == "real"
    assert not (tmp_path / "new.txt").exists()


@pytest.mark.parametrize("fixture, match", [
    ({"path": "/a"}, "must be a JSON list"),
    (["x"], r"files\[0\] must be an object"),
    ([{"path": "/a"}], "missing fields"),
    ([{"path": "/a", "content": 1}], "must be strings"),
    ([{"path": "/a", "content": ""}, {"path": "a", "content": ""}], "duplicates path"),
])
def test_bad_fixture(log, fixture, match):
    with pytest.raises(FixtureError, match=match):
        MockFiles(fixture, log)
