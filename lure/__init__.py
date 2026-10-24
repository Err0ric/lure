from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lure")
except PackageNotFoundError:  # running from a checkout that was never installed
    __version__ = "unknown"
