import pytest

from swt import __version__


def pytest_report_header(config):
    return f"project version: {__version__}"
