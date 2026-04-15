from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

HAS_BENCHMARK = importlib.util.find_spec("pytest_benchmark") is not None


def absolute_path(filename: str):
    return Path(__file__).parent / filename


@pytest.fixture
def get_absolute_path():
    def _absolute_path(filename):
        return absolute_path(filename)

    return _absolute_path


def pytest_configure(config: pytest.Config) -> None:
    if not HAS_BENCHMARK:
        # If we don't have pytest-benchmark (or pytest-codspeed) installed, register the benchmark marker ourselves
        # to avoid pytest warnings
        config.addinivalue_line(
            "markers",
            "benchmark: mark test for benchmarking (requires pytest-benchmark)",
        )


def pytest_runtest_setup(item: pytest.Item) -> None:
    if not HAS_BENCHMARK and item.get_closest_marker("benchmark") is not None:
        pytest.skip("pytest-benchmark is not installed")
