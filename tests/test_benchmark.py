from __future__ import annotations

import sys
from functools import partial
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.eventlog.evt import Evt
from dissect.eventlog.evtx import Evtx
from dissect.eventlog.wevt.wevt_object import TEMP
from examples.parse_wevt import main as wevt_main
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


@pytest.mark.benchmark
@pytest.mark.parametrize(
    "path",
    [
        "_data/TestLog.evt",
        "_data/TestLog-dirty.evt",
    ],
)
def test_benchmark_evt(path: str, benchmark: BenchmarkFixture) -> None:
    with absolute_path(path).open("rb") as fh:
        evt = Evt(fh)
        benchmark(lambda: list(evt))


@pytest.mark.benchmark
@pytest.mark.parametrize(
    "path",
    [
        "_data/TestLog.evt",
        "_data/TestLog-dirty.evt",
    ],
)
def test_benchmark_evt_scrape(path: str, monkeypatch: pytest.MonkeyPatch, benchmark: BenchmarkFixture) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["", path])
        m.setitem(sys.modules, "dissect.target", Mock())
        m.setitem(sys.modules, "dissect.target.container", Mock())
        from examples import scrape_evt

        with (
            absolute_path(path).open("rb") as fh,
            patch("examples.scrape_evt.open_image", return_value=fh),
        ):
            benchmark(scrape_evt.main)


@pytest.mark.benchmark
def test_benchmark_evtx(benchmark: BenchmarkFixture) -> None:
    with absolute_path("_data/TestLogX.evtx").open("rb") as fh:
        evtx = Evtx(fh)
        benchmark(lambda: list(evtx))


@pytest.mark.benchmark
def test_benchmark_evtx_scrape(monkeypatch: pytest.MonkeyPatch, benchmark: BenchmarkFixture) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["", "_data/TestLogX.evtx"])
        m.setitem(sys.modules, "dissect.target", Mock())
        m.setitem(sys.modules, "dissect.target.container", Mock())
        from examples import scrape_evtx

        with (
            absolute_path("_data/TestLogX.evtx").open("rb") as fh,
            patch("examples.scrape_evtx.open_image", return_value=fh),
        ):
            benchmark(scrape_evtx.main)


@pytest.mark.benchmark
@pytest.mark.parametrize(
    "path",
    [
        "_data/mpengine_etw.wevt",
        "_data/services.wevt",
    ],
)
def test_benchmark_wevt(path: str, monkeypatch: pytest.MonkeyPatch, benchmark: BenchmarkFixture) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["", str(absolute_path(path))])

        benchmark(wevt_main)


@pytest.mark.benchmark
@pytest.mark.parametrize(
    ("path", "start_offset", "size"),
    [
        ("_data/mpengine_etw.wevt", 0x358, 0xC8B8),
        ("_data/services.wevt", 0x114, 0x1504),
    ],
)
def test_benchmark_binxml_wevt(path: str, start_offset: int, size: int, benchmark: BenchmarkFixture) -> None:
    """Tries to isolate the BinXML parsing."""
    with absolute_path(path).open("rb") as fh:
        fh.seek(start_offset)
        temp = partial(TEMP, offset=start_offset, data=fh.read(size))
        benchmark(temp)
