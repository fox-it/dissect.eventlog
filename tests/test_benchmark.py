from __future__ import annotations

import sys
from functools import partial
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.eventlog.evt import Evt
from dissect.eventlog.evtx import Evtx
from dissect.eventlog.wevt_object import TEMP
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
    evt_path = absolute_path(path)
    with evt_path.open("rb") as fp:
        evt = Evt(fp)
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
    evt_path = absolute_path(path)
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["", path])
        m.setitem(sys.modules, "dissect.target", Mock())
        m.setitem(sys.modules, "dissect.target.container", Mock())
        from examples import scrape_evt

        with (
            evt_path.open("rb") as fp,
            patch("examples.scrape_evt.open_image", return_value=fp),
        ):
            benchmark(scrape_evt.main)


@pytest.mark.benchmark
def test_benchmark_evtx(benchmark: BenchmarkFixture) -> None:
    evtx_path = absolute_path("_data/TestLogX.evtx")
    with evtx_path.open("rb") as fp:
        evtx = Evtx(fp)
        benchmark(lambda: list(evtx))


@pytest.mark.benchmark
def test_benchmark_evtx_scrape(monkeypatch: pytest.MonkeyPatch, benchmark: BenchmarkFixture) -> None:
    evtx_path = absolute_path("_data/TestLogX.evtx")
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["", "_data/TestLogX.evtx"])
        m.setitem(sys.modules, "dissect.target", Mock())
        m.setitem(sys.modules, "dissect.target.container", Mock())
        from examples import scrape_evtx

        with (
            evtx_path.open("rb") as fp,
            patch("examples.scrape_evtx.open_image", return_value=fp),
        ):
            benchmark(scrape_evtx.main)


@pytest.mark.benchmark
@pytest.mark.parametrize("path", ["_data/mpenging_etw.wevt", "_data/services.wevt"])
def test_benchmark_wevt(path: str, monkeypatch: pytest.MonkeyPatch, benchmark: BenchmarkFixture) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["", str(absolute_path(path))])

        benchmark(wevt_main)


@pytest.mark.benchmark
@pytest.mark.parametrize(
    ("filename", "start_offset", "size"),
    [
        ("_data/mpenging_etw.wevt", 0x358, 0xC8B8),
        ("_data/services.wevt", 0x114, 0x1504),
    ],
)
def test_benchmark_binxml_wevt(filename: str, start_offset: int, size: int, benchmark: BenchmarkFixture) -> None:
    """Tries to isolate the BinXML parsing."""
    wevt_file = absolute_path(filename)
    with wevt_file.open("rb") as fp:
        fp.seek(start_offset)
        temp = partial(TEMP, offset=start_offset, data=fp.read(size))
        benchmark(temp)
