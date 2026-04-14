from __future__ import annotations

import typing
from pathlib import Path

import pytest

if typing.TYPE_CHECKING:
    from collections.abc import Callable


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.joinpath(filename).resolve()


@pytest.fixture
def get_absolute_path() -> Callable[[str], Path]:
    def _absolute_path(filename: str) -> Path:
        return absolute_path(filename)

    return _absolute_path
