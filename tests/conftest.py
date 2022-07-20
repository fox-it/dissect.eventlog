import os
import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


@pytest.fixture
def get_absolute_path():
    def _absolute_path(filename):
        return absolute_path(filename)

    return _absolute_path
