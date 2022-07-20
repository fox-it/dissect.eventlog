from dissect.eventlog.exceptions import UnknownSignatureException
from dissect.eventlog.wevt import CRIM
from unittest.mock import patch

import pytest

CRIM_HEADER = (
    b"\x43\x52\x49\x4D\xF8\x1B\x07\x00\x05\x00\x01\x00\x01\x00\x00\x00"
    b"\xB7\xE6\xF3\x2F\x90\xCB\x00\x47\x96\x21\x44\x3F\x38\x97\x34\xED"
    b"\x58\x03\x00\x00"
)


def test_initialization():
    CRIM(CRIM_HEADER)


@patch("dissect.eventlog.wevt.WEVT")
def test_crim_offset(patched_wevt):
    crim = CRIM(CRIM_HEADER)
    assert next(crim.wevt_headers()) == patched_wevt.return_value


def test_crim_parsed():
    crim = CRIM(CRIM_HEADER)
    assert crim.file_size == 0x71BF8


def test_crim_failed():
    with pytest.raises(UnknownSignatureException):
        CRIM(b"HELP" + CRIM_HEADER[4:])
