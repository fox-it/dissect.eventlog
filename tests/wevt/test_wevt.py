from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import mock_open, patch

import pytest

from dissect.eventlog.exceptions import UnknownSignatureException
from dissect.eventlog.wevt import MAPS_WEVT_TYPE, TTBL_WEVT_TYPE, WEVT, WEVT_TYPE
from dissect.eventlog.wevt.c_wevt import c_wevt

if TYPE_CHECKING:
    from collections.abc import Iterator

WEVT_HEADER = (
    b"\x57\x45\x56\x54\x68\x1e\x00\x00\x01\x00\x00\x90\x08\x00\x00\x00"
    b"\x05\x00\x00\x00\xa8\x03\x00\x00\x07\x00\x00\x00\xd8\x04\x00\x00"
    b"\x0d\x00\x00\x00\xd0\x18\x00\x00\x02\x00\x00\x00\x20\x19\x00\x00"
    b"\x00\x00\x00\x00\x5c\x1d\x00\x00\x01\x00\x00\x00\xe8\x1d\x00\x00"
    b"\x03\x00\x00\x00\x84\x1e\x00\x00\x04\x00\x00\x00\xf8\x1e\x00\x00"
)


@pytest.fixture
def mocked_fh() -> Iterator[BinaryIO]:
    with patch("dissect.eventlog.open", mock_open(read_data=WEVT_HEADER), create=True) as obj:
        yield obj.return_value


@pytest.fixture
def wevt(mocked_fh: BinaryIO) -> WEVT:
    return create_wevt(mocked_fh)


def create_wevt(mocked_fh: BinaryIO) -> WEVT:
    provider = c_wevt.Event_Descriptor(
        ProviderId=b"\xb7\xe6\xf3\x2f\x90\xcb\x00\x47\x96\x21\x44\x3f\x38\x97\x34\xed",
        offset=int.from_bytes(b"\x58\x03\x00\x00", "little"),
    )
    return WEVT(provider, mocked_fh)


def test_wevt_init_invalid_signature() -> None:
    mocked_fh = mock_open(read_data=b"RAND" + WEVT_HEADER[4:])
    with pytest.raises(UnknownSignatureException):
        create_wevt(mocked_fh.return_value)


def test_wevt_items(wevt: WEVT) -> None:
    assert len(wevt.payload_types) == wevt.len_types


@pytest.mark.parametrize(
    ("value", "expected_result"),
    [
        (0x3A8, 0x50),
        (0x4D8, 0x180),
        (0x18D0, 0x1578),
        (0x1920, 0x15C8),
        (0x1D5C, 0x1A04),
        (0x1DE8, 0x1A90),
        (0x1E84, 0x1B2C),
        (0x1EF8, 0x1BA0),
    ],
)
def test_wevt_test_offset(value: int, expected_result: int, wevt: WEVT) -> None:
    next_offset = wevt._next_type_offset(value)
    assert next_offset == expected_result


def test_wevt_test_iterator(wevt: WEVT) -> None:
    with (
        patch("dissect.eventlog.wevt.wevt.WEVT_TYPE"),
        patch.object(WEVT, WEVT._next_type_offset.__name__),
        patch("dissect.cstruct.types.char.Char._read_array"),
    ):
        for index, _ in enumerate(wevt):
            wevt._next_type_offset.assert_called_with(wevt.payload_types[index].offset)


@pytest.mark.parametrize(
    ("signature", "wevt_type"),
    [
        (b"TTBL", TTBL_WEVT_TYPE),
        (b"MAPS", MAPS_WEVT_TYPE),
        (b"other", WEVT_TYPE),
    ],
)
def test_wevt_types(signature: bytes, wevt_type: type[WEVT_TYPE], mocked_fh: BinaryIO) -> None:
    wevt = create_wevt(mocked_fh)
    assert wevt._choose_wevt_type(signature) is wevt_type
