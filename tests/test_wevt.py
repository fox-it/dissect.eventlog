from dissect.eventlog.exceptions import UnknownSignatureException
from unittest.mock import MagicMock, mock_open, patch

import pytest
from dissect.eventlog.wevt import MAPS_WEVT_TYPE, TTBL_WEVT_TYPE, WEVT, WEVT_TYPE

WEVT_HEADER = (
    b"\x57\x45\x56\x54\x68\x1E\x00\x00\x01\x00\x00\x90\x08\x00\x00\x00"
    b"\x05\x00\x00\x00\xA8\x03\x00\x00\x07\x00\x00\x00\xD8\x04\x00\x00"
    b"\x0D\x00\x00\x00\xD0\x18\x00\x00\x02\x00\x00\x00\x20\x19\x00\x00"
    b"\x00\x00\x00\x00\x5C\x1D\x00\x00\x01\x00\x00\x00\xE8\x1D\x00\x00"
    b"\x03\x00\x00\x00\x84\x1E\x00\x00\x04\x00\x00\x00\xF8\x1E\x00\x00"
)


def create_eventprovider():
    event_provider = MagicMock()
    event_provider.ProviderId = b"\xB7\xE6\xF3\x2F\x90\xCB\x00\x47\x96\x21\x44\x3F\x38\x97\x34\xED"
    event_provider.offset = int.from_bytes(b"\x58\x03\x00\x00", "little")
    return event_provider


@pytest.fixture
def mocked_fh():
    with patch("dissect.eventlog.open", mock_open(read_data=WEVT_HEADER), create=True) as obj:
        yield obj.return_value


def create_wevt(mocked_fh):
    provider = create_eventprovider()
    return WEVT(provider, mocked_fh)


def test_wevt_init(mocked_fh):
    create_wevt(mocked_fh)


def test_wevt_init_invalid_signature():
    mocked_fh = mock_open(read_data=b"RAND" + WEVT_HEADER[4:])
    with pytest.raises(UnknownSignatureException):
        create_wevt(mocked_fh.return_value)


def test_wevt_items(mocked_fh):
    wevt = create_wevt(mocked_fh)
    assert len(wevt.payload_types) == wevt.len_types


@pytest.mark.parametrize(
    "value,expected_result",
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
def test_wevt_test_offset(value, expected_result, mocked_fh):
    wevt = create_wevt(mocked_fh)
    next_offset = wevt._next_type_offset(value)
    assert next_offset == expected_result


@patch("dissect.eventlog.wevt.WEVT_TYPE")
def test_wevt_test_iterator(_, mocked_fh):
    with patch.object(WEVT, WEVT._next_type_offset.__name__):
        wevt = create_wevt(mocked_fh)
        for index, _ in enumerate(wevt):
            wevt._next_type_offset.assert_called_with(wevt.payload_types[index].offset)


@pytest.mark.parametrize(
    "signature,object",
    [
        (b"TTBL", TTBL_WEVT_TYPE),
        (b"MAPS", MAPS_WEVT_TYPE),
        (b"other", WEVT_TYPE),
    ],
)
def test_wevt_types(signature, object, mocked_fh):
    wevt = create_wevt(mocked_fh)
    assert wevt._choose_wevt_type(signature) is object
