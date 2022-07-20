from dissect.eventlog.exceptions import UnknownSignatureException
from dissect.eventlog.wevt import WEVT_TYPE, TTBL_WEVT_TYPE, MAPS_WEVT_TYPE
from dissect.eventlog.wevt_object import WevtObject
from unittest.mock import Mock, patch
import pytest

from ._utils import (
    TTBL_HEADER,
    CHAN_HEADER,
    CHAN_DATA,
    TEMP_HEADER,
    create_header,
    create_data_item,
    create_header_type,
)


def test_wevt_type_data():
    wevt_type = WEVT_TYPE(0x3A8, CHAN_HEADER + CHAN_DATA)
    for item in wevt_type:
        assert isinstance(item, WevtObject)


def test_wevt_init_failed():
    with pytest.raises(EOFError):
        WEVT_TYPE(Mock(), b"CHAN")


def test_wevt_invalid_signature():
    with pytest.raises(UnknownSignatureException):
        WEVT_TYPE(Mock(), b"TEST" + CHAN_HEADER[4:])


def test_wevt_chan():
    wevtype = WEVT_TYPE(Mock(), CHAN_HEADER + CHAN_DATA)
    assert wevtype.signature == "CHAN"


def test_wevt_ttbl():
    wevtype = WEVT_TYPE(0x04D0, TTBL_HEADER)

    assert wevtype.header.size == 0x13F8
    assert wevtype.header.nr_of_items == 0xA


@patch("dissect.eventlog.wevt_object.TEMP")
def test_wevt_temp_binxml(mocked_temp):
    ttbl_header = create_header("WEVT_TYPE", signature=b"TTBL", size=0x13F8, nr_of_items=1).dumps()
    wevtype = TTBL_WEVT_TYPE(0xE78, ttbl_header + TEMP_HEADER)
    for item in wevtype:
        assert item == mocked_temp.return_value


def maps_obj(offset, data_offset):
    maps_header = create_header("WEVT_TYPE", signature=b"MAPS", size=0x13F8, nr_of_items=1).dumps()
    maps_header += (offset + len(maps_header) + 4).to_bytes(byteorder="little", length=4)
    vmap_header = create_header_type("VMAP", signature=b"VMAP", size=0x40, data_offset=data_offset)
    data_item = create_data_item("test")
    return maps_header + vmap_header + data_item


@patch("dissect.eventlog.wevt_object.VMAP")
def test_maps_basic(mocked_map):
    offset = 0x48
    maps = maps_obj(offset, 0)
    wevt_type = MAPS_WEVT_TYPE(offset, maps)
    for item in wevt_type:
        assert item is mocked_map.return_value


def test_maps_different_dataoffset():
    """
    The structure of a VMAP WEVT_TYPE is just a bit different
    nr_of_items doesn't exist.
    """
    data_offset = 2000
    offset = 0x2248
    maps = maps_obj(offset, data_offset)
    wevt_type = MAPS_WEVT_TYPE(offset, maps)
    for x in wevt_type:
        assert x.header.data_offset == data_offset
