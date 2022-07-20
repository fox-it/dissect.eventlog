from unittest.mock import patch

from dissect.eventlog.wevt import MAPS_WEVT_TYPE

from ._utils import create_data_item, create_header, create_header_type


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
