import pytest

from unittest.mock import patch, call

from dissect.eventlog import wevt_object

from ._utils import TEMP_HEADER, create_data_item, create_header_type


signatures = ["CHAN", "OPCO", "LEVL", "KEYW"]


@pytest.mark.parametrize("signature", signatures)
def test_init(signature):
    wevtobject = getattr(wevt_object, signature)
    wevtobject(0x0, create_header_type(signature) + create_data_item("test"))


@pytest.mark.parametrize("signature", signatures)
def test_offset(signature):
    wevtobject = getattr(wevt_object, signature)
    chanel = wevtobject(0x0, create_header_type(type=signature) + create_data_item("test"))
    assert chanel.offset == 0x0


@pytest.mark.parametrize("signature", signatures)
@pytest.mark.parametrize(
    "data_offset,expected_name",
    [(0x42, "zaphod beeblebrox"), (0x200, "A test is now in session!")],
)
def test_name(signature, data_offset, expected_name):
    wevt_header = create_header_type(type=signature, data_offset=data_offset)
    padding = data_offset - len(wevt_header)
    data = wevt_header + b"\x00" * padding + create_data_item(expected_name)
    wevtobject = getattr(wevt_object, signature)(0x0, data)
    assert wevtobject.name == expected_name


@patch.object(wevt_object.WevtObject, wevt_object.WevtName.extract_name.__name__)
def test_template_offset_calls(mocked_extract_name):
    wevt_object.TEMP(0xE84, TEMP_HEADER)
    mocked_extract_name.assert_has_calls([call(20), call(28)], any_order=True)


def test_template():
    expected_values = [
        {"name": "ProviderID", "inType": "win:GUID", "outType": "win:BINARY"},
        {"name": "EventID", "inType": "win:UINT16", "outType": "win:UINT16"},
    ]

    template: wevt_object.TEMP = wevt_object.TEMP(0xE84, TEMP_HEADER)

    for index, descriptor in enumerate(template.names):
        assert descriptor.name == expected_values[index]["name"]
        assert descriptor.inType == expected_values[index]["inType"]
        assert descriptor.outType == expected_values[index]["outType"]
