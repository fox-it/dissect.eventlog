from dissect.eventlog.exceptions import BxmlException
from io import BytesIO
from dissect.eventlog.bxml import BxmlToken, Bxml
import pytest

from unittest.mock import Mock, patch


@pytest.mark.parametrize(
    "token,mocked_method",
    [
        (BxmlToken.BXML_START_ELEMENT, Bxml.parse_start_element),
        (BxmlToken.BXML_VALUE, Bxml.read_value),
        (BxmlToken.BXML_ATTRIBUTE, Bxml.read_attribute),
        (BxmlToken.BXML_TOKEN_CHAR_REFERENCE, Bxml.read_char_reference),
        (BxmlToken.BXML_TOKEN_ENTITY_REFERENCE, Bxml.read_entity_reference),
        (BxmlToken.BXML_TEMPLATE_INSTANCE, Bxml.read_template_instance),
        (BxmlToken.BXML_TOKEN_NORMAL_SUBSTITUTION, Bxml.substitute_token_and_add_to_template),
        (BxmlToken.BXML_TOKEN_OPTIONAL_SUBSTITUTION, Bxml.substitute_token_and_add_to_template),
    ],
)
def test_bxml_read_token(token, mocked_method):
    bxml_obj = Bxml(bytes([token]), None)
    with patch.object(Bxml, mocked_method.__name__) as obj:
        assert bxml_obj.read_token() == obj.return_value


@pytest.mark.parametrize(
    "token,expected_end",
    [
        (BxmlToken.BXML_END, BxmlToken.BXML_END),
        (BxmlToken.BXML_CLOSE_START_ELEMENT_TAG, BxmlToken.BXML_CLOSE_START_ELEMENT_TAG),
        (BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG, BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG),
        (BxmlToken.BXML_END_ELEMENT, BxmlToken.BXML_END_ELEMENT),
        (BxmlToken.BXML_FRAGMENT_HEADER, BxmlToken.BXML_FRAGMENT_HEADER),
    ],
)
def test_bxml_read_token_end_states(token, expected_end):
    bxml_obj = Bxml(bytes([token, 0x0, 0x0, 0x0]), None)
    assert bxml_obj.read_token() == expected_end


def test_bxml_read_unknown_token():
    bxml_obj = Bxml(bytes([0x10]), None)
    with pytest.raises(BxmlException):
        bxml_obj.read_token()


def test_bxml_substitution():
    mocked_template = Mock()
    bxml_obj = Bxml(BytesIO(b"\x01\x00\x00"), Mock())

    sub = bxml_obj.substitute_token_and_add_to_template(mocked_template)

    assert sub.sub_id == 0x1
    mocked_template.add_sub.assert_called_with(0x1, sub)


def test_value_text():
    bxml_obj = Bxml(b"\x05\x00h\x00e\x00l\x00l\x00o\x00", None)
    assert bxml_obj._read_string_value(False, Mock()) == "hello"


@patch.object(Bxml, Bxml.read_token.__name__, return_value=" World")
def test_value_more(_):
    bxml_obj = Bxml(b"\x05\x00H\x00e\x00l\x00l\x00o\x00", None)
    assert bxml_obj._read_string_value(True, Mock()) == "Hello World"


@patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="data")
def test_read_tag_and_attributes(mocked_read):
    tag = Bxml(None, None)._read_tag_and_attributes(False, Mock())
    assert tag.name == mocked_read.return_value
    assert len(tag.attributes) == 0


@patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="data")
def test_read_tag_and_attributes_attributes(mocked_tag):
    with patch.object(Bxml, Bxml._read_attributes.__name__) as attributes:
        attributes.return_value = [("name", "test")]
        bxml_obj = Bxml(None, None)
        tag = bxml_obj._read_tag_and_attributes(True, Mock())
        assert tag.name == mocked_tag.return_value
        assert tag.attributes["name"] == "test"


@pytest.mark.parametrize(
    "side_effects,expected_length",
    [
        (["children_tag", BxmlToken.BXML_END_ELEMENT], 1),
        (["children_tag", "children_tag", BxmlToken.BXML_END_ELEMENT], 2),
        (["children_tag", BxmlToken.BXML_END_ELEMENT, "children_tag"], 1),
    ],
)
@patch.object(Bxml, Bxml.read_token.__name__)
def test_read_children(mocked_token, side_effects, expected_length):
    mocked_token.side_effect = side_effects
    bxml_obj = Bxml(None, None)
    children = [child for child in bxml_obj._read_children(Mock())]
    assert len(children) == expected_length


@pytest.mark.parametrize("bxml_data,expected_output", [(b"\x01\x01", "101"), (b"\xDE\xAD\xBE\xEF", "adde")])
def text_bxml_char_reference(bxml_data, expected_output):
    bxml_obj = Bxml(bxml_data, None)
    assert bxml_obj.read_char_reference() == "&x" + expected_output


@pytest.mark.parametrize("data", [b"\x01", b"\x01\x00"])
@patch.object(Bxml, Bxml._read_string_value.__name__)
def test_bxml_value(mocked_string, data):
    bxml_obj = Bxml(data, None)
    assert mocked_string.return_value == bxml_obj.read_value(Mock(), Mock())


@pytest.mark.parametrize("data", [b"\x02", b"\x03"])
def test_bxml_value_failed(data):
    bxml_obj = Bxml(data, None)
    with pytest.raises(BxmlException):
        bxml_obj.read_value(Mock(), Mock())


@patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="Hello")
def test_parse_entity_reference(_):
    assert Bxml(None, None).read_entity_reference(False, Mock()) == "&Hello;"


@patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="Hello")
@patch.object(Bxml, Bxml.read_token.__name__, return_value=" World")
def test_parse_entity_more(_, __):
    assert Bxml(None, None).read_entity_reference(True, Mock()) == "&Hello; World"
