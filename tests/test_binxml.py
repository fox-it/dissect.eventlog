from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from dissect.util.stream import RelativeStream

from dissect.eventlog.bxml import parse_bxml
from dissect.eventlog.bxml.bxml import (
    Bxml,
    BxmlStream,
    Descriptor,
    Element,
    EvtxNameReader,
    Template,
    Value,
    create_record,
)
from dissect.eventlog.bxml.c_bxml import BXML_TOKEN, BXML_TYPE
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def evtx_template() -> Iterator[BxmlStream]:
    chunk_start = 4096
    bxml_offset = 536
    with absolute_path("_data/TestLogX.evtx").open("rb") as fh:
        relative_stream = RelativeStream(fh, chunk_start + bxml_offset, size=1582)
        bxml_stream = BxmlStream(relative_stream, EvtxNameReader(None), bxml_offset)
        yield bxml_stream


def test_bxml_reader(evtx_template: BxmlStream) -> None:
    # Uses bxml_offset as its base
    assert evtx_template.seek(0) == 536
    assert evtx_template.seek(536) == 536
    assert evtx_template.current() is None

    # Check whether current gets updated
    assert evtx_template.next().token == BXML_TOKEN.FRAGMENT_HEADER
    assert evtx_template.current().token == BXML_TOKEN.FRAGMENT_HEADER

    # Check if reading includes the peeked element (0x0F)
    evtx_template.seek(0)
    assert evtx_template.current() is None
    assert evtx_template.peek_next().token == BXML_TOKEN.FRAGMENT_HEADER
    assert evtx_template.read(10) == b"\x0f\x01\x01\x00\x0c\x01_fl@"
    assert evtx_template.current() is None

    # Check whether the internal queue gets used
    evtx_template.seek(0)
    assert evtx_template.current() is None
    assert evtx_template.peek_next().token == BXML_TOKEN.FRAGMENT_HEADER
    assert evtx_template.current() is None
    assert evtx_template.next().token == BXML_TOKEN.FRAGMENT_HEADER
    assert evtx_template.current().token == BXML_TOKEN.FRAGMENT_HEADER


def test_read_template(evtx_template: BxmlStream) -> None:
    # Template elements itself are still empty
    bxml = Bxml()
    temp = bxml.parse(evtx_template)

    assert isinstance(temp, Template)
    assert temp.identifier == 1080845919
    assert temp.uuid == UUID("406c665f-7934-5303-7648-8e8950058505")
    assert temp.root is not None

    assert temp.identifier in bxml.templates


def test_read_element(evtx_template: BxmlStream) -> None:
    bxml = Bxml()
    temp: Template = bxml.parse(evtx_template)
    elem = temp.root

    assert isinstance(elem, Element)
    assert elem.tag == "Event"
    assert elem.attributes["xmlns"].value == "http://schemas.microsoft.com/win/2004/08/events/event"

    assert elem is not None
    assert len(elem.children) == 1
    assert elem.children[0].tag == "System"

    children = [
        "Provider",
        "EventID",
        "Version",
        "Level",
        "Task",
        "Opcode",
        "Keywords",
        "TimeCreated",
        "EventRecordID",
        "Correlation",
        "Execution",
        "Channel",
        "Computer",
        "Security",
    ]
    assert children == [_elem.tag for _elem in elem.children[0].children]


def test_invalid_states(evtx_template: BxmlStream) -> None:
    bxml = Bxml()
    # Seek end element without a start element
    evtx_template.seek(867)
    with pytest.raises(RuntimeError, match="Cannot end an element if it never started"):
        bxml.parse(evtx_template)

    # FInd a substitution without a template
    evtx_template.seek(947)
    with pytest.raises(RuntimeError, match="Cannot use a substitution without a template"):
        bxml.parse(evtx_template)

    # Seek start of a value without parsing an element
    evtx_template.seek(1579)
    with pytest.raises(RuntimeError, match="Cannot parse value for an undefined element"):
        bxml.parse(evtx_template)


def test_unexpected_end() -> None:
    # Create a start of element then a EOF
    _binary = bytes.fromhex(
        "01      "  # Start element
        "DEADBEEF"  # Size of element
        "09000000"  # offset to the name of the element
        "00000000"  # BXML_NAME: unknown
        "FFFF    "  #            hash
        "0200    "  #            size
        "41004100"  #            "AAAA"
        "0000    "  #            padding
        "02      "  # End element
        "00      "  # End bxml
    )

    stream = BxmlStream(BytesIO(_binary), EvtxNameReader(None))
    bxml = Bxml()

    with pytest.raises(RuntimeError, match="Found an unexpected end of the bxml stream"):
        bxml.parse(stream)


def test_read_descriptors(evtx_template: BxmlStream) -> None:
    bxml = Bxml()
    _temp: Template = bxml.parse(evtx_template)

    descriptors = Descriptor.read_descriptors(evtx_template)

    assert len(descriptors) == 20
    assert descriptors[0].type == BXML_TYPE.UINT8
    assert descriptors[0].value == 4
    assert descriptors[6].type == BXML_TYPE.FILETIME
    assert descriptors[6].value == datetime(2021, 7, 22, 15, 44, 21, 416718, tzinfo=timezone.utc)
    assert descriptors[-1].type == BXML_TYPE.BINXML

    # parse the bxml underneath
    bxml_desc = descriptors[-1]
    evtx_template.seek(bxml_desc.offset)
    _temp1: Template = bxml.parse(evtx_template)

    desc1 = Descriptor.read_descriptors(evtx_template)
    assert len(desc1) == 3
    assert desc1[0].type == BXML_TYPE.STRING
    assert desc1[0].is_array is True
    assert desc1[0].value == "Test log message, information"


def test_create_record(evtx_template: BxmlStream) -> None:
    bxml = Bxml()
    temp: Template = bxml.parse(evtx_template)

    descriptors = Descriptor.read_descriptors(evtx_template)
    record = create_record(evtx_template, bxml, temp.root, descriptors)

    assert isinstance(record["Event_xmlns"], Value)
    assert record["Event_xmlns"].value == "http://schemas.microsoft.com/win/2004/08/events/event"
    assert isinstance(record["Binary"], Descriptor)
    assert record["Binary"].value is None


def test_binxml_evtx(evtx_template: BxmlStream) -> None:
    """Test the whole chain with parse_bxml."""
    bxml = Bxml()
    record = next(parse_bxml(evtx_template, bxml), {})

    assert record["Provider_Name"].value == "TestAppX"
    assert record["EventID"].value == 1
    assert record["EventID_Qualifiers"].value == 0
    assert record["Version"].value == 0
    assert record["Level"].value == 4
    assert record["Task"].value == 1
    assert record["Opcode"].value == 0
    assert record["Keywords"].value == "0x80000000000000"
    assert str(record["TimeCreated_SystemTime"].value) == "2021-07-22 15:44:21.416718+00:00"
    assert record["EventRecordID"].value == 1
    assert record["Correlation_ActivityID"].value is None
    assert record["Correlation_RelatedActivityID"].value is None
    assert record["Execution_ProcessID"].value == 0
    assert record["Execution_ThreadID"].value == 0
    assert record["Channel"].value == "TestLogX"
    assert record["Computer"].value == "DESKTOP-PJOQLJS"
    assert record["Security_UserID"].value is None

    assert record["Data"].value == "Test log message, information"
    assert record["Binary"].value is None

    assert len(bxml.templates) == 2
