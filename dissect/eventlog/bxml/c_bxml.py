from __future__ import annotations

import binascii
import uuid
from datetime import datetime
from functools import partial
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Callable

bxml_def = """

enum BXML_TOKEN {
    BXML_END = 0x00,
    BXML_START_ELEMENT = 0x01,
    BXML_CLOSE_START_ELEMENT_TAG = 0x02,
    BXML_CLOSE_EMPTY_ELEMENT_TAG = 0x03,
    BXML_END_ELEMENT = 0x04,
    BXML_VALUE = 0x05,
    BXML_ATTRIBUTE = 0x06,
    BXML_TOKEN_CHAR_REFERENCE = 0x08,
    BXML_TOKEN_ENTITY_REFERENCE = 0x09,
    BXML_TEMPLATE_INSTANCE = 0x0C,
    BXML_TOKEN_NORMAL_SUBSTITUTION = 0x0D,
    BXML_TOKEN_OPTIONAL_SUBSTITUTION = 0x0E,
    BXML_FRAGMENT_HEADER = 0x0F,
};


enum BXML_TYPE: uint8 {
    NULL = 0x00,
    STRING = 0x01,
    ANSISTRING = 0x02,
    INT8 = 0x03,
    UINT8 = 0x04,
    INT16 = 0x05,
    UINT16 = 0x06,
    INT32 = 0x07,
    UINT32 = 0x08,
    INT64 = 0x09,
    UINT64 = 0x0A,
    FLOAT = 0x0B,
    DOUBLE = 0x0C,
    BOOL = 0x0D,
    BINARY = 0x0E,
    GUID = 0x0F,
    SIZET = 0x10,
    FILETIME = 0x11,
    SYSTEMTIME = 0x12,
    SID = 0x13,
    HEXINT32 = 0x14,
    HEXINT64 = 0x15,
    EVTHANDLE = 0x20,
    BINXML = 0x21,
    EVTXML = 0x23,
};


struct BXML_FRAGMENT_HEADER {
    uint8 major_version;
    uint8 minor_version;
    uint8 flags;
};

struct BXML_ELEMENT_START_TPL {
    uint16 dependency_id;
    uint32 data_size;
};

struct BXML_ELEMENT_START {
    uint32 data_size;
};

struct BXML_NAME {
    uint32 unknown;
    uint16 hash;
    uint16 size;
    wchar value[size];
};

struct BXML_ATTR {
    uint8 token;
};

struct BXML_VALUE_TEXT {
    uint16 size;
    wchar value[size];
};

struct BXML_TEMPLATE_REFERENCE {
    uint8 a;
    uint32 template_id;
    uint32 offset;
};

struct BXML_TEMPLATE_DEFINITION {
    uint32 next_template;
    char identifier[16];
    uint32 data_size;
};

struct BXML_OPTIONAL_SUBSTITUTION {
    uint16 sub_id;
    uint8 value_type;
};

struct BXML_TEMPLATE_VALUE_DESC {
    uint16 size;
    uint8 type_id;
    uint8 a;
};

typedef struct SID {
    uint8 revision;
    uint8 subAuthorityCount;
    char authority[6];
    uint32 subAuthorities[subAuthorityCount];
};

struct SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};
"""
c_bxml = cstruct().load(bxml_def)


def read_filetime(stream: BinaryIO) -> datetime:
    return wintimestamp(c_bxml.uint64_t(stream))


def read_systemtime(stream: BinaryIO) -> datetime:
    """Read systemtime from stream."""
    st = c_bxml.SYSTEMTIME(stream)
    return datetime(  # noqa: DTZ001
        year=st.wYear,
        month=st.wMonth,
        day=st.wDay,
        hour=st.wHour,
        minute=st.wMinute,
        second=st.wSecond,
        microsecond=st.wMilliseconds * 1000,
    )


def read_guid(stream: BinaryIO) -> str:
    """Read guid from stream."""
    guid = uuid.UUID(bytes=stream.read(16))
    guid_str = str(guid).upper()
    return f"{{{guid_str}}}"


def read_sid(stream: BinaryIO) -> str:
    """Read SID from stream."""
    sid = c_bxml.SID(stream)
    revision_str = str(sid.revision)
    last_authority = str(bytearray(sid.authority)[-1])
    sub_authorities = [str(authority) for authority in sid.subAuthorities]
    return "-".join(["S", revision_str, last_authority, *sub_authorities])


def _read_hexidecimal_int(stream: BinaryIO, value_size: int) -> str:
    _type = c_bxml.uint32 if value_size == 4 else c_bxml.uint64
    return f"0x{_type(stream):x}"


BXML_TYPE = c_bxml.BXML_TYPE
BXML_TOKEN = c_bxml.BXML_TOKEN

TYPE_READERS: dict[BXML_TYPE, Callable[[BinaryIO | bytes], Any]] = {
    BXML_TYPE.NULL: lambda s: None,
    BXML_TYPE.STRING: c_bxml.wchar[None],
    BXML_TYPE.ANSISTRING: c_bxml.char[None],
    BXML_TYPE.INT8: c_bxml.int8,
    BXML_TYPE.UINT8: c_bxml.uint8,
    BXML_TYPE.INT16: c_bxml.int16,
    BXML_TYPE.UINT16: c_bxml.uint16,
    BXML_TYPE.INT32: c_bxml.int32,
    BXML_TYPE.UINT32: c_bxml.uint32,
    BXML_TYPE.INT64: c_bxml.int64,
    BXML_TYPE.UINT64: c_bxml.uint64,
    BXML_TYPE.FLOAT: c_bxml.float,
    BXML_TYPE.DOUBLE: c_bxml.double,
    BXML_TYPE.BOOL: c_bxml.uint8,
    BXML_TYPE.BINARY: lambda s: None,
    BXML_TYPE.GUID: c_bxml.uint8[16],
    # NOTE: SIZET changes depending on the target operating that was used to record the file.
    # There is currently no way to determine that in bxml and the value type has no concept of the size
    # of the value. So it is unsure if SIZET will work as it is.
    BXML_TYPE.SIZET: lambda stream: c_bxml.uint32 if stream.getvalue() == 4 else c_bxml.uint64,
    BXML_TYPE.FILETIME: c_bxml.uint64,
    BXML_TYPE.SYSTEMTIME: c_bxml.SYSTEMTIME,
    BXML_TYPE.SID: c_bxml.SID,
    BXML_TYPE.HEXINT32: c_bxml.uint32,
    BXML_TYPE.HEXINT64: c_bxml.uint64,
}

DYNAMIC_LENGTH_TYPES: tuple[BXML_TYPE, ...] = (
    BXML_TYPE.NULL,
    BXML_TYPE.STRING,
    BXML_TYPE.ANSISTRING,
    BXML_TYPE.BINARY,
    BXML_TYPE.SIZET,
    BXML_TYPE.SID,
)

TYPE_TRANSFORMERS: dict[BXML_TYPE, Callable[[BinaryIO | bytes], Any]] = {
    **TYPE_READERS,
    BXML_TYPE.GUID: read_guid,
    BXML_TYPE.SID: read_sid,
    BXML_TYPE.SYSTEMTIME: read_systemtime,
    BXML_TYPE.FILETIME: read_filetime,
    BXML_TYPE.HEXINT32: partial(_read_hexidecimal_int, value_size=4),
    BXML_TYPE.HEXINT64: partial(_read_hexidecimal_int, value_size=8),
    BXML_TYPE.SIZET: lambda stream: _read_hexidecimal_int(stream, value_size=stream.getvalue()),
    BXML_TYPE.BINARY: lambda stream: binascii.hexlify(stream.read()),
}
