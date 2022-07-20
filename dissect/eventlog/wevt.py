from dissect.eventlog.exceptions import UnknownSignatureException
from io import BufferedReader
from uuid import UUID

import dissect.eventlog.wevt_object as wevt_objects

from dissect.cstruct import cstruct

header_dev = """
struct Event_Descriptor {
    char      ProviderId[16];
    uint32    offset;
};

struct CRIM_HEADER {
    char             signature[4];
    uint32           size;
    uint32           unknown;
    uint32           providers;
    Event_Descriptor event_providers[providers];
};

struct WEVT_TYPES {
    uint32    type;
    uint32    offset;
}

struct WEVT {
    char        signature[4];
    uint32      size;
    uint32      message_table_id;
    uint32      nr_of_types;
    WEVT_TYPES  types[nr_of_types];
};

struct WEVT_TYPE {
    char    signature[4];
    uint32  size;
    uint32  nr_of_items;
};
"""

c_wevt_headers = cstruct()
c_wevt_headers.load(header_dev)


def validate_signature(signature, expected_signature):
    if signature != expected_signature:
        raise UnknownSignatureException(f"Invalid {str(expected_signature)}")


class CRIM:
    """Start header of the WEVT_TEMPLATE
    Holds the number of providers inside the template
    """

    def __init__(self, fh: BufferedReader):
        self.fh = fh
        self.header = c_wevt_headers.CRIM_HEADER(fh)
        validate_signature(self.header.signature, b"CRIM")

    @property
    def file_size(self):
        """Return size of the whole file."""
        return self.header.size

    def wevt_headers(self):
        """Get the WEVT object for a specific provider"""
        for event_provider in self.header.event_providers:
            yield WEVT(event_provider, self.fh)


class WEVT:
    """Parse WEVT format and reads the files data into memory.
    Additionally, it goes through all items inside the file.
    """

    def __init__(self, provider, fh):
        self.event_provider = provider
        self.offset = provider.offset

        fh.seek(self.offset)
        self.header = c_wevt_headers.WEVT(fh)
        fh.seek(self.offset)
        validate_signature(self.header.signature, b"WEVT")

        self.payload_size = self.header.size
        self.data = memoryview(fh.read(self.payload_size))

    @property
    def len_types(self):
        return self.header.nr_of_types

    @property
    def payload_types(self):
        return self.header.types

    def _choose_wevt_type(self, signature):
        if signature == b"MAPS":
            return MAPS_WEVT_TYPE
        if signature == b"TTBL":
            return TTBL_WEVT_TYPE
        return WEVT_TYPE

    def __iter__(self):
        for type in self.payload_types:
            next_offset = self._next_type_offset(type.offset)
            signature = c_wevt_headers.char[4](self.data[next_offset:])
            yield self._choose_wevt_type(signature)(type.offset, self.data[next_offset:])

    def _next_type_offset(self, type_offset):
        return type_offset - self.offset

    @property
    def provider_id(self):
        return UUID(bytes_le=self.event_provider.ProviderId)

    @property
    def size(self):
        return self.header.size

    def __repr__(self):
        return f"<WEVT providerid={self.provider_id} payload_size={self.payload_size} header={self.header}>"


class WEVT_TYPE:
    """
    A wrapper that is used to create a wevt_object.
    This class assigns this object the correct offset value
    and passes the size of the data.
    """

    valid_signatures = ["CHAN", "TEMP", "PRVA", "TASK", "KEYW", "LEVL", "OPCO", "VMAP", "BMAP", "MAPS", "TTBL", "EVNT"]

    def __init__(self, offset, data: memoryview):
        self.offset = offset
        self.data = data
        self.header = c_wevt_headers.WEVT_TYPE(self.data)
        self.signature = self.header.signature.decode("ascii")
        if self.signature not in self.valid_signatures:
            raise UnknownSignatureException(f"Invalid WEVT_TYPE signature {self.signature}")
        self.payload = data[len(self.header) : self.header.size]

    def __iter__(self):
        offset = self._additional_offset()
        start_offset = len(self.header) + self.offset
        for _ in range(self.nr_of_items):
            item = getattr(wevt_objects, self.signature)(start_offset + offset, self.payload[offset:])
            yield item
            offset += len(item.header)

    def _additional_offset(self):
        """An additional offset for specific wevtobjects"""
        if self.signature == "EVNT":
            return 4
        return 0

    @property
    def nr_of_items(self):
        return self.header.nr_of_items

    @property
    def size(self):
        return self.header.size


class MAPS_WEVT_TYPE(WEVT_TYPE):
    """A specific MAPS type, that behaves differently from WEVT_TYPE

    The MAPS header holds the offsets of its object just behind its header in any order.
    """

    def __iter__(self):
        offset = len(self.header) + self.offset

        for index in range(self.nr_of_items):
            map_offset = c_wevt_headers.uint32(self.payload[index * 4 :])
            data = self.payload[(map_offset - offset) :]
            signature = c_wevt_headers.char[4](data)
            map = self._get_map(signature)(map_offset, data)
            yield map

    def _get_map(self, signature):
        if signature == b"VMAP":
            return wevt_objects.VMAP
        if signature == b"BMAP":
            return wevt_objects.BMAP


class TTBL_WEVT_TYPE(WEVT_TYPE):
    """A specific WEVT Type that loads multiple TEMP."""

    def __iter__(self):
        offset = 0
        start_offset = len(self.header) + self.offset
        for _ in range(self.nr_of_items):
            test_header = wevt_objects.TEMP(start_offset + offset, self.payload[offset:])
            yield test_header
            offset += test_header.size
