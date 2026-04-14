from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

import dissect.eventlog.wevt.wevt_object as wevt_objects
from dissect.eventlog.exceptions import UnknownSignatureException
from dissect.eventlog.wevt.c_wevt import c_wevt

if TYPE_CHECKING:
    from collections.abc import Iterator


class CRIM:
    """Start header of the WEVT_TEMPLATE
    Holds the number of providers inside the template.
    """

    fh: BinaryIO
    header: c_wevt.CRIM_HEADER

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_wevt.CRIM_HEADER(fh)
        if self.header.signature != b"CRIM":
            raise UnknownSignatureException(f"Invalid signature, expected b'CRIM' got {self.header.signature}")

    @property
    def file_size(self) -> int:
        """Return size of the whole file."""
        return self.header.size

    def wevt_headers(self) -> Iterator[WEVT]:
        """Get the WEVT object for a specific provider."""
        for event_provider in self.header.event_providers:
            yield WEVT(event_provider, self.fh)


class WEVT:
    """Parse WEVT format and reads the files data into memory.
    Additionally, it goes through all items inside the file.
    """

    def __init__(self, provider: c_wevt.Event_Descriptor, fh: BinaryIO):
        self.event_provider = provider
        self.offset: int = provider.offset

        fh.seek(self.offset)
        self.header = c_wevt.WEVT(fh)
        fh.seek(self.offset)
        if self.header.signature != b"WEVT":
            raise UnknownSignatureException(f"Invalid signature, expected b'WEVT' got {self.header.signature}")

        self.payload_size = self.header.size
        self.data = memoryview(fh.read(self.payload_size))

    def __repr__(self) -> str:
        return f"<WEVT provider_id={self.provider_id} payload_size={self.payload_size} header={self.header}>"

    @property
    def len_types(self) -> int:
        return self.header.nr_of_types

    @property
    def payload_types(self) -> list[c_wevt.WEVT_TYPES]:
        return self.header.types

    def _choose_wevt_type(self, signature: bytes) -> type[WEVT_TYPE]:
        if signature == b"MAPS":
            return MAPS_WEVT_TYPE
        if signature == b"TTBL":
            return TTBL_WEVT_TYPE
        return WEVT_TYPE

    def __iter__(self) -> Iterator[WEVT_TYPE]:
        for _type in self.payload_types:
            next_offset = self._next_type_offset(_type.offset)
            signature = c_wevt.char[4](self.data[next_offset:])
            yield self._choose_wevt_type(signature)(_type.offset, self.data[next_offset:])

    def _next_type_offset(self, offset: int) -> int:
        return offset - self.offset

    @property
    def provider_id(self) -> UUID:
        return UUID(bytes_le=self.event_provider.ProviderId)

    @property
    def size(self) -> int:
        return self.header.size


class WEVT_TYPE:
    """A wrapper that is used to create a wevt_object.
    This class assigns this object the correct offset value
    and passes the size of the data.
    """

    valid_signatures: tuple[str, ...] = (
        "CHAN",
        "TEMP",
        "PRVA",
        "TASK",
        "KEYW",
        "LEVL",
        "OPCO",
        "VMAP",
        "BMAP",
        "MAPS",
        "TTBL",
        "EVNT",
    )

    def __init__(self, offset: int, data: memoryview):
        self.offset = offset
        self.data = data
        self.header = c_wevt.WEVT_TYPE(self.data)
        self.signature = self.header.signature.decode("ascii")
        if self.signature not in self.valid_signatures:
            raise UnknownSignatureException(f"Invalid WEVT_TYPE signature {self.signature}")
        self.payload = data[len(self.header) : self.header.size]

    def __iter__(self) -> Iterator[WEVT_TYPE]:
        offset = 4 if self.signature == "EVNT" else 0
        start_offset = len(self.header) + self.offset
        for _ in range(self.nr_of_items):
            item = getattr(wevt_objects, self.signature)(start_offset + offset, self.payload[offset:])
            yield item
            offset += len(item.header)

    @property
    def nr_of_items(self) -> int:
        return self.header.nr_of_items

    @property
    def size(self) -> int:
        return self.header.size


class MAPS_WEVT_TYPE(WEVT_TYPE):
    """A specific MAPS type, that behaves differently from WEVT_TYPE.

    The MAPS header holds the offsets of its object just behind its header in any order.
    """

    def __iter__(self):
        offset = len(self.header) + self.offset

        for index in range(self.nr_of_items):
            map_offset = c_wevt.uint32(self.payload[index * 4 :])
            data = self.payload[(map_offset - offset) :]
            signature = c_wevt.char[4](data)
            map = self._get_map(signature)(map_offset, data)
            yield map

    def _get_map(self, signature: bytes) -> type[wevt_objects.WevtName] | None:
        if signature == b"VMAP":
            return wevt_objects.VMAP
        if signature == b"BMAP":
            return wevt_objects.BMAP
        return None


class TTBL_WEVT_TYPE(WEVT_TYPE):
    """A specific WEVT Type that loads multiple TEMP."""

    def __iter__(self) -> Iterator[wevt_objects.TEMP]:
        offset = 0
        start_offset = len(self.header) + self.offset
        for _ in range(self.nr_of_items):
            test_header = wevt_objects.TEMP(start_offset + offset, self.payload[offset:])
            yield test_header
            offset += test_header.size
