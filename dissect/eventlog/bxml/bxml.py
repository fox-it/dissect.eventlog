"""Binary XML classes.

Reference:
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b
  - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
"""

from __future__ import annotations

import io
from collections import deque
from dataclasses import dataclass
from functools import partial
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, Protocol
from uuid import UUID

from dissect.util.stream import BufferedStream

from dissect.eventlog.bxml.c_bxml import (
    BXML_TOKEN,
    BXML_TYPE,
    STATIC_TYPE_LENGTHS,
    TYPE_READERS,
    TYPE_TRANSFORMERS,
    c_bxml,
)
from dissect.eventlog.exceptions import BxmlException
from dissect.eventlog.utils import KeyValueCollection

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from dissect.cstruct.types import BaseType
    from typing_extensions import Self


class Element:
    """A Bxml Element that provides a `tag` for a name and contains a value and a list of children."""

    __slots__ = (
        "attributes",
        "children",
        "dependency_id",
        "empty",
        "offset",
        "parent",
        "size",
        "tag",
        "value",
    )

    def __init__(self, offset: int, size: int, tag: str, dependency_id: int) -> None:
        self.attributes: Attributes = Attributes()
        self.children: list[Element] = []
        self.dependency_id: int = dependency_id
        self.empty: bool = False
        self.offset: int = offset
        self.parent: Element = None
        self.size: int = size
        self.tag: str = tag
        self.value: Value | Substitution | str = None

    def __repr__(self) -> str:
        suffix = "/" if self.empty else ""
        if self.attributes:
            return f"<{self.tag} {self.attributes}{suffix}>"
        return f"<{self.tag}{suffix}>"

    @classmethod
    def from_stream(cls, fh: BxmlStream, template: Template | None = None) -> Self:
        current_token = fh.current()
        header = c_bxml.BXML_ELEMENT_START(fh) if template is None else c_bxml.BXML_ELEMENT_START_TPL(fh)
        data_offset = fh.tell()
        name = fh.read_name()

        elem = cls(data_offset, header.data_size, name, getattr(header, "dependency_id", -1))
        if current_token.has_more:
            elem.attributes.from_stream(fh, template)

        _token = fh.peek_next().token
        if _token not in (
            BXML_TOKEN.CLOSE_START_ELEMENT_TAG,
            BXML_TOKEN.CLOSE_EMPTY_ELEMENT_TAG,
        ):
            raise RuntimeError("Expected the tag to get closed.")
        elem.empty = _token == BXML_TOKEN.CLOSE_EMPTY_ELEMENT_TAG
        if not elem.empty:
            # Consume the start element tag
            fh.next()

        return elem

    def add_child(self, element: Element) -> None:
        element.parent = self
        self.children.append(element)


class Template:
    """A representation of a template element that keeps track of the root element."""

    __slots__ = (
        "identifier",
        "offset",
        "root",
        "size",
        "uuid",
    )

    def __init__(self, identifier: int, offset: int, size: int, uuid: UUID, fh: BxmlStream, bxml: Bxml) -> None:
        self.identifier: int = identifier
        self.offset: int = offset
        self.size: int = size
        self.uuid: UUID = uuid
        self.root: Element = self._parse(fh, bxml)

    def __repr__(self) -> str:
        return f"<Template {self.identifier=} {self.offset=:X}, {self.size=:X}>"

    @classmethod
    def from_fh(cls, fh: BxmlStream, reference: c_bxml.BXML_TEMPLATE_REFERENCE, bxml: Bxml) -> Self:
        definition = c_bxml.BXML_TEMPLATE_DEFINITION(fh)
        return cls(
            identifier=reference.template_id,
            offset=reference.offset + len(definition),
            size=definition.data_size,
            uuid=UUID(bytes_le=definition.identifier),
            fh=fh,
            bxml=bxml,
        )

    def _parse(self, fh: BxmlStream, bxml: Bxml) -> Element:
        fh.seek(self.offset)
        elem = bxml.parse(fh, self)
        if fh.tell() > self.offset + self.size:
            raise RuntimeError("Read the offset too far")
        return elem


class ValueDescriptor(Protocol):
    """Describes what a bxml value will look like."""

    type: BXML_TYPE

    @property
    def value(self) -> Any: ...


class Descriptor:
    """Describes how a :class:`Substitution` should be interpretted when encountered in a :class:`Template`."""

    __slots__ = (
        "_fh",
        "_value",
        "is_array",
        "offset",
        "size",
        "type",
    )

    def __init__(self, fh: BinaryIO, struct: c_bxml.BXML_TEMPLATE_VALUE_DESC, offset: int):
        self._fh: BinaryIO = fh
        self._value: Any = None
        self.is_array: bool = bool(struct.type_id & 0x80)
        self.offset: int = offset
        self.size: int = struct.size
        self.type: BXML_TYPE = BXML_TYPE(struct.type_id & 0x7F)

    def __repr__(self) -> str:
        _type = self.type.name
        if self.is_array:
            _type = f"{_type}[]"
        return f"<Descriptor data_offset=0x{self.offset}, data_size=0x{self.size} type={_type}>"

    @classmethod
    def from_fh(cls, fh: BinaryIO, offset: int) -> Self:
        """Read a BXML descriptor from fh."""
        data = c_bxml.BXML_TEMPLATE_VALUE_DESC(fh)
        return cls(fh, data, offset)

    @classmethod
    def read_descriptors(cls, fh: BxmlStream) -> list[Self]:
        output = []
        entries = c_bxml.uint32(fh)

        desc_class = c_bxml.BXML_TEMPLATE_VALUE_DESC

        data_offset = fh.tell() + entries * len(desc_class)
        for _ in range(entries):
            desc = cls(fh, desc_class(fh), data_offset)
            output.append(desc)
            data_offset += desc.size
        # We didn't actually read the descriptors, so we skip over them to speed up the process a bit
        fh.seek(data_offset)
        return output

    @property
    def value(self) -> Any:
        """Lazily evaluate the value, only read it from stream when required."""
        if self._value is not None:
            # If we already defined self._value, return that
            return self._value

        self._fh.seek(self.offset)

        if self.type in (BXML_TYPE.STRING, BXML_TYPE.ANSISTRING):
            # Read and parse the string value
            self._value = self._read_string()
            return self._value

        type_reader = TYPE_TRANSFORMERS.get(self.type)
        if type_reader is None:
            raise BxmlException(f"Unknown value type 0x{self.type:x}")

        data = BytesIO(self._fh.read(self.size))
        result = []
        while data.tell() != self.size:
            result.append(type_reader(data))
            if not self.is_array:
                break

        if result:
            self._value = result[0] if len(result) == 1 else result
        return self._value

    def _read_string(self) -> str | list[str] | bytes:
        data = self._fh.read(self.size)
        if self.type == BXML_TYPE.ANSISTRING:
            return data.decode("utf-8", errors="ignore").rstrip("\x00")

        output = data.decode("utf-16-le").rstrip("\x00")
        if self.is_array:
            output = output.split("\x00")
            output = output if len(output) > 1 else output[0]
        return output


class Value:
    """Defines and holds the data of a bxml value."""

    __slots__ = (
        "_data",
        "_value",
        "optional",
        "type",
    )

    def __init__(self, type: BXML_TYPE, data: bytes | BaseType) -> None:
        self._data: bytes | BaseType = data
        self._value: Any = None
        self.optional: bool = False
        self.type: BXML_TYPE = type

    def __repr__(self) -> str:
        if self._value:
            return self._value
        return f"<Value type={self.type}>"

    @classmethod
    def from_stream(cls, fh: BinaryIO) -> Self:
        _type = BXML_TYPE(c_bxml.uint8(fh))
        if length := STATIC_TYPE_LENGTHS.get(_type):
            data = fh.read(length)
        elif _type == BXML_TYPE.STRING:
            data = c_bxml.BXML_VALUE_TEXT(fh).value
        elif _type == BXML_TYPE.NULL:
            data = b""
        elif _type == BXML_TYPE.BINARY:
            data = fh.read()
        else:
            data = TYPE_READERS.get(_type)(fh)
        return cls(_type, data)

    @property
    def value(self) -> Any:
        if self._value is not None:
            return self._value

        if not isinstance(self._data, bytes) or self.type not in STATIC_TYPE_LENGTHS:
            self._value = self._data
            return self._value

        _value = TYPE_READERS.get(self.type)
        if _value is None:
            raise BxmlException(f"Unexpected value type {self.type:x}")
        self._value = _value(self._data)

        return self._value


@dataclass(slots=True)
class Substitution:
    """Defines which values should be substituted inside a :class:`Template`."""

    id: int
    type: BXML_TYPE
    optional: bool
    is_array: bool

    @classmethod
    def from_fh(cls, fh: BinaryIO, is_optional: bool) -> Self:
        value = c_bxml.BXML_OPTIONAL_SUBSTITUTION(fh)
        _type = BXML_TYPE(value.value_type & 0x7F)
        _is_array = bool(value.value_type & 0x80)
        return cls(
            id=value.sub_id,
            type=_type,
            is_array=_is_array,
            optional=is_optional,
        )


class Attributes(dict[str, Value | Substitution]):
    """A dictionary of attributes, containing their names and values."""

    def from_stream(self, fh: BxmlStream, template: Template | None) -> None:
        """Read attributes from a bxml stream."""
        attr_size = c_bxml.uint32(fh)
        attr_end = fh.tell() + attr_size

        _next = fh.next
        _reader = fh.read_name
        while fh.tell() < attr_end:
            token = _next().token
            if token != BXML_TOKEN.ATTRIBUTE:
                raise RuntimeError("Expected a BXML_ATTRIBUTE")

            name = _reader()
            token = _next().token
            if token not in (
                BXML_TOKEN.VALUE,
                BXML_TOKEN.NORMAL_SUBSTITUTION,
                BXML_TOKEN.OPTIONAL_SUBSTITUTION,
            ):
                raise RuntimeError("Expected a BXML_VALUE or SUBSTITUTION after a bxml attribute")

            if token is BXML_TOKEN.VALUE:
                value = Value.from_stream(fh)
            elif template is None:
                raise RuntimeError("Cannot use a substitution without a template")
            else:
                value = Substitution.from_fh(fh, token is BXML_TOKEN.OPTIONAL_SUBSTITUTION)
            self.update({name: value})


class BxmlName(Protocol):
    """An interface to facilitate different methods to read names with BXML data."""

    def read_name(self, fh: BxmlStream) -> str: ...


class EvtxNameReader:
    """An implementation to read names from an Evtx elf chunk.

    Args:
        elf_chunk_fh: a reference to elf data that contains the name of the data.
    """

    def __init__(self, elf_chunk_fh: BinaryIO) -> None:
        self.fh: BinaryIO = elf_chunk_fh

    def read_name(self, fh: BxmlStream) -> str:
        """Read name from BXML data.

        If the offset is outside the BXML data range elf_chunk data is used.
        """
        offset = c_bxml.uint32(fh)
        if offset == fh.tell():
            name = c_bxml.BXML_NAME(fh)
            if fh.read(2) != b"\x00\x00":
                raise BxmlException("No padding after BXML_NAME")
        else:
            # We need to jump back to the offset, otherwise i
            pos = self.fh.tell()
            self.fh.seek(offset)
            name = c_bxml.BXML_NAME(self.fh)
            self.fh.seek(pos)

        return name.value


class WevtNameReader:
    def read_name(self, fh: BxmlStream) -> str:
        _hash = c_bxml.uint16(fh)
        name = c_bxml.BXML_VALUE_TEXT(fh)
        if fh.read(2) != b"\x00\x00":
            raise BxmlException("No padding after bxml name")
        return name.value


class Token:
    TOKEN_MASK: int = 0x1F
    MORE_MASK: int = 0x40

    __slots__ = ("_token",)

    def __init__(self, token: int) -> None:
        self._token: int = token

    @property
    def has_more(self) -> bool:
        return bool(self._token & self.MORE_MASK)

    @property
    def flags(self) -> int:
        return self._token & ~self.TOKEN_MASK

    @property
    def token(self) -> BXML_TOKEN:
        return BXML_TOKEN(self._token & self.TOKEN_MASK)

    def __repr__(self) -> str:
        return f"<TOKEN_BXML {self.flags=}, {self.token=}, {self.has_more=}>"

    @classmethod
    def from_fh(cls, fh: BxmlStream) -> Self:
        return cls(c_bxml.uint8_t(fh))


class BxmlStream(BufferedStream):
    """Manipulates the datastream and creates some short hand functions to get the current token."""

    def __init__(self, fh: BinaryIO, reader: BxmlName, bxml_offset: int = 0, size: int | None = None):
        super().__init__(fh, 0, size)
        self.bxml_offset = bxml_offset

        self.__queue = deque()
        self.__current: Token = None

        self.read_name = partial(reader.read_name, self)

    read_name: Callable[[], str] = None

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        self.__current = None
        seek_pos = max(0, pos - self.bxml_offset)
        return self.bxml_offset + self._fh.seek(seek_pos, whence)

    def tell(self) -> int:
        return self._fh.tell() + self.bxml_offset

    def read(self, n: int = -1) -> bytes:
        # Reset current value
        self.__current = None
        if not self.__queue:
            return self._fh.read(n)

        result = self.__queue.pop()
        if n > 0:
            n = n - 1
        return result._token.dumps() + self._fh.read(n)

    def next(self) -> Token:
        if self.__queue:
            self.__current = self.__queue.pop()
        else:
            self.__current = Token.from_fh(self._fh)
        return self.__current

    def current(self) -> Token:
        return self.__current

    def peek_next(self) -> Token:
        if not self.__queue:
            self.__queue.append(Token.from_fh(self._fh))
        return self.__queue[0]


class Bxml:
    """Parses a BXML structure using a BxmlStream.

    The parsing of the bxml structure continues until it finds a BXML_END tag or finds a template.
    Bxml keeps track of the templates as they keep being reused.

    The Bxml format is as follows:

    code::

      > FRAGMENT
      > TEMPLATE_DEFINITION
        > START_ELEMENT
        > ATTRIBUTES
        > CLOSE_START_ELEMENT
        > VALUE / BXML_SUBSTITUTION / START_ELEMENT
        > BXML_END_ELEMENT
      > BXML_END
      > DESCRIPTORS
    """

    def __init__(self) -> None:
        self.templates: dict[int, Template] = {}

    def parse(self, fh: BxmlStream, template: Template | None = None) -> Element | Template | None:
        """Parses the bxml stream and returns everything as either a template or fileheader."""
        depth = 0

        element: Element | None = None

        while True:
            _token = fh.next().token

            if _token == BXML_TOKEN.FRAGMENT_HEADER:
                _ = c_bxml.BXML_FRAGMENT_HEADER(fh)
                continue
            if _token == BXML_TOKEN.START_ELEMENT_TAG:
                depth += 1
                _element = Element.from_stream(fh, template)
                if element:
                    element.add_child(_element)
                element = _element
                continue
            if _token in (BXML_TOKEN.END_ELEMENT, BXML_TOKEN.CLOSE_EMPTY_ELEMENT_TAG):
                if depth == 0:
                    raise RuntimeError("Cannot end an element if it never started")
                depth -= 1
                element = element.parent if element.parent is not None else element
                continue
            if _token in (BXML_TOKEN.NORMAL_SUBSTITUTION, BXML_TOKEN.OPTIONAL_SUBSTITUTION):
                if template is None:
                    raise RuntimeError("Cannot use a substitution without a template")
                element.value = Substitution.from_fh(fh, _token is BXML_TOKEN.OPTIONAL_SUBSTITUTION)
                continue
            if _token == BXML_TOKEN.TEMPLATE_INSTANCE:
                return self._read_template_reference(fh)
            if _token == BXML_TOKEN.VALUE:
                if element is None:
                    raise RuntimeError("Cannot parse value for an undefined element")
                element.value = Value.from_stream(fh)
                continue
            if _token == BXML_TOKEN.CHAR_REFERENCE:
                element.value = f"&x{c_bxml.uint16(fh):x};"
                continue
            if _token == BXML_TOKEN.ENTITY_REFERENCE:
                # NOTE: Couldn't find any reference that about more data after a entity reference
                element.value = f"&{fh.read_name()};"
                continue
            if _token == BXML_TOKEN.END:
                if depth != 0:
                    raise RuntimeError("Found an unexpected end of the bxml stream")
                break

            raise RuntimeError("Unknown token found")
        return element

    def _read_template_reference(self, fh: BxmlStream) -> Template:
        """Check whether we already have the template or if we still need to parse it."""
        reference = c_bxml.BXML_TEMPLATE_REFERENCE(fh)
        if template := self.templates.get(reference.template_id):
            return template

        if reference.offset == fh.tell():
            # We have a BXML template definition on our hands
            template = Template.from_fh(fh, reference, self)
            self.templates[reference.template_id] = template
            return template

        raise RuntimeError("Something went wrong, couldn't parse template at the current offset.")


def _stub_function(elem: Element, result: KeyValueCollection, descriptors: list[Descriptor]) -> bool:
    return False


def parse_bxml(
    fh: BxmlStream,
    bxml: Bxml,
    transform_func: Callable[[Element, KeyValueCollection, list[Descriptor]], bool] = _stub_function,
) -> Iterator[KeyValueCollection]:
    """Parse the bxml stream.

    Args:
        fh: BxmlStream to read from
        bxml: A Bxml instance used to parse the bxml stream.
        transform_func: An optional function that transforms the input. Returns `True` if anything changed.
    """
    curr_pos = fh.tell()
    size = fh.seek(0, io.SEEK_END)
    fh.seek(curr_pos, io.SEEK_SET)
    while fh.tell() != size:
        elem = bxml.parse(fh)
        elem, descriptors = _get_element(fh, elem)
        if output := create_record(fh, bxml, elem, descriptors, transform_func):
            yield output


def _get_element(
    fh: BxmlStream,
    elem: Element | Template,
) -> tuple[Element, list[Descriptor]]:
    if isinstance(elem, Template):
        _elem = elem.root
        descriptors = Descriptor.read_descriptors(fh)
    else:
        _elem = elem
        descriptors = []

    return _elem, descriptors


def create_record(
    fh: BxmlStream,
    bxml: Bxml,
    elem: Element | None,
    descriptors: list[Descriptor],
    transform_func: Callable[[Element, KeyValueCollection, list[Descriptor]], bool] = _stub_function,
) -> KeyValueCollection:
    """Put attributes and values of a bxml element in a flat structure.

    Args:
        fh: BxmlStream to read from
        bxml: the bxml element to store any templates in
        elem: The bxml element to search through
        descriptors: a list of descriptors to search through for substitutions
        transform_func: An optional function that transforms the input. Returns `True` if anything changed.
    """
    result = KeyValueCollection()

    if elem is None:
        return result

    elements = [elem]

    while elements:
        current = elements.pop()

        elements.extend(current.children)

        if transform_func(current, result, descriptors):
            continue

        for name, attribute in current.attributes.items():
            _elem = resolve_substitution(attribute, descriptors)

            result[f"{current.tag}_{name}"] = _elem

        if current.value is None:
            continue

        item = resolve_substitution(current.value, descriptors)

        if item.type != BXML_TYPE.BINXML:
            result[current.tag] = item
            continue

        # Parse subelement
        # An attribute cannot be a BINXML element, so we get away to use offset here.
        fh.seek(item.offset)

        sub_elem = bxml.parse(fh)
        _elem, _new_descriptors = _get_element(fh, sub_elem)
        result.update(create_record(fh, bxml, _elem, _new_descriptors, transform_func))
    return result


def resolve_substitution(value: Substitution | Value, descriptors: list[Descriptor]) -> ValueDescriptor:
    """Retrieves the descriptor if it encounters a substitution."""
    if isinstance(value, Substitution):
        return descriptors[value.id]
    return value
