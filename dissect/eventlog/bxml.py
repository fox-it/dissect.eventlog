""" Binary XML classes """


import binascii
from typing import Any, BinaryIO, Dict, List, Tuple
import uuid
from datetime import datetime
from io import BytesIO
from enum import IntEnum

from dissect.cstruct.cstruct import cstruct
from dissect.eventlog.exceptions import BxmlException
from dissect.eventlog.utils import KeyValueCollection
from dissect.util.ts import wintimestamp


class BxmlToken(IntEnum):
    BXML_END = 0x00
    BXML_START_ELEMENT = 0x01
    BXML_CLOSE_START_ELEMENT_TAG = 0x02
    BXML_CLOSE_EMPTY_ELEMENT_TAG = 0x03
    BXML_END_ELEMENT = 0x04
    BXML_VALUE = 0x05
    BXML_ATTRIBUTE = 0x06
    BXML_TOKEN_CHAR_REFERENCE = 0x08
    BXML_TOKEN_ENTITY_REFERENCE = 0x09
    BXML_TEMPLATE_INSTANCE = 0x0C
    BXML_TOKEN_NORMAL_SUBSTITUTION = 0x0D
    BXML_TOKEN_OPTIONAL_SUBSTITUTION = 0x0E
    BXML_FRAGMENT_HEADER = 0x0F


class BxmlType(IntEnum):
    NULL = 0x00
    STRING = 0x01
    ANSITRING = 0x02
    INT8 = 0x03
    UINT8 = 0x04
    INT16 = 0x05
    UINT16 = 0x06
    INT32 = 0x07
    UINT32 = 0x08
    INT64 = 0x09
    UINT64 = 0x0A
    FLOAT = 0x0B
    DOUBLE = 0x0C
    BOOL = 0x0D
    BINARY = 0x0E
    GUID = 0x0F
    SIZET = 0x10
    FILETIME = 0x11
    SYSTEMTIME = 0x12
    SID = 0x13
    HEXINT32 = 0x14
    HEXINT64 = 0x15
    EVTHANDLE = 0x20
    BINXML = 0x21
    EVTXML = 0x23

    @classmethod
    def _missing_(cls, value: int) -> Any:
        """Create a new member if it was missing.

        In some cases the value is win:<number>, this is to accomodate that edge case.
        """
        new_member = int.__new__(cls, value)
        new_member._name_ = str(value)
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)

    def __str__(self) -> str:
        return f"win:{self.name.lstrip('_')}"


bxml_def = """
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
bxml_struct = cstruct()
bxml_struct.load(bxml_def)


def read_systemtime(stream):
    """Read systemtime from stream."""
    st = bxml_struct.SYSTEMTIME(stream)
    return datetime(
        year=st.wYear,
        month=st.wMonth,
        day=st.wDay,
        hour=st.wHour,
        minute=st.wMinute,
        second=st.wSecond,
        microsecond=st.wMilliseconds * 1000,
    )


def read_guid(stream) -> str:
    """Read guid from stream."""
    guid = uuid.UUID(bytes=stream.read(16))
    guid_str = str(guid).upper()
    return f"{{{guid_str}}}"


def read_sid(stream) -> str:
    """Read SID from stream."""
    sid = bxml_struct.SID(stream)
    revision_str = str(sid.revision)
    last_authority = str(bytearray(sid.authority)[-1])
    sub_authorities = [str(authority) for authority in sid.subAuthorities]
    return "-".join(["S", revision_str, last_authority] + sub_authorities)


TYPE_READERS = {
    BxmlType.NULL: lambda s: None,
    BxmlType.STRING: bxml_struct.wchar[None].read,
    BxmlType.ANSITRING: bxml_struct.char[None].read,
    BxmlType.INT8: bxml_struct.int8.read,
    BxmlType.UINT8: bxml_struct.uint8.read,
    BxmlType.INT16: bxml_struct.int16.read,
    BxmlType.UINT16: bxml_struct.uint16.read,
    BxmlType.INT32: bxml_struct.int32.read,
    BxmlType.UINT32: bxml_struct.uint32.read,
    BxmlType.INT64: bxml_struct.int64.read,
    BxmlType.UINT64: bxml_struct.uint64.read,
    BxmlType.FLOAT: bxml_struct.float.read,
    BxmlType.DOUBLE: bxml_struct.double.read,
    BxmlType.BOOL: lambda stream: bxml_struct.uint8.read(stream),
    BxmlType.BINARY: lambda stream: binascii.hexlify(stream.read()),
    BxmlType.GUID: read_guid,
    BxmlType.SIZET: (
        lambda stream: f"0x{bxml_struct.uint32(stream):x}"
        if len(stream.getvalue()) == 4
        else f"0x{bxml_struct.uint64(stream):x}"
    ),
    BxmlType.FILETIME: lambda stream: wintimestamp(bxml_struct.uint64(stream)),
    BxmlType.SYSTEMTIME: lambda stream: read_systemtime(stream),
    BxmlType.SID: read_sid,
    BxmlType.HEXINT32: lambda stream: f"0x{bxml_struct.uint32(stream):x}",
    BxmlType.HEXINT64: lambda stream: f"0x{bxml_struct.uint64(stream):x}",
}


class BxmlTag:
    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.children = []

    def __str__(self):
        if self.attributes:
            temp_items = " ".join(f'{k}="{v}"' for k, v in self.attributes.items())
            result = f"<{self.name} {temp_items}>"
        else:
            result = f"<{self.name}>"

        for child in self.children:
            result += str(child)

        result += f"</{self.name}>"

        return result

    def add_children(self, tags: list) -> None:
        self.children.extend(tags)

    def add_attributes(self, attribute: dict) -> None:
        self.attributes.update(attribute)


class BxmlSub:
    def __init__(self, sub_id):
        self.sub_id = sub_id
        self.value = None

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return str(self.value)

    def set(self, value) -> None:
        self.value = value

    def get(self) -> Any:
        return self.value


class Template:
    def __init__(self):
        self.subs: Dict[int, BxmlSub] = {}
        self.mapping = {}
        self.element = None
        self.child_templates: List[Template] = []

    def __str__(self):
        return str(self.element)

    def add_sub(self, sub_id: int, tag: BxmlSub):
        self.subs[sub_id] = tag

    def create_map(self):
        self.mapping = {}
        self._createmap(self.element, [])

    def _createmap(self, tag: BxmlTag, path):
        for child in tag.children:
            if isinstance(child, BxmlTag):
                self._createmap(child, path + [child])

            if isinstance(child, BxmlSub):
                if not path:
                    continue

                previous_tag: BxmlTag = path[-1]
                if "Name" in previous_tag.attributes:
                    self.mapping[previous_tag.attributes["Name"]] = child.sub_id
                elif previous_tag.name == "UserData":
                    continue
                else:
                    self.mapping[previous_tag.name] = child.sub_id

        for key, value in tag.attributes.items():
            if isinstance(value, BxmlSub):
                self.mapping[key] = value.sub_id

    def as_map(self):
        result_dict = {}

        for key, value in self.mapping.items():
            result_dict[key] = self.subs[value].get()

        for template in self.child_templates:
            result_dict.update(template.as_map())

        return result_dict

    def as_full_map(self):
        key_value_pair = KeyValueCollection()
        self._get_map_recursive(self.element, [], key_value_pair)
        return key_value_pair

    def _get_map_recursive(self, obj, path, collection: KeyValueCollection):
        if isinstance(obj, Template):
            self._get_map_recursive(obj.element, path, collection)

        elif isinstance(obj, BxmlSub):
            self._get_map_recursive(obj.get(), path, collection)

        elif isinstance(obj, BxmlTag):
            for child in obj.children:
                self._get_map_recursive(child, path + [obj], collection)

            if obj.name == "Event":
                return

            for key, value in obj.attributes.items():
                if obj.name == "Data" and key == "Name":
                    continue

                collection[obj.name + "_" + key] = value
        elif isinstance(path[-1], BxmlTag):
            previous_tag: BxmlTag = path[-1]
            path_str = "_".join([val.name for val in path[2:]])
            if previous_tag.name == "Data" and "Name" in previous_tag.attributes:
                collection[previous_tag.attributes["Name"]] = obj
                return

            collection[path_str] = obj

    def add_child_template(self, tpl):
        self.child_templates.append(tpl)


class Bxml:
    """An object that keeps track of the BXML streams"""

    def __init__(self, bxml_stream: BytesIO, elf_chunk_stream: BytesIO) -> None:
        self.bxml_stream = bxml_stream
        self.elf_chunk_stream = elf_chunk_stream
        self.data_offset: int = None
        self.template: Template = None
        self.templates: Dict[Template] = None

    @property
    def current_offset(self) -> int:
        """Current offset in the BXML data stream."""
        return self.data_offset + self.bxml_stream.tell()

    def read_name_from_stream(self) -> str:
        """Use _reader to read a specific name from stream"""
        return self._reader.read()

    def set_name_reader(self, reader) -> None:
        self._reader = reader

    def read_token(self, template: Template = None):
        """Read the next BXML token from stream."""
        token = Token(bxml_struct.uint8(self.bxml_stream))

        if token == BxmlToken.BXML_END:
            return BxmlToken.BXML_END
        elif token == BxmlToken.BXML_START_ELEMENT:
            return self.parse_start_element(token.has_more, template)
        elif token == BxmlToken.BXML_CLOSE_START_ELEMENT_TAG:
            return BxmlToken.BXML_CLOSE_START_ELEMENT_TAG
        elif token == BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG:
            return BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG
        elif token == BxmlToken.BXML_END_ELEMENT:
            return BxmlToken.BXML_END_ELEMENT
        elif token == BxmlToken.BXML_VALUE:
            return self.read_value(token.has_more, template)
        elif token == BxmlToken.BXML_ATTRIBUTE:
            return self.read_attribute(template)
        elif token == BxmlToken.BXML_TOKEN_CHAR_REFERENCE:
            return self.read_char_reference()
        elif token == BxmlToken.BXML_TOKEN_ENTITY_REFERENCE:
            return self.read_entity_reference(token.has_more, template)
        elif token == BxmlToken.BXML_TEMPLATE_INSTANCE:
            return self.read_template_instance()
        elif token == BxmlToken.BXML_TOKEN_NORMAL_SUBSTITUTION or token == BxmlToken.BXML_TOKEN_OPTIONAL_SUBSTITUTION:
            return self.substitute_token_and_add_to_template(template)
        elif token == BxmlToken.BXML_FRAGMENT_HEADER:
            return self.read_fragment_header()
        else:
            raise BxmlException(f"Unknown BXML token {token}")

    def parse_start_element(self, more_data: bool, template: Template) -> BxmlTag:
        if template:
            bxml_struct.BXML_ELEMENT_START_TPL(self.bxml_stream)
        else:
            bxml_struct.BXML_ELEMENT_START(self.bxml_stream)

        tag = self._read_tag_and_attributes(more_data, template)

        next_tag = self.read_token(template)

        if self._is_end_empty_element(next_tag):
            return tag

        if not self._is_end_start_element(next_tag):
            raise BxmlException("Unexpected tag, expected an END element")

        tag.add_children([child for child in self._read_children(template)])
        return tag

    def _read_tag_and_attributes(self, flag_more: bool, template: Template) -> BxmlTag:
        tag = BxmlTag(self.read_name_from_stream())
        if flag_more:
            attributes = {key: value for key, value in self._read_attributes(template)}
            tag.add_attributes(attributes)
        return tag

    def _read_attributes(self, template: Template) -> Tuple[str, Any]:
        attr_size = bxml_struct.uint32(self.bxml_stream)
        attr_end = self.bxml_stream.tell() + attr_size
        while self.bxml_stream.tell() < attr_end:
            yield self.read_token(template)

    def _read_template_reference_and_data(self) -> Template:
        """Read template reference and create a template"""
        reference = bxml_struct.BXML_TEMPLATE_REFERENCE(self.bxml_stream)

        if reference.offset == self.current_offset:
            template = self._create_and_fill_template()

            self.templates[reference.offset] = template
        else:
            template = self.templates[reference.offset]

        return template

    def _create_and_fill_template(self) -> Template:
        bxml_struct.BXML_TEMPLATE_DEFINITION(self.bxml_stream)
        bxml_struct.BXML_FRAGMENT_HEADER(self.bxml_stream)

        template = Template()

        tag = self.read_token(template)
        if tag == BxmlToken.BXML_FRAGMENT_HEADER:
            tag = self.read_token(template)

        template.element = self.read_token(template)
        if self.read_token(template) != BxmlToken.BXML_END:
            raise BxmlException("Expected BxmlEnd")

        template.create_map()
        return template

    def _is_end_empty_element(self, next_tag: BxmlTag) -> bool:
        return next_tag is BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG

    def _is_end_start_element(self, next_tag: BxmlTag) -> bool:
        return next_tag is BxmlToken.BXML_CLOSE_START_ELEMENT_TAG

    def _read_children(self, template) -> List[Any]:
        while True:
            tag = self.read_token(template)
            if tag == BxmlToken.BXML_END_ELEMENT:
                break
            yield tag

    def _read_string_value(self, flag_more: bool, template: Template) -> str:
        value = bxml_struct.BXML_VALUE_TEXT(self.bxml_stream).value
        if flag_more:
            value += self.read_token(template)
        return value

    def read_value(self, flag_more: bool, template: Template) -> str:
        value_type = bxml_struct.uint8(self.bxml_stream)
        if value_type == BxmlType.STRING:
            return self._read_string_value(flag_more, template)

        raise BxmlException(f"Unexpected value type 0x{value_type:x}")

    def read_attribute(self, template: Template) -> Tuple[str, Any]:
        name = self.read_name_from_stream()
        value = self.read_token(template)
        return name, value

    def read_entity_reference(self, flag_more: bool, template: Template) -> str:
        entity = self.read_name_from_stream()
        reference = f"&{entity};"
        if flag_more:
            reference += self.read_token(template)
        return reference

    def substitute_token_and_add_to_template(self, template: Template) -> BxmlSub:
        substitution = bxml_struct.BXML_OPTIONAL_SUBSTITUTION(self.bxml_stream)
        bxml_sub = BxmlSub(substitution.sub_id)
        template.add_sub(substitution.sub_id, bxml_sub)
        return bxml_sub

    def read_fragment_header(self) -> BxmlToken:
        bxml_struct.BXML_FRAGMENT_HEADER(self.bxml_stream)
        return BxmlToken.BXML_FRAGMENT_HEADER

    def read_char_reference(self) -> str:
        return f"&x{bxml_struct.uint16(self.bxml_stream):x};"

    def read_template_instance(self) -> Template:
        _template = self._read_template_reference_and_data()

        descriptors = [desc for desc in BxmlTemplateDescriptor.read_descriptors_from_stream(self.bxml_stream)]

        for index, descriptor in enumerate(descriptors):
            value = _read_descriptor_value(self, descriptor)

            if isinstance(value, Template):
                _template.add_child_template(value)

            if index in _template.subs:
                _template.subs[index].set(value)

        return _template


class BxmlNameReader:
    """An interface to facilitate different methods to read names with BXML data."""

    def __init__(self, bxml: Bxml) -> None:
        self.bxml = bxml
        self.bxml_datastream = bxml.bxml_stream
        self.elf_chunk_stream = bxml.elf_chunk_stream

    def read(self) -> str:
        """Read the name from the bxml_datastream."""
        pass

    def _read_and_validate_padding(self) -> None:
        """Determine if the padding after name equals 0"""
        padding = self.bxml_datastream.read(2)
        if padding != b"\x00\x00":
            raise BxmlException("No padding after BXML_NAME")


class EvtxNameReader(BxmlNameReader):
    """Evtx method to read names in BXML."""

    def read(self) -> str:
        """Read name from BXML data.

        If the offset is outside the BXML data range elf_chunk data is used.
        """
        offset = bxml_struct.uint32(self.bxml_datastream)
        if offset == self.bxml.current_offset:
            element_name = self._read_name_from_bxml_stream()
        else:
            element_name = self._read_name_from_elf_stream(offset)

        return element_name.value

    def _read_name_from_elf_stream(self, offset: int):
        """Read the name from the ELF chunk, but keeps the needle position."""
        pos = self.elf_chunk_stream.tell()
        self.elf_chunk_stream.seek(offset)
        element_name = bxml_struct.BXML_NAME(self.elf_chunk_stream)
        self.elf_chunk_stream.seek(pos)
        return element_name

    def _read_name_from_bxml_stream(self):
        """Read the name from the bxml_datastream."""
        element_name = bxml_struct.BXML_NAME(self.bxml_datastream)
        self._read_and_validate_padding()
        return element_name


class WevtNameReader(BxmlNameReader):
    """WEVT method for reading names.

    WEVT uses a different method to read BXML_NAME
    There is no offset and additional unknown 32-bit value.
    """

    def read(self):
        return self._read_bxml_data_name().value

    def _read_bxml_data_name(self):
        self._read_hash_value()
        element_name = bxml_struct.BXML_VALUE_TEXT(self.bxml_datastream)
        self._read_and_validate_padding()
        return element_name

    def _read_hash_value(self):
        """Reads the hash value for the object."""
        return bxml_struct.uint16(self.bxml_datastream)


class Token:
    TOKEN_MASK = 0x1F
    MORE_MASK = 0x40

    def __init__(self, token: int) -> None:
        self.flags = token & ~self.TOKEN_MASK
        self.token = token & self.TOKEN_MASK
        self.has_more = self.flags & self.MORE_MASK

    def __eq__(self, other) -> bool:
        if isinstance(other, BxmlToken):
            return self.token == other
        return False


def parse_bxml(bxml: Bxml):
    while True:
        token = bxml.read_token(bxml.template)
        if token == BxmlToken.BXML_END:
            raise BxmlException("Unexpected BxmlEnd")

        if token == BxmlToken.BXML_FRAGMENT_HEADER:
            continue

        if isinstance(token, BxmlTag):
            key_collection = KeyValueCollection()
            Template()._get_map_recursive(token, [], key_collection)
            return key_collection
        else:
            if bxml.read_token() != BxmlToken.BXML_END:
                pass

            return token.as_full_map()


class BxmlTemplateDescriptor:
    DESCRIPTOR_MASK = 0x7F
    ARRAY_MASK = 0x80

    def __init__(self, descriptor_struct):
        self.descriptor_struct = descriptor_struct

        self.type_id = BxmlType(self.descriptor_struct.type_id & self.DESCRIPTOR_MASK)
        self.is_array = (self.descriptor_struct.type_id & self.ARRAY_MASK) == self.ARRAY_MASK
        self.has_type_reader = self.type_id in TYPE_READERS

    @property
    def size(self):
        return self.descriptor_struct.size

    @property
    def value_type(self):
        return TYPE_READERS[self.type_id]

    @classmethod
    def read_descriptors_from_stream(cls, stream: BytesIO):
        """Read a range of BXML descriptors from stream."""
        entry_count = bxml_struct.uint32(stream)
        for _ in range(entry_count):
            yield cls.from_stream(stream)

    @classmethod
    def from_stream(cls, stream: BytesIO):
        """Read a singular BXML descriptors from stream."""
        struct = bxml_struct.BXML_TEMPLATE_VALUE_DESC(stream)
        return cls(struct)


def _read_descriptor_value(bxml: Bxml, descriptor: BxmlTemplateDescriptor) -> Any:
    try:
        value = read_value(bxml, descriptor, None)
    except BxmlException:
        value = "<CORRUPT DATA>"
    return value


def read_value(binxml: Bxml, descriptor: BxmlTemplateDescriptor, template: Template) -> Any:
    """
    0x00 NullType NULL or empty
    0x01 StringType Unicode string
    0x02 AnsiStringType ASCII string
    0x03 Int8Type 8-bit integer signed
    0x04 UInt8Type 8-bit integer unsigned
    0x05 Int16Type 16-bit integer signed
    0x06 UInt16Type 16-bit integer unsigned
    0x07 Int32Type 32-bit integer signed
    0x08 UInt32Type 32-bit integer unsigned
    0x09 Int64Type 64-bit integer signed
    0x0a UInt64Type 64-bit integer unsigned
    0x0b Real32Type Floating point 32-bit (single precision)
    0x0c Real64Type Floating point 64-bit (double precision)
    0x0d BoolType Boolean
    0x0e BinaryType Binary data
    0x0f GuidType GUID
    0x10 SizeT Type Size type
    0x11 FileTimeType Filetime (64-bit)
    0x12 SysTimeType System time (128-bit)
    0x13 SidType NT Security Identifier (SID)
    0x14 HexInt32Type 32-bit integer hexadecimal
    0x15 HexInt64Type 64-bit integer hexadecimal
    0x20 EvtHandle
    0x21 BinXmlType Binary XML fragment
    0x23 EvtXml
    """

    if descriptor.has_type_reader:
        data = binxml.bxml_stream.read(descriptor.size)
        stream = BytesIO(data)

        if descriptor.is_array:
            return [descriptor for descriptor in read_descriptor_array(stream, descriptor)]

        if descriptor.type_id == BxmlType.STRING:
            return data.decode("utf-16-le").rstrip("\x00")

        if descriptor.type_id == BxmlType.ANSITRING:
            return data.rstrip(b"\x00")

        return descriptor.value_type(stream)

    if descriptor.type_id == BxmlType.BINXML:
        return read_binxml_fragment(binxml, template, descriptor.size)

    raise BxmlException(f"Unknown value type 0x{descriptor.type_id:x}")


def read_descriptor_array(stream: BinaryIO, descriptor: BxmlTemplateDescriptor) -> List[Any]:
    while stream.tell() != descriptor.size:
        yield descriptor.value_type(stream)


def read_binxml_fragment(bxml: Bxml, template: Template, length):
    pos = bxml.bxml_stream.tell()
    element = bxml.read_token(template)
    if element == BxmlToken.BXML_FRAGMENT_HEADER:
        element = bxml.read_token(template)

    bxml.bxml_stream.seek(pos + length)
    return element
