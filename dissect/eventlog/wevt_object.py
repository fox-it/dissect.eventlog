from typing import List
from dissect.eventlog.bxml import Bxml, Template, WevtNameReader, parse_bxml, BxmlType
from dissect.cstruct import cstruct
from uuid import UUID
from io import BytesIO

wevt_object_def = """
struct DATA_ITEM {
    uint32  size;
    wchar   name[(size/2)-2];
};

struct CHAN {
    uint32  id;
    uint32  data_offset;
    uint32  nr;
    uint32  message_table_id;
};

struct TEMP {
    char          signature[4];
    uint32        size;
    uint32        nr_of_items;
    uint32        nr_of_names;
    uint32        data_offset;
    uint32        binxml_fragments;
    char          identifier[16];
};

struct TEMP_DESCRIPTOR {
    uint32        unknown0;
    uint8         input_type;
    uint8         output_type;
    uint16        unknown1;
    uint32        unknown2;
    uint32        unknown3;
    uint32        data_offset;
}

struct PRVA {
    uint32        unknown;
    uint32        data_offset;
};

struct TASK {
    uint32        id;
    uint32        message_table_id;
    char          mui_id[16];
    uint32        data_offset;
};

struct KEYW {
    uint64        bitmask;
    uint32        message_table_id;
    uint32        data_offset;
};

struct LEVL {
    uint32        id;
    uint32        message_table_id;
    uint32        data_offset;
};

struct EVNT {
    uint16  id;
    uchar   version;
    uchar   channel;
    uchar   level;
    uchar   opcode;
    uint16  task;
    uint64  keyword;
    uint32  message_table_id;
    uint32  template_offset;
    uint32  opcode_offset;
    uint32  level_offset;
    uint32  task_offset;
    uint32  data_counter;
    uint32  data_offset;
    uint32  flags;
};

struct OPCO {
    uint16  task_id;
    uint16  value;
    uint32  message_table_id;
    uint32  data_offset;
};

struct VMAP {
    char   signature[4];
    uint32 size;
    uint32 data_offset;
};

struct BMAP {
    char   signature[4];
    uint32 size;
    uint32 data_offset;
};
"""

wevt_objects = cstruct()
wevt_objects.load(wevt_object_def)


class WevtObject:
    """Base object that functions as a wrapper for the header"""

    def __init__(self, offset, data):
        self.offset = offset
        self.header = getattr(wevt_objects, self.__class__.__name__)(data)
        self.data = data[len(self.header) :]
        self.data_start = self.offset + len(self.header)
        self.data_offset = self.header.data_offset - self.data_start

    def extract_name(self, data_offset):
        """data_offset is a relative offset that usually points to the data_item.
        This point is used to read the name for this specific"""
        return wevt_objects.DATA_ITEM(self.data[data_offset:]).name.rstrip("\x00")

    def __getattribute__(self, name: str):
        try:
            return super().__getattribute__(name)
        except AttributeError:
            pass
        return getattr(self.header, name)

    def __repr__(self):
        """Use __slots__ to get all the data we need from the object"""
        output_data = [item + "=" + str(getattr(self, item)) for item in self.__slots__]
        return f"{self.__class__.__name__} {' '.join(output_data)}"


class WevtName(WevtObject):
    def __init__(self, offset, data):
        super().__init__(offset, data)
        self.name = self.extract_name(self.data_offset)


class CHAN(WevtName):
    __slots__ = ["offset", "id", "message_table_id", "name", "nr"]


class OPCO(WevtName):
    __slots__ = ["offset", "task_id", "value", "message_table_id", "name"]


class LEVL(WevtName):
    __slots__ = ["offset", "id", "message_table_id", "name"]


class KEYW(WevtName):
    __slots__ = ["offset", "bitmask", "message_table_id", "name"]


class VMAP(WevtName):
    __slots__ = ["offset", "name"]


class BMAP(WevtName):
    __slots__ = ["offset", "name"]


class PRVA(WevtObject):
    __slots__ = ["offset", "unknown"]


class TASK(WevtName):
    __slots__ = ["offset", "id", "message_table_id", "mui_id", "name"]

    def __init__(self, offset, data):
        super().__init__(offset, data)
        self.mui_id = UUID(bytes_le=self.header.mui_id)


class EVNT(WevtObject):
    __slots__ = [
        "offset",
        "id",
        "version",
        "channel",
        "level",
        "opcode",
        "task",
        "keyword",
        "message_table_id",
        "level_offset",
        "opcode_offset",
        "task_offset",
        "template_offset",
        "flags",
    ]


class TEMP(WevtObject):
    __slots__ = ["offset", "identifier", "template", "names"]

    def __init__(self, offset, data):
        super().__init__(offset, data)
        self.template = self._extract_bxml_template()

        self.identifier = UUID(bytes_le=self.header.identifier)
        self.names: List[TEMP_DESCRIPTOR] = []
        offset = self.data_offset
        for _ in range(self.header.nr_of_names):
            desc = TEMP_DESCRIPTOR(self.data_start + offset, self.data[offset:])
            self.names.append(desc)
            offset += len(desc.header)

    def _create_template_descriptor(self, start_offset, offset):
        return TEMP_DESCRIPTOR(start_offset + offset, self.data[offset:])

    def _extract_bxml_template(self):
        bxml_datastream = BytesIO(self.data[: self.data_offset])
        bxml = Bxml(bxml_stream=bxml_datastream, elf_chunk_stream=None)
        bxml.set_name_reader(WevtNameReader(bxml))
        bxml.template = Template()
        return parse_bxml(bxml)


class TEMP_DESCRIPTOR(WevtName):
    __slots__ = ["inType", "outType", "name"]

    def __init__(self, offset, data):
        super().__init__(offset, data)

        self.inType = str(BxmlType(self.header.input_type))
        self.outType = str(BxmlType(self.header.output_type))
