from __future__ import annotations

from dissect.cstruct import cstruct

wevt_def = """
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
    char    signature[4];
    uint32  size;
    uint32  nr_of_items;
    uint32  nr_of_names;
    uint32  data_offset;
    uint32  binxml_fragments;
    char    identifier[16];
};

struct TEMP_DESCRIPTOR {
    uint32  unknown0;
    uint8   input_type;
    uint8   output_type;
    uint16  unknown1;
    uint32  unknown2;
    uint32  unknown3;
    uint32  data_offset;
}

struct PRVA {
    uint32  unknown;
    uint32  data_offset;
};

struct TASK {
    uint32  id;
    uint32  message_table_id;
    char    mui_id[16];
    uint32  data_offset;
};

struct KEYW {
    uint64  bitmask;
    uint32  message_table_id;
    uint32  data_offset;
};

struct LEVL {
    uint32  id;
    uint32  message_table_id;
    uint32  data_offset;
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

c_wevt = cstruct().load(wevt_def)
