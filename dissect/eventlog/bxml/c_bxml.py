from __future__ import annotations

from dissect.cstruct import cstruct

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
c_bxml = cstruct().load(bxml_def)
