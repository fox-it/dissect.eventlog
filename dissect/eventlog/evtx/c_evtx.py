from __future__ import annotations

from dissect.cstruct import cstruct

evtx_def = """
struct EVTX_HEADER {
    char magic[8];
    uint64 first_chunk;
    uint64 last_chunk;
    uint64 next_record_id;
    uint32 header_size;
    uint16 minor_version;
    uint16 major_version;
    uint16 header_block_size;
    uint16 num_chunks;
    char _padding[76];
    uint32 flags;
    uint32 checksum;
};

struct EVTX_CHUNK {
    char magic[8];
    uint64 first_record_nr;
    uint64 last_record_nr;
    uint64 first_record_id;
    uint64 last_record_id;
    uint32 header_size;
    uint32 last_record_offset;
    uint32 free_space_offset;
    uint32 records_checksum;
    char _padding[64];
    uint32 flags;
    uint32 checksum;
    uint32 string_offsets[64];
    uint32 template_ptr[32];
};

struct EVTX_RECORD {
    uint32 signature;
    uint32 size;
    uint64 record_id;
    uint64 time_written;
    char data[size-28];
    uint32 size_copy;
};
"""

c_evtx = cstruct().load(evtx_def)
