# - http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-EVEN6].pdf
# - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc

import io
import logging
import os

from dissect import cstruct

from dissect.eventlog.bxml import Bxml, BxmlSub, EvtxNameReader, parse_bxml
from dissect.eventlog.exceptions import MalformedElfChnkException

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EVTX", "CRITICAL"))

evtx = cstruct.cstruct()
evtx.load(
    """
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
)


class ElfChnk:
    def __init__(self, d, path=None):
        self.path = path
        self.stream = io.BytesIO(d)
        self.header = evtx.EVTX_CHUNK(self.stream)

        if self.header.magic != b"ElfChnk\x00":
            if self.header.magic != b"\x00\x00\x00\x00\x00\x00\x00\x00":
                log.error(f"{self.path}: Bad ElfChnk magic")

            raise MalformedElfChnkException("Bad ElfChnk magic")

        self.empty = self.header.free_space_offset == 512

        self.names = {}
        self.templates = {}
        self.data_offset = 0

    def read(self, records=True):
        try:
            while True:
                offset = self.stream.tell()
                try:
                    r = evtx.EVTX_RECORD(self.stream)
                except EOFError:
                    break

                if r.signature != 0x2A2A:
                    break

                # Truncated or partially written record
                if r.size != r.size_copy:
                    continue

                self.data_offset = offset + 24

                bxml_data = io.BytesIO(r.data)
                bxml = Bxml(bxml_stream=bxml_data, elf_chunk_stream=self.stream)
                bxml.data_offset = self.data_offset
                bxml.templates = self.templates
                bxml.template = None
                bxml.set_name_reader(EvtxNameReader(bxml))
                rec = parse_bxml(bxml)

                # Validate record
                if (
                    "TimeCreated_SystemTime" not in rec
                    or (
                        isinstance(rec["TimeCreated_SystemTime"], BxmlSub)
                        and rec["TimeCreated_SystemTime"].get() is None
                    )
                    or rec["TimeCreated_SystemTime"] is None
                ):
                    log.warning("Missing timestamp in record")
                    continue

                yield rec
        except Exception as e:
            if not self.empty:
                log.error(f"Exception when processing chunk: {e!r}")
                raise MalformedElfChnkException()


class Evtx:
    """Microsoft Event logs"""

    def __init__(self, fh, path=None):
        self.path = path
        self.fh = fh
        self.header = evtx.EVTX_HEADER(self.fh)
        self.count = 0

    def __iter__(self):
        chunk_offset = self.header.header_block_size

        skip = self.header.header_block_size - len(evtx.EVTX_HEADER)
        if skip > 0:
            self.fh.read(skip)

        while True:

            chunk = self.fh.read(0x10000)
            if len(chunk) != 0x10000:
                break

            try:
                c = ElfChnk(chunk, self.path)
                for r in c.read():
                    yield r
                    self.count += 1
            except MalformedElfChnkException:
                continue

            chunk_offset += 0x10000
