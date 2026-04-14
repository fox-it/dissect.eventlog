# - http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-EVEN6].pdf
# - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
from __future__ import annotations

import io
import logging
import os

from dissect.eventlog.bxml import Bxml, BxmlSub, EvtxNameReader, parse_bxml
from dissect.eventlog.evtx.c_evtx import c_evtx
from dissect.eventlog.exceptions import MalformedElfChnkException

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EVTX", "CRITICAL"))


class ElfChnk:
    def __init__(self, d, path=None):
        self.path = path
        self.stream = io.BytesIO(d)
        self.header = c_evtx.EVTX_CHUNK(self.stream)

        if self.header.magic != b"ElfChnk\x00":
            if self.header.magic != b"\x00\x00\x00\x00\x00\x00\x00\x00":
                log.error("%s: Bad ElfChnk magic", self.path)

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
                    r = c_evtx.EVTX_RECORD(self.stream)
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
        except Exception:
            if not self.empty:
                log.exception("Exception when processing chunk")
                raise MalformedElfChnkException


class Evtx:
    """Microsoft Event logs."""

    def __init__(self, fh, path=None):
        self.path = path
        self.fh = fh
        self.header = c_evtx.EVTX_HEADER(self.fh)
        self.count = 0

    def __iter__(self):
        chunk_offset = self.header.header_block_size

        skip = self.header.header_block_size - len(c_evtx.EVTX_HEADER)
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
