# - http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-EVEN6].pdf
# - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
from __future__ import annotations

import io
import logging
import os
from typing import TYPE_CHECKING, BinaryIO

from dissect.eventlog.bxml import (
    Bxml,
    BxmlStream,
    EvtxNameReader,
    parse_bxml,
)
from dissect.eventlog.bxml.c_bxml import BXML_TYPE
from dissect.eventlog.evtx.c_evtx import c_evtx
from dissect.eventlog.exceptions import MalformedElfChnkException

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.eventlog.bxml import Element
    from dissect.eventlog.utils import KeyValueCollection

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EVTX", "CRITICAL"))


def _data_func(elem: Element, result: KeyValueCollection) -> bool:
    attributes = elem.attributes
    check = elem.tag == "Data" and "Name" in attributes and len(attributes) == 1
    if check:
        result[attributes.get("Name").value] = elem.value

    return check


class ElfChnk:
    def __init__(self, d: bytes, path: Path | None = None):
        self.path = path
        self.stream = io.BytesIO(d)
        self.header = c_evtx.EVTX_CHUNK(self.stream)

        if self.header.magic != b"ElfChnk\x00":
            if self.header.magic != b"\x00\x00\x00\x00\x00\x00\x00\x00":
                log.error("%s: Bad ElfChnk magic", self.path)

            raise MalformedElfChnkException("Bad ElfChnk magic")

        self.empty = self.header.free_space_offset == 512

        self.templates = {}
        self.data_offset = 0
        self.bxml = Bxml()
        self.reader = EvtxNameReader(self.stream)

    def read(self, records: bool = True) -> Iterator[KeyValueCollection]:
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

                bxml_fh = BxmlStream(io.BytesIO(r.data), self.reader, bxml_offset=offset + 24)
                rec = next(parse_bxml(bxml_fh, self.bxml, _data_func), {})

                time = rec.get("TimeCreated_SystemTime")
                # Validate record
                if time is None or time.type == BXML_TYPE.NULL:
                    log.warning("Missing timestamp in record")
                    continue

                yield rec

        except Exception as e:
            if not self.empty:
                log.exception("Exception when processing chunk")
                raise MalformedElfChnkException from e


class Evtx:
    """Microsoft Event logs."""

    def __init__(self, fh: BinaryIO, path: Path | None = None):
        self.path = path
        self.fh = fh
        self.header = c_evtx.EVTX_HEADER(self.fh)
        self.count = 0

    def __iter__(self) -> Iterator[KeyValueCollection]:
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
