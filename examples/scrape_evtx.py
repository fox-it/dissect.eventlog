from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING, BinaryIO

from dissect.target import container

from dissect.eventlog.evtx import ElfChnk

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

BLOCK_SIZE = io.DEFAULT_BUFFER_SIZE


def open_image(path: Path | str) -> container.Container:
    return container.open(path)


def scrape_pos(fp: BinaryIO, needle: bytes, block_size: int = BLOCK_SIZE) -> Iterator[int]:
    needle_len = len(needle)
    overlap_len = needle_len - 1

    saved = b"\x00" * overlap_len
    while True:
        pos = fp.tell()
        block = fp.read(block_size)
        if not block:
            break
        d = saved + block
        p = -1
        while True:
            p = d.find(needle, p + 1)
            if p == -1:
                break

            offset = pos + p - overlap_len
            yield offset

        saved = d[-overlap_len:]


def scrape(fp: BinaryIO, needle: bytes, size: int, block_size: int = BLOCK_SIZE) -> Iterator[tuple[int, bytes]]:
    needle_len = len(needle)
    overlap_len = needle_len - 1

    saved = b"\x00" * overlap_len
    next_block = None
    while True:
        pos = fp.tell()
        if not next_block:
            block = fp.read(block_size)
            if not block:
                break
            d = saved + block
        else:
            d = next_block
            next_block = None
        p = -1
        while True:
            p = d.find(needle, p + 1)
            if p == -1:
                break

            offset = pos + p - overlap_len

            data = d[p : p + size]
            if len(data) != size:
                next_block = fp.read(block_size)
                if not next_block:
                    break
                data += next_block[: size - len(data)]
                yield offset, data

            saved = d[-overlap_len:]


def main() -> None:
    fp = open_image(sys.argv[1])

    for offset, chunk in scrape(fp, b"ElfChnk\x00", 0x10000):
        print(f"ElfChnk @ 0x{offset:x}", file=sys.stderr)
        e = ElfChnk(chunk)
        count = 0
        for r in e.read(False):
            print(r)
            count += 1

        print(f"ElfChnk @ 0x{offset:x}: {count} records", file=sys.stderr)


if __name__ == "__main__":
    main()
