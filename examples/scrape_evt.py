from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING, BinaryIO

from dissect.target import container

from dissect.eventlog import evt

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

BLOCK_SIZE = io.DEFAULT_BUFFER_SIZE


def open_image(path: str | Path) -> container.Container:
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
        data = saved + block
        pos = -1
        while True:
            pos = data.find(needle, pos + 1)
            if pos == -1:
                break

            offset = pos + pos - overlap_len
            yield offset

        saved = data[-overlap_len:]


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
        _pos = -1
        while True:
            _pos = d.find(needle, _pos + 1)
            if _pos == -1:
                break

            offset = pos + _pos - overlap_len

            data = d[_pos : _pos + size]
            if len(data) != size:
                next_block = fp.read(block_size)
                if not next_block:
                    break
                data += next_block[: size - len(data)]
                yield offset, data

            saved = d[-overlap_len:]


def main() -> None:
    fp = open_image(sys.argv[1])

    for offset, _chunk in scrape(fp, b"LfLe\x00", 0x10000):
        print(f"LfLe @ 0x{offset:x}", file=sys.stderr)
        pos = 0
        try:
            pos = fp.tell()
            fp.seek(offset - 4)
            record = evt.c_evt.EVENTLOGRECORD(fp)
            if record.Length == 0x28 and record.Reserved == 0x11111111 and record.TimeWritten == 0x44444444:
                continue

            print(evt.parse_record(record, io.BytesIO(fp.read(0x10000))))
        except Exception:
            pass
        finally:
            fp.seek(pos)


if __name__ == "__main__":
    main()
