from __future__ import print_function
import io
import sys

from dissect.target import container
from dissect.eventlog.evtx import ElfChnk


BLOCK_SIZE = io.DEFAULT_BUFFER_SIZE


def open_image(path):
    return container.open(path)


def scrape_pos(fp, needle, block_size=BLOCK_SIZE):
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


def scrape(fp, needle, size, block_size=BLOCK_SIZE):
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


def main():
    fp = open_image(sys.argv[1])

    for offset, chunk in scrape(fp, b"ElfChnk\x00", 0x10000):
        print("ElfChnk @ 0x{:x}".format(offset), file=sys.stderr)
        e = ElfChnk(chunk)
        count = 0
        for r in e.read(False):
            print(r)
            count += 1

        print(f"ElfChnk @ 0x{offset:x}: {count} records", file=sys.stderr)


if __name__ == "__main__":
    main()
