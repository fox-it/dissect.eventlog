from __future__ import print_function
import io
import sys

from dissect.eventlog import evt
from dissect.target import container


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

    for offset, chunk in scrape(fp, b"LfLe\x00", 0x10000):
        print(f"LfLe @ 0x{offset:x}", file=sys.stderr)
        p = 0
        try:
            p = fp.tell()
            fp.seek(offset - 4)
            r = evt.c_evt.EVENTLOGRECORD(fp)
            if r.Length == 0x28 and r.Reserved == 0x11111111 and r.TimeWritten == 0x44444444:
                continue

            print(evt.parse_record(r, io.BytesIO(fp.read(0x10000))))
        except Exception:
            pass
        finally:
            fp.seek(p)


if __name__ == "__main__":
    main()
