from __future__ import annotations

import gzip
import os
import time
from multiprocessing import Pool
from pathlib import Path
from typing import TYPE_CHECKING

from fileprocessing import DirectoryWalker

from dissect.eventlog import evtx

if TYPE_CHECKING:
    from collections.abc import Iterator


def log(s: str, *args, **kwargs) -> None:
    print(s.format(*args, **kwargs))


def iter_dir(root: str) -> Iterator[Path]:
    _root = Path(root).absolute()
    if not _root.is_dir():
        yield _root
    else:
        for path, _dirs, files in os.walk(root):
            for filename in files:
                if not filename.lower().endswith(".evtx"):
                    continue

                fullpath = Path(path).joinpath(filename)
                yield fullpath.relative_to(root)


class EvtxHandler:
    srcbase: Path
    dstbase: Path

    def __init__(self, srcbase: Path, dstbase: Path):
        self.srcbase = srcbase
        self.dstbase = dstbase

    def process(self, path: str) -> tuple[str, int, Exception | None]:
        error = None
        count = 0
        try:
            dstpath = Path(self.dstbase) / (path + ".log.gz")
            dstdir = dstpath.parent

            if dstpath.exists():
                return path, -1, None

            if not dstdir.exists():
                dstdir.mkdir(parents=True, exist_ok=True)

            with (
                self.srcbase.joinpath(path).open("rb") as input_file,
                gzip.open(dstpath, "wb") as output_file,
            ):
                e = evtx.Evtx(input_file)
                output_file.writelines(map(evtx.splunkify, e))
                count = e.count
        except KeyboardInterrupt:
            raise
        except Exception as error:  # noqa
            pass

        return path, count, error


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("directory", metavar="DIRECTORY", type=Path)
    parser.add_argument("-p", dest="pattern")
    parser.add_argument("-o", dest="outputdir", type=Path, required=True)
    args = parser.parse_args()

    start = time.time()
    log("Starting Pool")
    pool = Pool(processes=28)

    handler = EvtxHandler(args.directory, args.outputdir)

    total = 0

    it = DirectoryWalker(args.directory, args.pattern)

    for path, count, error in pool.imap_unordered(handler.process, it, 1):
        if not path:
            continue

        log("[{:10d}] {}: {}", count, path, error)
        total += count

    stop = time.time()
    log("Finished in {} sec", stop - start)
    log("Total events: {}", total)

    pool.close()


if __name__ == "__main__":
    main()
