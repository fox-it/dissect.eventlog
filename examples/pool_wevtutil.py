from __future__ import annotations

import os
import sys
import time
from multiprocessing import Pool
from pathlib import Path
from typing import TYPE_CHECKING, Any

import elasticsearch.helpers

from dissect.eventlog import wevtutil

if TYPE_CHECKING:
    from collections.abc import Iterator


es = elasticsearch.Elasticsearch()


def log(format_string: str, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> None:
    print(format_string.format(*args, **kwargs))


def iter_dir(root: str) -> Iterator[tuple[Path, Path]]:
    _root = Path(root).absolute()
    if not _root.is_dir():
        yield _root, None
    else:
        for path, _dirs, files in os.walk(_root):
            for filename in files:
                if not filename.lower().endswith((".evt", ".evtx")):
                    continue

                fullpath = Path(path) / filename
                yield fullpath, fullpath.relative_to(_root)


class EvtxHandler:
    outdir: Path

    def __init__(self, outdir: Path):
        self.outdir = outdir

    # CPython won't pickle instance methods, therefore use a __call__
    def __call__(self, paths: tuple[Path, Path]):
        return self.process(paths)

    def process(self, paths: tuple[Path, Path]) -> tuple[Path, int, Exception | None]:
        path, relpath = paths

        error = None
        count = 0
        try:
            e = wevtutil.WevtutilWrapper(path)

            outpath = self.outdir.joinpath(relpath or path.name).with_suffix(".log")
            dirpath = outpath.parent

            if not dirpath.exists():
                dirpath.mkdir(parents=True, exist_ok=True)

            with outpath.open("wb") as outf:
                outf.writelines(map(wevtutil.splunkify, e))

            count = e.count
        except KeyboardInterrupt:
            raise
        except Exception as error:  # noqa
            pass

        return relpath, count, error


def main() -> None:
    start = time.time()
    log("Starting Pool")
    pool = Pool(processes=28)

    path = Path(sys.argv[2])
    if path.exists():
        raise RuntimeError("Output directory already exists")

    handler = EvtxHandler(path)

    total = 0
    it = iter_dir(sys.argv[1])
    for path, count, error in pool.imap_unordered(handler, it):
        log("[{:10d}] {}: {}", count, path, error)
        total += count

    stop = time.time()
    log("Finished in {} sec", stop - start)
    log("Total events: {}", total)


if __name__ == "__main__":
    main()
