import os
import sys
import time
import elasticsearch.helpers
from multiprocessing import Pool
from itertools import imap

from dissect.eventlog import wevtutil

es = elasticsearch.Elasticsearch()


def log(s, *args, **kwargs):
    print(s.format(*args, **kwargs))


def iter_dir(root):
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        yield root
    else:
        for path, dirs, files in os.walk(root):
            for filename in files:
                if not (filename.lower().endswith(".evt") or filename.lower().endswith(".evtx")):
                    continue

                fullpath = os.path.join(path, filename)
                yield fullpath, os.path.relpath(fullpath, root)


class EvtxHandler:
    outdir = None

    def __init__(self, outdir):
        self.outdir = outdir

    # CPython won't pickle instance methods, therefore use a __call__
    def __call__(self, paths):
        return self.process(paths)

    def process(self, paths):
        path, relpath = paths

        error = None
        count = 0
        try:
            e = wevtutil.WevtutilWrapper(path)

            outpath = os.path.join(self.outdir, relpath + ".log")
            dirpath = os.path.dirname(outpath)

            if not os.path.exists(dirpath):
                os.makedirs(dirpath)

            outf = open(outpath, "wb")
            outf.writelines(imap(wevtutil.splunkify, e))
            outf.close()

            count = e.count
        except KeyboardInterrupt:
            raise
        except Exception as error:  # noqa
            pass

        return relpath, count, error


def main():
    start = time.time()
    log("Starting Pool")
    pool = Pool(processes=28)

    if os.path.exists(sys.argv[2]):
        raise Exception("Output directory already exists")

    handler = EvtxHandler(sys.argv[2])

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
