import os
import time
import gzip
from itertools import imap
from multiprocessing import Pool

from fileprocessing import DirectoryWalker

from dissect.eventlog import evtx


def log(s, *args, **kwargs):
    print(s.format(*args, **kwargs))


def iter_dir(root):
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        yield root
    else:
        for path, dirs, files in os.walk(root):
            for filename in files:
                if not filename.lower().endswith(".evtx"):
                    continue

                fullpath = os.path.join(path, filename)
                yield os.path.relpath(fullpath, root)


class EvtxHandler:
    srcdir = None
    dstdir = None

    def __init__(self, srcbase, dstbase):
        self.srcbase = srcbase
        self.dstbase = dstbase

    def process(self, path):
        error = None
        count = 0
        try:
            dstpath = os.path.join(self.dstbase, path + ".log.gz")
            dstdir = os.path.dirname(dstpath)

            f = open(os.path.join(self.srcbase, path), "rb")
            e = evtx.Evtx(f)

            if os.path.exists(dstpath):
                return path, -1, None

            if not os.path.exists(dstdir):
                os.makedirs(dstdir)

            outf = gzip.open(dstpath, "wb")
            outf.writelines(imap(evtx.splunkify, e))
            outf.close()

            f.close()

            count = e.count
        except KeyboardInterrupt:
            raise
        except Exception as error:  # noqa
            pass

        return path, count, error


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("directory", metavar="DIRECTORY")
    parser.add_argument("-p", dest="pattern")
    parser.add_argument("-o", dest="outputdir", required=True)
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
