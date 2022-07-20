#!/usr/bin/env python

import sys

from datetime import datetime

from dissect.eventlog import wevtutil
from dissect.eventlog.utils import KeyValueCollection


def repr_doublequote(s):
    r = repr(s)
    if r[0] == '"':
        return r

    if r[0] != "'":
        raise Exception("Unexpected repr string")

    r = r.replace('"', '\\"')
    r = '"' + r[1:-1] + '"'
    return r


def splunkify_value(v):
    if type(v) is datetime:
        return v.isoformat() + "Z"

    return v


def splunkify(d):
    if type(d) is KeyValueCollection:
        it = d.items()
    else:
        it = d.dict().items()

    r = []
    ts = "Unknown"
    for k, v in it:
        if k == "TimeCreated_SystemTime":
            ts = splunkify_value(v)
            continue

        if type(v) is list:
            idx = 0
            for i in v:
                i = splunkify_value(i)
                r.append(f'{k}_{idx}={repr_doublequote(str(i).encode("utf-8"))}')
                idx += 1
        else:
            v = splunkify_value(v)
            r.append('{k}={repr_doublequote(str(v).encode("utf-8"))}')

    return ts + " " + " ".join(r) + "\n"


def main():
    wevt = wevtutil.WevtutilWrapper(sys.argv[1])
    for r in wevt:
        print(splunkify(r))


if __name__ == "__main__":
    main()
