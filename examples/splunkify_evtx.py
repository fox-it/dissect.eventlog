#!/usr/bin/env python

import sys

from datetime import datetime

from dissect.eventlog.bxml import BxmlSub
from dissect.eventlog.utils import KeyValueCollection
from dissect.eventlog import evtx


def repr_doublequote(s):
    r = repr(s)
    if r[0] == '"':
        return r

    if r[0] != "'":
        raise Exception(f"Unexpected repr string: {s}")

    r = r.replace('"', '\\"')
    r = '"' + r[1:-1] + '"'
    return r


def splunkify_value(v):
    if isinstance(v, BxmlSub):
        v = v.get()

    if isinstance(v, datetime):
        return v.isoformat() + "Z"

    return v


def splunkify(d):
    if isinstance(d, KeyValueCollection):
        items = d.items()
    else:
        items = d.dict().items()

    r = []
    ts = "Unknown"
    for k, v in items:
        if k == "TimeCreated_SystemTime":
            ts = splunkify_value(v)
            continue

        if isinstance(v, list):
            idx = 0
            for i in v:
                i = splunkify_value(i)
                r.append(f"{k}_{idx}={repr_doublequote(str(i))}")
                idx += 1
        else:
            v = splunkify_value(v)
            r.append(f"{k}={repr_doublequote(str(v))}")

    return f"{ts} {' '.join(r)}\n"


def main():
    for i in sys.argv[1:]:
        e = evtx.Evtx(open(i, "rb"))
        for r in e:
            print(splunkify(r))


if __name__ == "__main__":
    main()
