#!/usr/bin/env python
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from dissect.eventlog.bxml import BxmlSub
from dissect.eventlog.evtx import Evtx
from dissect.eventlog.utils import KeyValueCollection


def repr_doublequote(string: Any) -> str:
    result = repr(string)
    if result[0] == '"':
        return result

    if result[0] != "'":
        raise RuntimeError(f"Unexpected repr string: {string}")

    result = result.replace('"', '\\"')
    return '"' + result[1:-1] + '"'


def splunkify_value(v: BxmlSub | datetime | Any) -> Any:
    if isinstance(v, BxmlSub):
        v = v.get()

    if isinstance(v, datetime):
        return v.isoformat() + "Z"

    return v


def splunkify(data: KeyValueCollection | Any) -> str:
    items = data.items() if isinstance(data, KeyValueCollection) else data.dict().items()

    result = []
    ts = "Unknown"
    for key, value in items:
        if key == "TimeCreated_SystemTime":
            ts = splunkify_value(value)
            continue

        if isinstance(value, list):
            for idx, elem in enumerate(value):
                elem = splunkify_value(elem)
                result.append(f"{key}_{idx}={repr_doublequote(str(elem))}")
        else:
            value = splunkify_value(value)
            result.append(f"{key}={repr_doublequote(str(value))}")

    return f"{ts} {' '.join(result)}\n"


def main() -> None:
    for file in sys.argv[1:]:
        with Path(file).open("rb") as fp:
            evtx = Evtx(fp)
            for record in evtx:
                print(splunkify(record))


if __name__ == "__main__":
    main()
