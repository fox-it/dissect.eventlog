#!/usr/bin/env python
from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

from dissect.eventlog import wevtutil
from dissect.eventlog.utils import KeyValueCollection


def repr_doublequote(string: Any) -> str:
    result = repr(string)
    if result[0] == '"':
        return result

    if result[0] != "'":
        raise RuntimeError("Unexpected repr string")

    result = result.replace('"', '\\"')
    return '"' + result[1:-1] + '"'


def splunkify_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat() + "Z"

    return value


def splunkify(data: KeyValueCollection | Any) -> str:
    it = data.items() if isinstance(data, KeyValueCollection) else data.dict().items()

    result = []
    ts = "Unknown"
    for key, value in it:
        if key == "TimeCreated_SystemTime":
            ts = splunkify_value(value)
            continue

        if type(value) is list:
            for idx, elem in enumerate(value):
                elem = splunkify_value(elem)
                result.append(f"{key}_{idx}={repr_doublequote(str(elem).encode('utf-8'))}")
        else:
            value = splunkify_value(value)
            result.append(f"{key}={repr_doublequote(str(value).encode('utf-8'))}")

    return ts + " " + " ".join(result) + "\n"


def main() -> None:
    wevt = wevtutil.WevtutilWrapper(sys.argv[1])
    for r in wevt:
        print(splunkify(r))


if __name__ == "__main__":
    main()
