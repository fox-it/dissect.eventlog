from __future__ import annotations

import itertools
import string
import subprocess
from typing import TYPE_CHECKING

from defusedxml import ElementTree as ET

from dissect.eventlog.utils import KeyValueCollection

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from xml.etree.ElementTree import Element


CHAR_TRANSLATION = string.maketrans("".join(map(chr, range(10))), "".join(map(str, range(10))))


class WevtutilWrapper:
    path = None
    count = 0

    def __init__(self, path: str | Path):
        self.path = path

    def __iter__(self) -> Iterator[KeyValueCollection]:
        p = subprocess.Popen(
            ["wevtutil", "qe", "/lf:true", self.path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        p.stdin.close()

        buffer = ""

        for line in p.stdout:
            buffer += line

            if "</Event>" not in buffer:
                continue

            buffer = buffer.replace(" xmlns='http://schemas.microsoft.com/win/2004/08/events/event'", "")
            buffer = buffer.translate(CHAR_TRANSLATION)
            for character in [0xB, 0xC, 0xE, 0xF]:
                buffer = buffer.replace(chr(character), str(character))

            buffer = buffer.decode("windows-1252").encode("utf-8")

            try:
                element: Element = ET.fromstring(buffer)
            except ET.ParseError:
                buffer = ""
                continue

            result = KeyValueCollection()
            self.fullmap(element, [], result)

            yield result
            self.count += 1

            buffer = ""

    def fullmap(
        self, element: Element, path: list[Element], value_collection: KeyValueCollection
    ) -> KeyValueCollection:
        for e in element.iter():
            self.fullmap(e, [*path, element], value_collection)

        if element.text:
            if element.tag == "Data" and "Name" in element.attrib:
                value_collection[element.attrib["Name"]] = element.text
            else:
                pathstr = "_".join(itertools.chain((elem.tag for elem in path[2:]), [element.tag]))

                value_collection[pathstr] = element.text

        for key, value in element.attrib.items():
            if element.tag == "Data" and key == "Name":
                continue

            pathstr = "_".join(itertools.chain((elem.tag for elem in path[2:]), [element.tag, key]))
            value_collection[pathstr] = value

        return value_collection
