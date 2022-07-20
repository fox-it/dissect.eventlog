import string
import subprocess
import xml.etree.ElementTree as ET

from dissect.eventlog.utils import KeyValueCollection

CHAR_TRANSLATION = string.maketrans("".join(map(chr, range(0, 10))), "".join(map(str, range(0, 10))))


class WevtutilWrapper:
    path = None
    count = 0

    def __init__(self, path):
        self.path = path

    def __iter__(self):
        p = subprocess.Popen(
            ["wevtutil", "qe", "/lf:true", self.path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        p.stdin.close()

        d = ""

        for line in p.stdout:
            d += line

            if "</Event>" not in d:
                continue

            d = d.replace(" xmlns='http://schemas.microsoft.com/win/2004/08/events/event'", "")
            d = d.translate(CHAR_TRANSLATION)
            for i in [0xB, 0xC, 0xE, 0xF]:
                d = d.replace(chr(i), str(i))

            d = d.decode("windows-1252").encode("utf-8")

            try:
                e = ET.fromstring(d)
            except ET.ParseError:
                d = ""
                continue

            r = KeyValueCollection()
            self.fullmap(e, [], r)

            yield r
            self.count += 1

            d = ""

    def fullmap(self, t, path, d):
        for e in t.getchildren():
            if type(e) is ET.Element:
                self.fullmap(e, path + [t], d)

        if t.text:
            if t.tag == "Data" and "Name" in t.attrib:
                d[t.attrib["Name"]] = t.text
            else:
                pathstr = "_".join(map(lambda i: i.tag, path[2:]) + [t.tag])
                d[pathstr] = t.text

        for k, v in t.attrib.items():
            if t.tag == "Data" and k == "Name":
                continue

            pathstr = "_".join(map(lambda i: i.tag, path[2:]) + [t.tag, k])
            d[pathstr] = v

        return d
