from __future__ import annotations

from dissect.eventlog.bxml.bxml import (
    Bxml,
    BxmlNameReader,
    BxmlStream,
    Descriptor,
    Element,
    Template,
    WevtNameReader,
    parse_bxml,
    resolve_substitution,
)
from dissect.eventlog.bxml.c_bxml import BXML_TOKEN, BXML_TYPE

__all__ = (
    "BXML_TOKEN",
    "BXML_TYPE",
    "Bxml",
    "BxmlNameReader",
    "BxmlStream",
    "Descriptor",
    "Element",
    "Template",
    "WevtNameReader",
    "parse_bxml",
    "resolve_substitution",
)
