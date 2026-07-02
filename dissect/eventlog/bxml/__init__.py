from __future__ import annotations

from dissect.eventlog.bxml.bxml import (
    Bxml,
    BxmlStream,
    Descriptor,
    Element,
    EvtxNameReader,
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
    "BxmlStream",
    "Descriptor",
    "Element",
    "EvtxNameReader",
    "Template",
    "WevtNameReader",
    "parse_bxml",
    "resolve_substitution",
)
