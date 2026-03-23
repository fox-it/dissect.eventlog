from __future__ import annotations


class Error(Exception):
    pass


class MalformedElfChnkException(Error):
    pass


class BxmlException(Error):
    pass


class UnknownSignatureException(Error):
    pass
