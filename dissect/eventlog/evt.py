# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-eventlogrecord
# https://github.com/libyal/libevt/blob/main/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc
import io
import struct
from collections import namedtuple
from datetime import datetime, timezone

from dissect import cstruct

from dissect.eventlog.exceptions import Error

c_evt = cstruct.cstruct()
c_evt.load(
    """
#define ELF_LOGFILE_HEADER_DIRTY    0x0001
#define ELF_LOGFILE_HEADER_WRAP     0x0002
#define ELF_LOGFILE_LOGFULL_WRITTEN 0x0004
#define ELF_LOGFILE_ARCHIVE_SET     0x0008

typedef struct _EVENTLOGHEADER {
    ULONG   HeaderSize;
    char    Signature[4];
    ULONG   MajorVersion;
    ULONG   MinorVersion;
    ULONG   StartOffset;
    ULONG   EndOffset;
    ULONG   CurrentRecordNumber;
    ULONG   OldestRecordNumber;
    ULONG   MaxSize;
    ULONG   Flags;
    ULONG   Retention;
    ULONG   EndHeaderSize;
} EVENTLOGHEADER;

typedef struct _EVENTLOGRECORD {
    DWORD   Length;
    DWORD   Reserved;
    DWORD   RecordNumber;
    DWORD   TimeGenerated;
    DWORD   TimeWritten;
    DWORD   EventID;
    WORD    EventType;
    WORD    NumStrings;
    WORD    EventCategory;
    WORD    ReservedFlags;
    DWORD   ClosingRecordNumber;
    DWORD   StringOffset;
    DWORD   UserSidLength;
    DWORD   UserSidOffset;
    DWORD   DataLength;
    DWORD   DataOffset;
} EVENTLOGRECORD;

typedef struct _EVENTLOGEOF {
    ULONG   RecordSizeBeginning;
    ULONG   One;
    ULONG   Two;
    ULONG   Three;
    ULONG   Four;
    ULONG   BeginRecord;
    ULONG   EndRecord;
    ULONG   CurrentRecordNumber;
    ULONG   OldestRecordNumber;
    ULONG   RecordSizeEnd;
} EVENTLOGEOF;
"""
)

EVENTLOGRECORD_SIZE = len(c_evt.EVENTLOGRECORD)

Record = namedtuple(
    "Record",
    [
        "RecordNumber",
        "TimeGenerated",
        "TimeWritten",
        "EventID",
        "EventCode",
        "EventFacility",
        "EventCustomerFlag",
        "EventSeverity",
        "EventType",
        "EventCategory",
        "SourceName",
        "Computername",
        "UserSid",
        "Strings",
        "Data",
        "record",
    ],
)

BLOCK_SIZE = 4096
DIRTY_NEEDLE = b"\x28\x00\x00\x00" + (b"\x11" * 4) + (b"\x22" * 4) + (b"\x33" * 4) + (b"\x44" * 4)


class Evt:
    """Windows Event files for WinOS up until Windows XP"""

    def __init__(self, fh):
        self.fh = fh

        if not hasattr(fh, "size"):
            pos = fh.tell()
            fh.seek(0, io.SEEK_END)
            self.size = fh.tell()
            fh.seek(pos)
        else:
            self.size = fh.size

        self.header = c_evt.EVENTLOGHEADER(fh)

        if self.header.Signature != b"LfLe":
            raise Error("Invalid signature")

        self._post_header_offset = fh.tell()

        self.start_offset = self.header.StartOffset
        self.end_offset = self.header.EndOffset
        self.current_record_number = self.header.CurrentRecordNumber
        self.oldest_record_number = self.header.OldestRecordNumber
        self.flags = self.header.Flags

        # In the case of a "dirty" not-finalised file, the header might be outdated.
        # We can't trust header.StartOffset and header.EndOffset values, so we
        # need to look for end-of-file record
        if self._is_dirty():
            for offset in find_needle(fh, DIRTY_NEEDLE):
                fh.seek(offset)
                eof_record = c_evt.EVENTLOGEOF(fh)
                self._update_meta_from_eof_record(eof_record)
                break
            else:
                raise ValueError("Dirty evt file with no floating EOF record")

    def _is_dirty(self):
        return self.header.Flags & c_evt.ELF_LOGFILE_HEADER_DIRTY == c_evt.ELF_LOGFILE_HEADER_DIRTY

    def _update_meta_from_eof_record(self, eof_record):
        self.start_offset = eof_record.BeginRecord
        self.end_offset = eof_record.EndRecord
        self.current_record_number = eof_record.CurrentRecordNumber
        self.oldest_record_number = eof_record.OldestRecordNumber

    def __iter__(self):
        fh = self.fh
        fh.seek(self.start_offset)

        # allow only 2 reads from start_offset: initial and
        # another one in the case of metadata update
        read_from_start_limit = 2

        next_pos = 0
        last_pos = -1

        while True:

            pos = fh.tell()

            if pos == last_pos:
                # break the loop if position is the same
                # in 2 consecutive cycles
                break

            if pos == self.start_offset:
                read_from_start_limit -= 1

            if read_from_start_limit <= 0:
                break

            if (self.size - pos) < EVENTLOGRECORD_SIZE:
                # if data available is less than Record header,
                # jump back to after the header immediately

                if self._post_header_offset == self.start_offset:
                    # no need to jump to post-header offset, since
                    # that's where we started
                    break

                fh.seek(self._post_header_offset)
                pos = fh.tell()

            record = c_evt.EVENTLOGRECORD(fh)

            if is_eof_record(record):
                # back up and re-read record as EOF record
                fh.seek(pos)
                eof_record = c_evt.EVENTLOGEOF(fh)

                if eof_record.BeginRecord == self.start_offset and eof_record.EndRecord == self.end_offset:
                    # EOF record metadata matches the file header
                    # or EOF record found initially, nothing more to do
                    break
                else:
                    # This EOF record does not match the known metadata
                    # Update the metadata and start re-reading records start_offset
                    self._update_meta_from_eof_record(eof_record)
                    fh.seek(self.start_offset)
                    continue

            next_pos = pos + record.Length

            buffer = fh
            if next_pos > self.size:
                # if record is truncated (record length is below the file size),
                # the log file might've been rotated. It means missing record data
                # will start from the beginning of the file.
                #
                # Read first part of the record, jump back to the header
                # and read the second part of the record.

                part1_size = self.size - pos
                part2_size = record.Length - part1_size

                data_part1 = fh.read(part1_size)

                fh.seek(self._post_header_offset)
                data_part2 = fh.read(part2_size)

                buffer = io.BytesIO(data_part1 + data_part2)
                next_pos = self._post_header_offset + part2_size

            elif next_pos == self.size:
                # jump back to after the header for the next record
                next_pos = self._post_header_offset

            if record.UserSidOffset > self.header.MaxSize:
                # UserSidOffset is the first offset after the record header,
                # so if it is incorrect, skip the record
                fh.seek(pos + record.Length)
                continue

            yield parse_record(record, buffer)

            last_pos = pos
            fh.seek(next_pos)


def find_needle(fh, needle):
    needle_len = len(needle)
    overlap_len = needle_len - 1

    while True:
        offset = fh.tell()
        buf = fh.read(BLOCK_SIZE)
        if not buf:
            break

        p = buf.find(needle)
        if p != -1:
            yield offset + p

        fh.seek(offset + BLOCK_SIZE - overlap_len)


def parse_record(record, buf):
    pos = buf.tell()

    source = c_evt.wchar[None](buf)
    computer = c_evt.wchar[None](buf)

    # pos value is a position after a record header has been read
    # but UserSidOffset, StringOffset and DataOffset are all relative
    # to the start of the record
    record_start = pos - EVENTLOGRECORD_SIZE

    sid = b""
    if record.UserSidLength > 0:
        buf.seek(record_start + record.UserSidOffset)
        sid = buf.read(record.UserSidLength)

    fields = []
    if record.StringOffset > 0:
        buf.seek(record_start + record.StringOffset)
        for _ in range(record.NumStrings):
            fields.append(c_evt.wchar[None](buf))

    data = b""
    if record.DataLength > 0:
        buf.seek(record_start + record.DataOffset)
        data = buf.read(record.DataLength)

    return Record(
        record.RecordNumber,
        datetime.fromtimestamp(record.TimeGenerated, tz=timezone.utc),
        datetime.fromtimestamp(record.TimeWritten, tz=timezone.utc),
        record.EventID,
        record.EventID & 0x0000FFFF,
        record.EventID & 0x0FFF0000,
        record.EventID & 0x20000000,
        record.EventID & 0xC0000000,
        record.EventType,
        record.EventCategory,
        source,
        computer,
        reprsid(sid),
        fields,
        data,
        record,
    )


def reprsid(s):
    if not s:
        return None

    try:
        r = "S-" + str(ord(s[0])) + "-" + str(ord(s[1])) + "-" + str(c_evt.uint48(s[2:8]))
        for i in range(8, len(s), 4):
            r += "-" + str(struct.unpack(">I", s[i : i + 4])[0])
        return r
    except Exception:
        return "S-?"


def is_eof_record(record):
    return (
        record.Length == len(c_evt.EVENTLOGEOF)
        and record.Reserved == 0x11111111  # _EVENTLOGEOF.One
        and record.TimeWritten == 0x44444444  # _EVENTLOGEOF.Four
    )


def is_header_record(record):
    # https://forensicswiki.xyz/page/Windows_Event_Log_(EVT)
    return record.Length == len(c_evt.EVENTLOGHEADER) == 0x30


def parse_chunk(chunk):
    """
    Requires a chunk that starts with EVENTLOGRECORD header
    """
    buffer = io.BytesIO(chunk)
    record = c_evt.EVENTLOGRECORD(buffer)
    if is_eof_record(record) or is_header_record(record):
        return
    yield parse_record(record, buffer)
