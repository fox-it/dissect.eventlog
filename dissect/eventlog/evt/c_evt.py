from __future__ import annotations

from dissect.cstruct import cstruct

evt_def = """
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

c_evt = cstruct().load(evt_def)
