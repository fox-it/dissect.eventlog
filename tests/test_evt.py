import pytest

from dissect.eventlog.evt import Evt

# $rawData = [System.Text.Encoding]::Unicode.GetBytes("Test Binary Data")
# $rawData2 = [System.Text.Encoding]::Unicode.GetBytes("Test Binary Data 2")

# New-EventLog -Source TestApp -LogName TestLogX

# Write-EventLog -Source TestApp -LogName TestLogX -EntryType Information -EventId 1 -entry "Test log entry, information"  # noqa
# Write-EventLog -Source TestApp -LogName TestLogX -EntryType Error -EventId 2 -entry "Test log entry, error"
# Write-EventLog -Source TestApp -LogName TestLogX -EntryType Warning -EventId 3 -entry "Test log entry, warning"
# Write-EventLog -Source TestApp -LogName TestLogX -Category 99 -EntryType FailureAudit -EventId 65534 -entry "Test log entry, failure audit" -RawData $rawData  # noqa
# Write-EventLog -Source TestApp -LogName TestLogX -Category 1 -EntryType SuccessAudit -EventId 5 -entry "Test log entry, success audit" -RawData $rawData2  # noqa


@pytest.mark.parametrize("log_filename", ["data/TestLog.evt", "data/TestLog-dirty.evt"])
def test_evt_parsing(get_absolute_path, log_filename):

    file_path = get_absolute_path(log_filename)

    with open(file_path, "rb") as fh:
        records = list(Evt(fh))

        assert len(records) == 5

        assert {rec.Computername for rec in records} == {"POPSICKL-79ADD4"}
        assert {rec.SourceName for rec in records} == {"TestApp"}

        # https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlogentrytype?view=net-5.0
        event_types = {
            "Information": 4,
            "Error": 1,
            "Warning": 2,
            "FailureAudit": 16,
            "SuccessAudit": 8,
        }
        assert [
            # EventType, EventID, EventCategory, Message
            (event_types["Information"], 1, 1, "Test log entry, information"),
            (event_types["Error"], 2, 1, "Test log entry, error"),
            (event_types["Warning"], 3, 1, "Test log entry, warning"),
            (event_types["FailureAudit"], 65534, 99, "Test log entry, failure audit"),
            (event_types["SuccessAudit"], 5, 1, "Test log entry, success audit"),
        ] == [(rec.EventType, rec.EventID, rec.EventCategory, rec.Strings[0]) for rec in records]

        events_with_data = records[-2:]

        # other records have no Data
        assert not records[0].Data

        assert events_with_data[0].Data
        assert events_with_data[0].Data.decode("utf-16") == "Test Binary Data"

        assert events_with_data[1].Data
        assert events_with_data[1].Data.decode("utf-16") == "Test Binary Data 2"
