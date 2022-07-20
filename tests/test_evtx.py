from dissect.eventlog.evtx import Evtx


# $rawData = [System.Text.Encoding]::Unicode.GetBytes("Test Binary Data")

# New-EventLog -Source TestAppX -LogName TestLogX

# Write-EventLog -Source TestAppX -LogName TestLogX -EntryType Information -EventId 1 -Message "Test log message, information"  # noqa
# Write-EventLog -Source TestAppX -LogName TestLogX -EntryType Error -EventId 2 -Message "Test log message, error"
# Write-EventLog -Source TestAppX -LogName TestLogX -EntryType Warning -EventId 3 -Message "Test log message, warning"
# Write-EventLog -Source TestAppX -LogName TestLogX -Category 99 -EntryType FailureAudit -EventId 65534 -Message "Test log message, failure audit" -RawData $rawData  # noqa
# Write-EventLog -Source TestAppX -LogName TestLogX -Category 1 -EntryType SuccessAudit -EventId 5 -Message "Test log message, success audit" -RawData $rawData  # noqa


def test_evtx_parsing(get_absolute_path):

    log_file_path = get_absolute_path("data/TestLogX.evtx")

    with open(log_file_path, "rb") as f:
        records = list(Evtx(f))

        assert len(records) == 5

        assert {r["Computer"] for r in records} == {"DESKTOP-PJOQLJS"}
        assert {r["Provider_Name"] for r in records} == {"TestAppX"}
        assert {r["Channel"] for r in records} == {"TestLogX"}

        # https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc#52-level
        event_levels = {
            "Information": 4,
            "Error": 2,
            "Warning": 3,
            "FailureAudit": 0,
            "SuccessAudit": 0,
        }
        assert [
            # EventType, EventID, EventCategory, Message
            (event_levels["Information"], 1, 1, "Test log message, information"),
            (event_levels["Error"], 2, 1, "Test log message, error"),
            (event_levels["Warning"], 3, 1, "Test log message, warning"),
            (event_levels["FailureAudit"], 65534, 99, "Test log message, failure audit"),
            (event_levels["SuccessAudit"], 5, 1, "Test log message, success audit"),
        ] == [(r["Level"], r["EventID"], r["Task"], r["Data"][0]) for r in records]

        events_with_data = records[-2:]

        # other records have no Data
        assert not records[0]["Binary"]

        assert events_with_data[0]["Binary"]
        data1 = events_with_data[0]["Binary"]
        assert bytearray.fromhex(data1.decode()).decode("utf-16") == "Test Binary Data"

        assert events_with_data[1]["Binary"]
        data2 = events_with_data[1]["Binary"]
        assert bytearray.fromhex(data2.decode()).decode("utf-16") == "Test Binary Data"
