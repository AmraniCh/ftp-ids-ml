import pytest
from datetime import datetime
from ftp_ids.parsers.vsftpd_parser import VsftpdParser

@pytest.fixture
def parser():
    return VsftpdParser()

def test_connect_line(parser):
    line = 'Thu Jun 11 15:17:39 2026 [pid 1153056] CONNECT: Client "::ffff:203.0.113.x"'
    event = parser.parse_line(line)

    assert event is not None
    assert event["event_type"] == "CONNECT"
    assert event["src_ip"] == "203.0.113.x"
    assert event["pid"] == 1153056
    assert event["user"] is None
    assert event["timestamp"] == datetime(2026, 6, 11, 15, 17, 39)

def test_command_with_argument(parser):
    line = 'Thu Jun 11 15:17:40 2026 [pid 1153056] FTP command: Client "::ffff:203.0.113.x", "USER alice"'
    event = parser.parse_line(line)

    assert event["command"] == "USER"
    assert event["argument"] == "alice"

def test_goodbye_sets_session_end(parser):
    line = 'Thu Jun 11 15:17:51 2026 [pid 1153086] [alice] FTP response: Client "::ffff:203.0.113.x", "221 Goodbye."'
    event = parser.parse_line(line)

    assert event["response_code"] == 221
    assert event["session_end"] is True
    assert event["abrupt_end"] is False

def test_garbage_line_returns_none(parser):
    assert parser.parse_line("random garbage") is None
    assert parser.parse_line("") is None