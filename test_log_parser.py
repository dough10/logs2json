import pytest
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from main import (
  parse_log_line,
  is_lan,
  is_old_log,
  parse_log_file,
  LogEntry
)

SAMPLE_LINE = (
  '8.8.8.8 - - [09/May/2025:14:00:00 +0000] "GET /test HTTP/1.1" 200 1024 '
  '"-" "TestAgent/1.0" "-" "example.com" sn="web1" rt=0.100 '
  'ua="127.0.0.1:80" us="200" ut="0.100" ul="512" cs="HIT"'
)

LAN_LINE = SAMPLE_LINE.replace('8.8.8.8', '192.168.86.42')

OLD_LINE = SAMPLE_LINE.replace('09/May/2025:14:00:00', '01/May/2025:14:00:00')

MALFORMED_LINE = 'This is not a log line at all'

@pytest.fixture
def sample_file(tmp_path):
  path = tmp_path / "test.log"
  path.write_text('\n'.join([SAMPLE_LINE, LAN_LINE, OLD_LINE, MALFORMED_LINE]))
  return str(path)

def test_parse_valid_log_line():
  entry = parse_log_line(SAMPLE_LINE)
  assert isinstance(entry, LogEntry)
  assert entry.ip == '8.8.8.8'
  assert entry.method == 'GET'
  assert entry.status_code == 200
  assert entry.bytes_sent == 1024
  assert entry.user_agent == 'TestAgent/1.0'

def test_parse_invalid_log_line():
  assert parse_log_line(MALFORMED_LINE) is None

def test_is_lan_true():
  assert is_lan('192.168.86.55')

def test_is_lan_false():
  assert not is_lan('8.8.8.8')

def test_is_old_log_true():
  past = datetime.now(timezone.utc) - timedelta(days=2)
  assert is_old_log(past)

def test_is_old_log_false():
  recent = datetime.now(timezone.utc) - timedelta(hours=2)
  assert not is_old_log(recent)

def test_parse_log_file_filters(sample_file):
  data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
  parse_log_file(data, sample_file)

  # Only 1 line should be included: SAMPLE_LINE
  log_entries = list(data[sample_file].values())[0]
  assert len(log_entries) == 1
  ip_entries = list(log_entries.values())[0]
  assert len(ip_entries) == 1
  assert ip_entries[0]['ip'] == '8.8.8.8'
