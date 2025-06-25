import re
from os import path
from glob import glob
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from json import dumps as stringify
from collections import defaultdict
import logging
import logging.config
from logging.handlers import RotatingFileHandler
from typing import Optional

class Log:
  def __init__(self, max_bytes: int = 5_000_000, backup_count: int = 5) -> None:
    self.__logger = logging.getLogger('logs2json')
    self.__logger.setLevel(logging.DEBUG)

    if not self.__logger.hasHandlers():
      file_handler = RotatingFileHandler('logs2json.log', maxBytes=max_bytes, backupCount=backup_count)
      formatter = logging.Formatter('%(asctime)s %(filename)s:%(levelname)s - %(message)s')
      file_handler.setFormatter(formatter)
      self.__logger.addHandler(file_handler)

      stream_handler = logging.StreamHandler()
      stream_handler.setFormatter(formatter)
      self.__logger.addHandler(stream_handler)

  def get_logger(self) -> logging:
    return self.__logger

@dataclass
class LogEntry:
  ip: str
  user: str
  timestamp: datetime
  method: str
  resource: str
  status_code: int
  bytes_sent: int
  referer: str
  user_agent: str
  forwarded_address: str
  host: str
  server_name: str
  request_time: float
  upstream_addr: str
  upstream_status: int
  upstream_response_time: float
  upstream_response_length: int
  upstream_cache_status: str
  x_forwarded_for: str 

  def to_dict(self) -> dict:
    return {
      'ip': self.ip,
      'user': self.user,
      'timestamp': self.timestamp.isoformat(),
      'method': self.method,
      'resource': self.resource,
      'status_code': self.status_code,
      'bytes_sent': self.bytes_sent,
      'referer': self.referer,
      'user_agent': self.user_agent,
      'forwarded_address': self.forwarded_address,
      'host': self.host,
      'server_name': self.server_name,
      'request_time': self.request_time,
      'upstream_addr': self.upstream_addr,
      'upstream_status': self.upstream_status,
      'upstream_response_time': self.upstream_response_time,
      'upstream_response_length': self.upstream_response_length,
      'upstream_cache_status': self.upstream_cache_status,
      'x_forwarded_for': self.x_forwarded_for
    }

logs = Log()
logger = logs.get_logger()

def get_logs() -> list[str]:
  try:
    return [log for log in glob(path.join('/mnt/logs', '*dough10.me.log'))]
  except Exception as e:
    logger.error(f'Error while retrieving log files: {e}')
    return []

def read_log(log:str) -> str:
  try:
    with open(log, 'r') as file_data:
      return file_data.read()
  except FileNotFoundError:
    logger.error(f"Error: The file '{log}' was not found.")
  except PermissionError:
    logger.error(f"Error: Permission denied to read the file '{log}'.")
  except Exception as e:
    logger.error(f"Error while reading the file '{log}': {e}")
  return None

LOG_PATTERN = re.compile(
  r'(?P<ip>[\d\.]+) - (?P<user>[^ ]*) '
  r'\[(?P<timestamp>[^\]]+)\] '
  r'"(?P<method>[A-Z]+)? (?P<resource>[^ ]*) HTTP/[^"]*" '
  r'(?P<status_code>\d+) (?P<bytes_sent>\d+) '
  r'"(?P<referer>[^"]*)" '
  r'"(?P<user_agent>[^"]*)" '
  r'"(?P<x_forwarded_for>[^"]*)" '
  r'"(?P<host>[^"]*)" '
  r'sn="(?P<server_name>[^"]*)" '
  r'rt=(?P<request_time>[\d\.]+) '
  r'ua="(?P<upstream_addr>[^"]*)" '
  r'us="(?P<upstream_status>[^"]*)" '
  r'ut="(?P<upstream_response_time>[^"]*)" '
  r'ul="(?P<upstream_response_length>[^"]*)" '
  r'cs="?(?P<upstream_cache_status>[^"]*|-)"?$'
)

def parse_log_line(log_line: str) -> Optional['LogEntry']:
  match = LOG_PATTERN.fullmatch(log_line.strip())
  if not match:
    if log_line:
      logger.warning(f'Failed matching to regex: {log_line}')
    return None

  log_data = match.groupdict()

  try:
    log_data['status_code'] = int(log_data['status_code'])
    log_data['bytes_sent'] = int(log_data['bytes_sent'])
    log_data['request_time'] = float(log_data['request_time'])

    # Handle multiple upstream statuses (e.g., '502, 502, 502')
    upstream_status_raw = log_data['upstream_status'].split(':')[0].strip()
    upstream_status_first = upstream_status_raw.split(',')[0].strip()
    log_data['upstream_status'] = int(upstream_status_first) if upstream_status_first != '-' else None

    upstream_time_raw = log_data['upstream_response_time'].split(':')[0].strip()
    upstream_time_first = upstream_time_raw.split(',')[0].strip()
    log_data['upstream_response_time'] = float(upstream_time_first) if upstream_time_first != '-' else None

    upstream_len_raw = log_data['upstream_response_length'].split(':')[0].strip()
    upstream_len_first = upstream_len_raw.split(',')[0].strip()
    log_data['upstream_response_length'] = int(upstream_len_first) if upstream_len_first != '-' else 0

    cache_status = log_data.get('upstream_cache_status')
    if cache_status is not None:
      cache_status = cache_status.strip().strip('"')
    log_data['upstream_cache_status'] = cache_status if cache_status and cache_status != '-' else None

    log_data['forwarded_address'] = log_data.get('x_forwarded_for', None)

    log_data['timestamp'] = datetime.strptime(
      log_data['timestamp'], "%d/%b/%Y:%H:%M:%S %z"
    )

    return LogEntry(**log_data)

  except Exception as e:
    logger.exception(f"Failed to parse values from matched log line: {e}")
    return None

def is_lan(ip:str) -> bool:
  ip_regex = re.compile(r'^192\.168\.86\.\d{1,3}$')
  return ip_regex.match(ip)

def is_old_log(timestamp:datetime) -> bool:
  time_24_hours_ago = datetime.now(timezone.utc) - timedelta(days=1)
  return timestamp < time_24_hours_ago

def parse_log_file(data: dict[dict[dict[list]]], log: str) -> None:
  try:
    with open(log, 'r') as file:
      for line in file:
        try:
          log_entry = parse_log_line(line)
          if not log_entry:
            continue

          if is_lan(log_entry.ip):
            continue

          if is_old_log(log_entry.timestamp):
            continue

          log_date_str = log_entry.timestamp.date().isoformat()
          data[log][log_date_str][log_entry.ip].append(log_entry.to_dict())
        except IndexError as error:
          logger.error(f'Indexerror: {str(error)}')

  except FileNotFoundError:
    logger.error(f"Error: The file '{log}' was not found.")
  except PermissionError:
    logger.error(f"Error: Permission denied to read the file '{log}'.")
  except Exception as e:
    logger.error(f"Error while reading the file '{log}': {e}")

def main() -> None:
  data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

  for log in get_logs():
    parse_log_file(data, log)

  today = datetime.today().strftime('%Y-%m-%d')

  with open(f'/downloads/admin_at_dough10_dot_me/{today}.json', 'w') as json_file:
    json_file.write(stringify(data, indent=2))


if __name__ == '__main__':
  main()