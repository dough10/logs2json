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
      'forwarded_address': self.forwarded_address
    }

logs = Log()
logger = logs.get_logger()

def get_logs() -> list[str]:
  try:
    return [log for log in glob(path.join('/logs', '*dough10.me.log'))]
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

def parse_log_line(log_line:str) -> LogEntry:
  log_pattern = r'(?P<ip>[\d\.]+) - (?P<user>[^ ]*|-) \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<resource>[^ ]+) HTTP/[0-9\.]+" (?P<status_code>\d+) (?P<bytes_sent>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<forwarded_address>[^"]*)?"'

  match = re.match(log_pattern, log_line)
  if match:
    log_data = match.groupdict()

    log_data['status_code'] = int(log_data['status_code'])
    log_data['bytes_sent'] = int(log_data['bytes_sent'])

    timestamp = datetime.strptime(log_data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
    log_data['timestamp'] = timestamp

    return LogEntry(**log_data)
  else:
    # logger.debug(f'Error matching to regex: {str(log_line)}')
    return None
  
def is_lan(ip:str) -> bool:
  ip_regex = re.compile(r'^192\.168\.86\.\d{1,3}$')
  return ip_regex.match(ip)

def is_old_log(timestamp:datetime) -> bool:
  time_24_hours_ago = datetime.now(timezone.utc) - timedelta(days=1)
  return timestamp < time_24_hours_ago

def parse_log_file(data:dict[dict[dict[list]]], log:str) -> None:
  file = read_log(log)

  if not file:
    return

  file_lines = file.split('\n')

  for line in file_lines:
    try:
      log_entry = parse_log_line(line)
      if not log_entry:
        continue
      
      if is_lan(log_entry.ip):
        continue

      if is_old_log(log_entry.timestamp):
        continue

      log_date = log_entry.timestamp.date()

      log_date_str = log_date.isoformat()

      data[log][log_date_str][log_entry.ip].append(log_entry.to_dict())
    except IndexError as error:
      logging.debug(f'Indexerror: {str(error)}')

def main() -> None:
  data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

  for log in get_logs():
    parse_log_file(data, log)

  today = datetime.today().strftime('%Y-%m-%d')

  with open(f'/downloads/{today}.json', 'w') as json_file:
    json_file.write(stringify(data, indent=2))


if __name__ == '__main__':
  main()