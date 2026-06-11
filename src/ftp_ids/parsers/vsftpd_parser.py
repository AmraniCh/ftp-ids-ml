from ftp_ids.parsers.base import BaseParser
import re
from datetime import datetime

class VsftpdParser(BaseParser):

    name: str = "vsftpd"

    _REGEX_LINE_ = re.compile(r'(?P<dow>\w{3})\s+(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<year>\d{4})\s+\[pid\s+(?P<pid>\d+)\]\s+\[(?P<user>[^\]]+)\]\s+(?P<event_type>FTP command|FTP response):\s+Client\s+"(?P<raw_ip>[^"]+)",\s+"(?P<payload>[^"]+)"')
    
    def parse_line(self, line: str) -> dict | None:
        m = self._REGEX_LINE_.search(line)
        
        if not m:
            return None

        eventType = m['event_type']
        payload = m['payload']

        cmd = ''
        arg = ''
        if eventType == "FTP command":
            parts = payload.split(' ', 1)
            cmd = parts[0] 
            arg = parts[1] if len(parts) > 1 else None

        code = ''
        if eventType == "FTP response":
            first = payload.split(' ')[0]
            code = first if first.isdigit() else None

        """
        timestamp, PID, user, event_type, src_ip, 
                 command, argument, response_code, filename, filesize,
                 speed, session_end, abrupt_end, raw_line
        """
        print({
            'timestamp': self._parse_ts(m),
            'pid': int(m['pid']),
            'user': m['user'],
            'event_type': eventType,
            'src_ip': self._clean_ip(m['raw_ip']),
            'payload': payload,
            'command': cmd,
            'argument': arg,
            'response_code': code,
            'filename': '',
            'filesize': '',
            'speed': '',
            'session_end': '',
            'abrupt_end': '',
            # 'raw_line': line
        })


    def _parse_ts(self, m: re.Match) -> datetime:
        s = "{} {} {} {}".format(m['day'], m['month'], m['year'], m['time'])
        return datetime.strptime(s, "%d %b %Y %H:%M:%S")


    def _clean_ip(self, raw: str) -> str:
        return raw.replace('::ffff:', '').replace('::FFFF:', '')
