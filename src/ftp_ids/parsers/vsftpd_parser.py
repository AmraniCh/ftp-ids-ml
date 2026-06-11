from ftp_ids.parsers.base import BaseParser
import re
from datetime import datetime

class VsftpdParser(BaseParser):

    name: str = "vsftpd"

    _REGEX_CONNECT = re.compile(
        r'(?P<dow>\w{3})\s+'
        r'(?P<month>\w{3})\s+'
        r'(?P<day>\d+)\s+'
        r'(?P<time>\S+)\s+'
        r'(?P<year>\d{4})\s+'
        r'\[pid\s+(?P<pid>\d+)\]\s+'
        r'CONNECT:\s+'
        r'Client\s+"(?P<raw_ip>[^"]+)"'
    )
    
    _REGEX_DEBUG = re.compile(
        r'(?P<dow>\w{3})\s+'
        r'(?P<month>\w{3})\s+'
        r'(?P<day>\d+)\s+'
        r'(?P<time>\S+)\s+'
        r'(?P<year>\d{4})\s+'
        r'\[pid\s+(?P<pid>\d+)\]\s+'
        r'(?:\[(?P<user>[^\]]+)\]\s+)?' # optional
        r'DEBUG:\s+'
        r'Client\s+"(?P<raw_ip>[^"]+)",\s+'
        r'"(?P<message>[^"]+)"'
    )

    _REGEX_LINE = re.compile(
        r'(?P<dow>\w{3})\s+'
        r'(?P<month>\w{3})\s+'
        r'(?P<day>\d+)\s+'
        r'(?P<time>\S+)\s+'
        r'(?P<year>\d{4})\s+'
        r'\[pid\s+(?P<pid>\d+)\]\s+'
        r'(?:\[(?P<user>[^\]]+)\]\s+)?' # optional
        r'(?P<event_type>FTP command|FTP response):\s+'
        r'Client\s+"(?P<raw_ip>[^"]+)",\s+'
        r'"(?P<payload>[^"]+)"'
    )

        
    def parse_line(self, line: str) -> dict | None:
        m = self._REGEX_CONNECT.search(line)
        if m: return self._build_event(m, line, event_type="CONNECT")

        m = self._REGEX_DEBUG.search(line)
        if m:
            is_term = 'terminated' in m['message'].lower()
            return self._build_event(m, line, event_type="DEBUG",
                         message=m['message'],
                         session_end=is_term, abrupt_end=is_term)

        m = self._REGEX_LINE.search(line)
        
        if not m: return None

        event_type = m['event_type']
        payload = m['payload']

        cmd = None
        arg = None
        if event_type == "FTP command":
            parts = payload.split(' ', 1)
            cmd = parts[0] 
            arg = parts[1] if len(parts) > 1 else None

        code = None
        session_end = False
        if event_type == "FTP response":
            first = payload.split(' ')[0]
            code = int(first) if first.isdigit() else None
            if code in (530, 430): # reclassify failed logins TODO document this
                event_type = "FAIL_LOGIN"
                session_end = code == 221


        """
        timestamp, PID, user, event_type, src_ip, 
                 command, argument, response_code, filename, filesize,
                 speed, session_end, abrupt_end, raw_line
        """
        return self._build_event(m, line, 
            event_type=event_type, 
            payload=payload, 
            command=cmd, 
            argument=arg, 
            response_code=code, 
            session_end=session_end
        )

    def _build_event(
        self,
        m: re.Match,
        line: str,
        event_type: str,
        payload: str | None = None,
        command: str | None = None,
        argument: str | None = None,
        response_code: int | None = None,
        filename: str | None = None,
        filesize: float | None = None,
        speed: float | None = None,
        message: str | None = None,
        session_end: bool = False,
        abrupt_end: bool = False,
    ) -> dict:
        return {
            'timestamp':     self._parse_ts(m),
            'pid':           int(m['pid']),
            'user':          m.groupdict().get('user'),
            'event_type':    event_type,
            'src_ip':        self._clean_ip(m['raw_ip']),
            'payload':       payload,
            'command':       command,
            'argument':      argument,
            'response_code': response_code,
            'filename':      filename,
            'filesize':      filesize,
            'speed':         speed,
            'message':       message,
            'session_end':   session_end,
            'abrupt_end':    abrupt_end,
            # 'raw_line':      line,
        }


    def _parse_ts(self, m: re.Match) -> datetime:
        s = "{} {} {} {}".format(m['day'], m['month'], m['year'], m['time'])
        return datetime.strptime(s, "%d %b %Y %H:%M:%S")


    def _clean_ip(self, raw: str) -> str:
        return raw.replace('::ffff:', '').replace('::FFFF:', '')
