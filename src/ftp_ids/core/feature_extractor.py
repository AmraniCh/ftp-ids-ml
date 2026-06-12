from pprint import pprint
import json

"""
Feature extractor: converts session dicts into numeric feature vectors for the ML detector.

Each feature is motivated by an attack behavior:
  failed_logins/fail_ratio -> brute force
  garbage_cmd_ratio        -> protocol confusion
  total_bytes, ...         -> data exfiltration
  night_*                  -> off-hours access
  abrupt_disconnect        -> scripted/hostile clients
"""

# all features names
FEATURE_NAMES = [
    "total_events", "failed_logins", "downloads", "uploads",
    "unique_commands", "unique_files", "night_events",
    "total_bytes", "avg_speed_kbps", "session_duration",
    "fail_ratio", "night_ratio", "upload_ratio",
    "bytes_per_file", "garbage_cmd_ratio",
    "abrupt_disconnect",
]

# whitelist for the garbage_cmd_ratio feature
_KNOWN_COMMANDS = {
    "USER", "PASS", "QUIT", "AUTH", "OPTS", "FEAT", "TYPE", "STRU",
    "PBSZ", "PROT", "CWD", "MKD", "RMD", "DELE", "RNFR", "RNTO",
    "EPSV", "PASV", "PORT", "EPRT", "RETR", "STOR", "LIST", "NLST",
    "SIZE", "MDTM", "REST", "ABOR", "NOOP", "SYST", "PWD", "SITE",
}


class FeatureExtractor:

    def extract(self, session: dict) -> dict | None:
        """One session -> {feature_name: numeric value}."""

        events = session['events']

        total_events  = session['n_events']

        failed_logins  = self._count_events(events, 'FAIL_LOGIN')
        downloads      = self._count_events(events, 'OK_DOWNLOAD')
        uploads        = self._count_events(events, 'OK_UPLOAD')
        commands       = self._count_events(events, 'FTP command')
        clt_commands   = self._count_attr_exists(events, 'command')
        # responses      = self._count_events(events, 'FTP response') # TODO consider to replace this by pre_auth_commands (see todo.md)
        empty_commands = commands - clt_commands

        print('total_events', total_events, sep="=")
        print('failed_logins', failed_logins, sep="=")
        print('downloads', downloads, sep="=")
        print('uploads', uploads, sep="=")
        print('commands', commands, sep="=")
        print('clt_commands', clt_commands, sep="=")
        print('empty_commands', empty_commands, sep="=")

        unique_commands = self._count_unique(events, 'command')
        unique_files = self._count_unique(events, 'filename')
        night_events = self._calculate_night_hours(events)

        print('unique_commands', unique_commands, sep="=")
        print('unique_files', unique_files, sep="=")
        print('night_events', night_events, sep="=")


        ...


    def _count_events(self, events: list[dict], event_type: str) -> int:
        count = 0
        for e in events:
            if e['event_type'] == event_type:
                count = count + 1
        return count

    def _count_unique(self, events: list[dict], subject: str) -> int:
        s = set()
        for e in events:
            if e[subject]: s.add(e[subject])
        return len(s)

    def _calculate_night_hours(self, events, start_hour: int = 0, end_hour: int = 6):
        count = 0
        for ev in events:
            hour = ev['timestamp'].hour
            if hour >= start_hour and hour < end_hour:
                count = count + 1
        return count

    def _count_attr_exists(self, events, attr):
        count = 0
        for e in events:
            if e[attr]:
                count = count + 1
        return count

    # def _is_garbage_command(self, command: str) -> bool:
    #     ...


        # def extract_batch(self, sessions: list[dict]):
    #     """Map extract over sessions."""

    #     sessions = [sessions[-1]]

    #     for session in enumerate(sessions):

    #         for attr in session:
    #             print(attr, sep="=")


    #     ...
