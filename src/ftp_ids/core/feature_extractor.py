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
    "total_bytes", "avg_speed", "session_duration",
    "fail_ratio", "night_ratio", "transfer_ratio",
    "bytes_per_file", "garbage_cmd_ratio",
    "abrupt_disconnect", "is_auth"
]

# whitelist for the garbage_cmd_ratio feature
_KNOWN_COMMANDS = {
    # RFC 959 core
    "ABOR", "ACCT", "ALLO", "APPE", "CDUP", "CWD", "DELE", "HELP",
    "LIST", "MKD", "MODE", "NLST", "NOOP", "PASS", "PASV", "PORT",
    "PWD", "QUIT", "REIN", "REST", "RETR", "RMD", "RNFR", "RNTO",
    "SITE", "SMNT", "STAT", "STOR", "STOU", "STRU", "SYST", "TYPE",
    "USER",
    # RFC 2228 security
    "ADAT", "AUTH", "CCC", "CONF", "ENC", "MIC", "PBSZ", "PROT",
    # RFC 2389 feature negotiation
    "FEAT", "OPTS",
    # RFC 2428 IPv6/NAT
    "EPRT", "EPSV",
    # RFC 1639
    "LPRT", "LPSV",
    # RFC 2640
    "LANG",
    # RFC 3659 extensions
    "MDTM", "MLSD", "MLST", "SIZE",
    # RFC 7151
    "HOST",
    # legacy RFC 775 X-variants
    "XCUP", "XCWD", "XMKD", "XPWD", "XRMD",
    # common non-RFC extensions
    "MFMT", "MFCT", "MFF",
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

        # responses = self._count_events(events, 'FTP response') # TODO consider to replace this by pre_auth_commands (see todo.md)

        unique_commands = self._count_unique(events, 'command')
        unique_files = self._count_unique(events, 'filename')
        night_events = self._calculate_night_hours(events)

        # garbage_cmd_ratio
        clt_commands   = self._count_non_null(events, 'command')
        empty_commands = commands - clt_commands
        garbage_commands = empty_commands + sum(
            1 for e in events
                if e['command'] and self._is_garbage_command(e['command'])
        )
        garbage_cmd_ratio = 0 if commands == 0 else garbage_commands / commands

        # aggegation features
        total_bytes = sum(e['filesize'] for e in events if e['filesize'])

        speeds = [e['speed'] for e in events if e['speed']]
        avg_speed = sum(speeds) / len(speeds) if speeds else 0.0

        session_duration = (session['end_time'] - session['start_time']).total_seconds()

        # ratios
        fail_ratio   = failed_logins / total_events if total_events else 0 # TODO consider to remove the check on total_events because a session must have at least one event ?
        night_ratio  = night_events / total_events if total_events else 0
        transfer_ratio = (uploads + downloads) / total_events if total_events else 0
        bytes_per_file = total_bytes / unique_files if unique_files else 0

        return {
            "total_events":      total_events,
            "failed_logins":     failed_logins,
            "downloads":         downloads,
            "uploads":           uploads,
            "unique_commands":   unique_commands,
            "unique_files":      unique_files,
            "night_events":      night_events,
            "total_bytes":       total_bytes,
            "avg_speed":         avg_speed,
            "session_duration":  session_duration,
            "fail_ratio":        fail_ratio,
            "night_ratio":       night_ratio,
            "transfer_ratio":   transfer_ratio,
            "bytes_per_file":    bytes_per_file,
            "garbage_cmd_ratio": garbage_cmd_ratio,
            "abrupt_disconnect": 1 if session['end_type'] == 'abrupt' else 0,
            "is_auth":           1 if session['is_auth'] else 0,
        }

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

    def _count_non_null(self, events, attr):
        count = 0
        for e in events:
            if e[attr]:
                count = count + 1
        return count

    def _is_garbage_command(self, command: str) -> bool:
         return command.upper() not in _KNOWN_COMMANDS


    def extract_batch(self, sessions):
        return [self.extract(session) for session in sessions]