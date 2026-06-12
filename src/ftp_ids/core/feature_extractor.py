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

    def extract(self, session: dict) -> dict:
        """One session -> {feature_name: numeric value}."""

        ...

    def extract_batch(self, sessions: list[dict]) -> list[dict]:
        """Map extract over sessions."""
        ...

    def _count_events(self, events: list[dict], event_type: str) -> int:
        ...

    def _is_garbage_command(self, command: str) -> bool:
        ...