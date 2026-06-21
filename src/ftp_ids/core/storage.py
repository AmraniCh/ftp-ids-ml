from ftp_ids import config
from ftp_ids.core.feature_extractor import FEATURE_NAMES
from pathlib import Path
import csv

class Storage:



    def append_alert(self, session, score, features):
        row = {
            "src_ip":     session["src_ip"],
            "user":       session["user"] or "",
            "start_time": session["start_time"].isoformat(),
            "end_time":   session["end_time"].isoformat(),
            "n_events":   session["n_events"],
            "end_type":   session["end_type"],
            "score":      round(score, 4),
            **features,
        }

        fieldnames = [
            "src_ip", "user", "start_time", "end_time", "n_events", "end_type", "score",
            *FEATURE_NAMES,
        ]

        self._append_row(config.ALERTS_PATH, row, fieldnames)


    def _append_row(self, path, row, fieldnames):
        file_exists = Path(path).exists()
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)